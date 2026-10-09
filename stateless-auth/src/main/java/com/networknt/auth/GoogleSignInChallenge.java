package com.networknt.auth;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Iterator;
import java.util.function.LongSupplier;

/** Short-lived, single-use login CSRF challenges. Route both requests to the same gateway instance. */
final class GoogleSignInChallenge {
    record Challenge(String id, String nonce, String userId, String source, long expiresAt) { }
    static final class RateLimited extends IllegalStateException { }
    private static final int SOURCE_LIMIT = 32;
    private record SourceWindow(long expiresAt, int issued) { }
    // Insertion order is expiry order. Cleanup visits only expired entries, not the whole store.
    private final Map<String, Challenge> pending = new LinkedHashMap<>();
    private final Map<String, SourceWindow> sources = new LinkedHashMap<>();
    private final SecureRandom random = new SecureRandom();
    private final LongSupplier clock;
    GoogleSignInChallenge() { this(() -> System.nanoTime() / 1_000_000L); }
    GoogleSignInChallenge(LongSupplier clock) { this.clock = clock; }
    synchronized Challenge issue(String userId, String source) {
        long now = clock.getAsLong();
        expire(now);
        SourceWindow window = sources.get(source);
        if (window != null && window.issued() >= SOURCE_LIMIT) throw new RateLimited();
        if (pending.size() >= 10000) throw new IllegalStateException("Challenge capacity reached");
        if (window == null && sources.size() >= 10000) throw new IllegalStateException("Source capacity reached");
        byte[] bytes = new byte[32]; random.nextBytes(bytes);
        String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        String id = nonce.substring(0, 22);
        Challenge challenge = new Challenge(id, nonce, userId, source, now + 300000);
        pending.put(id, challenge);
        sources.put(source, new SourceWindow(window == null ? now + 300000 : window.expiresAt(),
                window == null ? 1 : window.issued() + 1));
        return challenge;
    }
    synchronized Challenge consume(String id, String cookie) {
        Challenge challenge = pending.remove(id);
        if (challenge != null && !GoogleIdTokenVerifier.same(challenge.nonce(), cookie)) return null;
        return challenge != null && challenge.expiresAt() > clock.getAsLong() ? challenge : null;
    }
    private void expire(long now) {
        Iterator<Challenge> challenges = pending.values().iterator();
        while (challenges.hasNext()) {
            if (challenges.next().expiresAt() > now) break;
            challenges.remove();
        }
        Iterator<SourceWindow> windows = sources.values().iterator();
        while (windows.hasNext()) {
            if (windows.next().expiresAt() > now) break;
            windows.remove();
        }
    }
}
