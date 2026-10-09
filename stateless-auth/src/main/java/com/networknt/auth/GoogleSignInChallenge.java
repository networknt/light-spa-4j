package com.networknt.auth;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.function.LongSupplier;

/** Short-lived, single-use login CSRF challenges. Route both requests to the same gateway instance. */
final class GoogleSignInChallenge {
    record Challenge(String nonce, String userId, long expiresAt) { }
    private final Map<String, Challenge> pending = new HashMap<>();
    private final SecureRandom random = new SecureRandom();
    private final LongSupplier clock;
    GoogleSignInChallenge() { this(System::currentTimeMillis); }
    GoogleSignInChallenge(LongSupplier clock) { this.clock = clock; }
    synchronized Challenge issue(String userId) {
        long now = clock.getAsLong();
        pending.values().removeIf(c -> c.expiresAt() <= now);
        if (pending.size() >= 10000) throw new IllegalStateException("Challenge capacity reached");
        byte[] bytes = new byte[32]; random.nextBytes(bytes);
        String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        Challenge challenge = new Challenge(nonce, userId, now + 300000);
        pending.put(nonce, challenge);
        return challenge;
    }
    synchronized Challenge consume(String nonce) {
        Challenge challenge = pending.remove(nonce);
        return challenge != null && challenge.expiresAt() > clock.getAsLong() ? challenge : null;
    }
}
