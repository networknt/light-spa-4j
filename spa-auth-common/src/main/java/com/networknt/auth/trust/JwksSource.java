package com.networknt.auth.trust;

import org.jose4j.http.SimpleGet;
import org.jose4j.http.SimpleResponse;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.jose4j.lang.UnresolvableKeyException;

import java.security.Key;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;

/** Endpoint-owned cache with explicit fetch provenance. Cached keys never join unknown-kid work. */
final class JwksSource implements VerificationKeyResolver {
    private static final long MISS_REPRIEVE = TimeUnit.SECONDS.toNanos(30);
    private static final long FAILURE_RETRY = TimeUnit.SECONDS.toNanos(5);
    private static final long STALE_RETENTION = TimeUnit.HOURS.toNanos(1);
    private final String uri;
    private final SimpleGet transport;
    private final LongSupplier clock;
    private final AtomicReference<CompletableFuture<Snapshot>> flight = new AtomicReference<>();
    private volatile Snapshot cached;
    private volatile LookupFailure lastFailure;
    private volatile AbsentKey confirmedAbsence;

    JwksSource(String uri, SimpleGet transport) { this(uri, transport, System::nanoTime); }
    JwksSource(String uri, SimpleGet transport, LongSupplier clock) {
        this.uri = uri; this.transport = transport; this.clock = clock;
    }

    @Override public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nesting) throws UnresolvableKeyException {
        String kid = jws.getKeyIdHeaderValue();
        if (kid == null || kid.isBlank() || kid.length() > 256) throw new InvalidSigningKey("Missing signing key identifier");
        Snapshot before = cached;
        long now = clock.getAsLong();
        Key known = null;
        if (before != null) {
            try { known = select(before.keys, kid); }
            catch (InvalidSigningKey invalid) { if (now - before.freshUntil < 0) throw invalid; }
        }
        if (known != null && now - before.freshUntil < 0) return known;
        AbsentKey absent = confirmedAbsence;
        if (known == null && before != null && absent != null && absent.generation == before.generation
                && absent.kid.equals(kid) && now - absent.expiresAt < 0) throw new MissingKey();
        Key retained = known;
        boolean canRetain = retained != null && now - before.staleUntil < 0;
        LookupFailure failed = lastFailure;
        // Never wait behind another key's fetch, or apply its cooldown to a retained known key.
        if (canRetain && (flight.get() != null || active(failed, now))) return retained;
        try {
            Snapshot current = refresh(before, known == null);
            Key key = select(current.keys, kid);
            if (key != null) return key;
            // Only a successful HTTP fetch newer than this request's snapshot proves absence.
            if (before == null || current.generation > before.generation) {
                confirmedAbsence = new AbsentKey(kid, current.generation, clock.getAsLong() + FAILURE_RETRY);
                throw new MissingKey();
            }
            throw new UnavailableKey("Signing-key absence has not been refreshed", null);
        } catch (UnavailableKey e) {
            if (canRetain && clock.getAsLong() - before.staleUntil < 0) return retained;
            throw e;
        }
    }

    private Snapshot refresh(Snapshot observed, boolean missing) throws UnavailableKey {
        CompletableFuture<Snapshot> current = flight.get();
        if (current == null) {
            long now = clock.getAsLong();
            LookupFailure failed = lastFailure;
            if (active(failed, now)) throw failed.error;
            Snapshot latest = cached;
            if (latest != observed) return latest; // A completed fetch can satisfy a concurrent caller.
            if (missing && latest != null && now - latest.freshUntil < 0 && now - (latest.fetchedAt + MISS_REPRIEVE) < 0)
                throw new UnavailableKey("Signing-key refresh is rate limited; retry later", null);
            CompletableFuture<Snapshot> owner = new CompletableFuture<>();
            current = flight.compareAndExchange(null, owner);
            if (current == null) {
                current = owner;
                try {
                    Snapshot latestSnapshot = cached;
                    Snapshot result = latestSnapshot != observed ? latestSnapshot : fetch(observed);
                    cached = result;
                    lastFailure = null;
                    owner.complete(result);
                } catch (Exception e) {
                    UnavailableKey unavailable = new UnavailableKey("Signing keys temporarily unavailable", e);
                    lastFailure = new LookupFailure(unavailable, clock.getAsLong() + FAILURE_RETRY);
                    owner.completeExceptionally(unavailable);
                } finally {
                    flight.compareAndSet(owner, null);
                    if (!owner.isDone()) owner.completeExceptionally(new IllegalStateException("Key lookup aborted"));
                }
            }
        }
        try { return current.get(5, TimeUnit.SECONDS); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new UnavailableKey("Signing-key wait interrupted", e); }
        catch (Exception e) { throw new UnavailableKey("Signing-key lookup incomplete", e); }
    }

    private Snapshot fetch(Snapshot observed) throws Exception {
        SimpleResponse response = transport.get(uri);
        if (response.getStatusCode() != 200) throw new java.io.IOException("JWKS endpoint returned a non-success status");
        List<JsonWebKey> keys = List.copyOf(new JsonWebKeySet(response.getBody()).getJsonWebKeys());
        long fetched = clock.getAsLong();
        long freshUntil = fetched + TimeUnit.SECONDS.toNanos(maxAge(response));
        return new Snapshot(keys, fetched, freshUntil, freshUntil + STALE_RETENTION,
                observed == null ? 1 : observed.generation + 1);
    }

    private static boolean active(LookupFailure failure, long now) { return failure != null && now - failure.expiresAt < 0; }
    private static long maxAge(SimpleResponse response) {
        long ttl = 300;
        List<String> values = response.getHeaderValues("Cache-Control");
        if (values != null) for (String value : values) for (String directive : value.split(",")) {
            String text = directive.trim();
            if (text.equalsIgnoreCase("no-cache") || text.equalsIgnoreCase("no-store")) return 0;
            if (text.toLowerCase(java.util.Locale.ROOT).startsWith("max-age=")) {
                try { ttl = Math.max(0, Math.min(ttl, Long.parseLong(text.substring(8).replace("\"", "")))); }
                catch (NumberFormatException ignored) { }
            }
        }
        return ttl;
    }

    private static Key select(List<JsonWebKey> keys, String kid) throws InvalidSigningKey {
        Key selected = null;
        for (JsonWebKey key : keys) if (key instanceof RsaJsonWebKey && kid.equals(key.getKeyId())
                && (key.getUse() == null || "sig".equals(key.getUse()))
                && (key.getKeyOps() == null || key.getKeyOps().contains("verify"))
                && (key.getAlgorithm() == null || AlgorithmIdentifiers.RSA_USING_SHA256.equals(key.getAlgorithm()))) {
            if (selected != null) throw new InvalidSigningKey("Ambiguous signing key");
            selected = key.getKey();
        }
        return selected;
    }
    private record Snapshot(List<JsonWebKey> keys, long fetchedAt, long freshUntil, long staleUntil, long generation) { }
    private record AbsentKey(String kid, long generation, long expiresAt) { }
    static final class MissingKey extends UnresolvableKeyException {
        MissingKey() { super("No matching signing key in freshly fetched JWKS"); }
    }
    private record LookupFailure(UnavailableKey error, long expiresAt) { }
    static final class UnavailableKey extends UnresolvableKeyException {
        UnavailableKey(String message, Throwable cause) { super(message, cause); }
    }
    private static final class InvalidSigningKey extends UnresolvableKeyException {
        InvalidSigningKey(String message) { super(message); }
    }
}
