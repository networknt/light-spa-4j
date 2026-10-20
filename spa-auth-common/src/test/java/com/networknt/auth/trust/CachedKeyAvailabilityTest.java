package com.networknt.auth.trust;

import org.jose4j.jwk.*;
import org.jose4j.jws.*;
import org.jose4j.jwt.*;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.http.*;
import org.junit.jupiter.api.*;
import java.io.IOException;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import static org.junit.jupiter.api.Assertions.*;

class CachedKeyAvailabilityTest {
    private static RsaJsonWebKey oldKey, newKey;
    @BeforeAll static void keys() throws Exception {
        oldKey = RsaJwkGenerator.generateJwk(2048); oldKey.setKeyId("old");
        newKey = RsaJwkGenerator.generateJwk(2048); newKey.setKeyId("new");
    }
    private static Map<String, Object> settings() { return Map.of("issuer", "owned", "audience", "gateway"); }
    private static String token(RsaJsonWebKey key) throws Exception {
        JwtClaims claims = new JwtClaims(); claims.setIssuer("owned"); claims.setAudience("gateway"); claims.setExpirationTimeMinutesInTheFuture(10);
        JsonWebSignature jws = new JsonWebSignature(); jws.setKey(key.getPrivateKey()); jws.setKeyIdHeaderValue(key.getKeyId());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256); jws.setPayload(claims.toJson()); return jws.getCompactSerialization();
    }
    private static SimpleResponse response(RsaJsonWebKey... keys) {
        return new Response(200, "OK", Map.of("cache-control", List.of("max-age=300")),
                new JsonWebKeySet(keys).toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
    }
    @Test void failedUnknownKeyRefreshDoesNotPoisonKnownKeys() throws Exception {
        AtomicLong now = new AtomicLong(TimeUnit.SECONDS.toNanos(1)); AtomicInteger calls = new AtomicInteger();
        JwksSource source = new JwksSource("https://keys.example", uri -> {
            if (calls.incrementAndGet() > 1) throw new IOException("outage"); return response(oldKey);
        }, now::get);
        JwtTrust trust = new JwtTrust(settings(), JwtTrust.Kind.INTERNAL_ACCESS, source);
        String known = token(oldKey), unknown = token(newKey);
        assertNotNull(trust.verify(known, false)); now.addAndGet(TimeUnit.SECONDS.toNanos(31));
        assertTrue(JwtTrust.unavailable(assertThrows(InvalidJwtException.class, () -> trust.verify(unknown, false))));
        for (int i = 0; i < 5; i++) assertNotNull(trust.verify(known, false));
        assertEquals(2, calls.get());
    }
    @Test void slowUnknownKeyRefreshDoesNotBlockKnownKeys() throws Exception {
        AtomicLong now = new AtomicLong(TimeUnit.SECONDS.toNanos(1)); AtomicInteger calls = new AtomicInteger();
        CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
        JwksSource source = new JwksSource("https://keys.example", uri -> {
            if (calls.incrementAndGet() > 1) {
                entered.countDown();
                try { if (!release.await(8, TimeUnit.SECONDS)) throw new IOException("test release timed out"); }
                catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IOException(e); }
            }
            return response(oldKey);
        }, now::get);
        JwtTrust trust = new JwtTrust(settings(), JwtTrust.Kind.INTERNAL_ACCESS, source);
        String known = token(oldKey), unknown = token(newKey);
        trust.verify(known, false); now.addAndGet(TimeUnit.SECONDS.toNanos(31));
        CompletableFuture<?> owner = CompletableFuture.runAsync(() -> assertThrows(InvalidJwtException.class, () -> trust.verify(unknown, false)));
        try {
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            assertTimeoutPreemptively(Duration.ofSeconds(1), () -> assertNotNull(trust.verify(known, false)));
            assertFalse(owner.isDone());
        } finally { release.countDown(); }
        owner.get(3, TimeUnit.SECONDS); assertEquals(2, calls.get());
    }
    @Test void expiredCacheSurvivesOutageOnlyWithinBoundedRetention() throws Exception {
        AtomicLong now = new AtomicLong(TimeUnit.SECONDS.toNanos(1)); AtomicInteger calls = new AtomicInteger();
        JwksSource source = new JwksSource("https://keys.example", uri -> {
            if (calls.incrementAndGet() > 1) throw new IOException("outage"); return response(oldKey);
        }, now::get);
        JwtTrust trust = new JwtTrust(settings(), JwtTrust.Kind.INTERNAL_ACCESS, source);
        String known = token(oldKey);
        trust.verify(known, false); now.addAndGet(TimeUnit.SECONDS.toNanos(301));
        assertNotNull(trust.verify(known, false)); assertNotNull(trust.verify(known, false)); assertEquals(2, calls.get());
        now.set(TimeUnit.SECONDS.toNanos(3902));
        assertTrue(JwtTrust.unavailable(assertThrows(InvalidJwtException.class, () -> trust.verify(known, false))));
    }
    @Test void reprieveDoesNotTurnNewlyRotatedKeysIntoDefinitiveFailures() throws Exception {
        AtomicLong now = new AtomicLong(TimeUnit.SECONDS.toNanos(1)); AtomicInteger calls = new AtomicInteger();
        JwksSource source = new JwksSource("https://keys.example", uri -> calls.incrementAndGet() == 1 ? response(oldKey) : response(oldKey, newKey), now::get);
        JwtTrust trust = new JwtTrust(settings(), JwtTrust.Kind.INTERNAL_ACCESS, source);
        trust.verify(token(oldKey), false);
        String rotated = token(newKey);
        assertTrue(JwtTrust.unavailable(assertThrows(InvalidJwtException.class, () -> trust.verify(rotated, false))));
        assertEquals(1, calls.get()); now.addAndGet(TimeUnit.SECONDS.toNanos(31));
        assertNotNull(trust.verify(rotated, false)); assertEquals(2, calls.get());
    }
    @Test void duplicateSigningKidIsDefinitiveAndDoesNotPoisonOtherKeys() throws Exception {
        RsaJsonWebKey duplicate = RsaJwkGenerator.generateJwk(2048); duplicate.setKeyId("old");
        AtomicInteger calls = new AtomicInteger();
        JwksSource source = new JwksSource("https://keys.example", uri -> { calls.incrementAndGet(); return response(oldKey, duplicate, newKey); });
        JwtTrust trust = new JwtTrust(settings(), JwtTrust.Kind.INTERNAL_ACCESS, source);
        String ambiguous = token(oldKey);
        for (int i = 0; i < 3; i++) assertFalse(JwtTrust.unavailable(assertThrows(InvalidJwtException.class, () -> trust.verify(ambiguous, false))));
        assertNotNull(trust.verify(token(newKey), false)); assertEquals(1, calls.get());
    }
    @Test void sameEndpointSharesSourceOnlyInsideItsConfigurationSnapshot() {
        Map<String, Object> subject = Map.of("issuer", "https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222/v2.0",
                "tenantId", "22222222-2222-2222-2222-222222222222", "audience", "11111111-1111-1111-1111-111111111111", "jwksUri", "https://keys.example");
        Map<String, Object> api = new HashMap<>(subject); api.put("audience", "33333333-3333-3333-3333-333333333333");
        api.put("requiredScopes", List.of("read")); api.put("allowedClientIds", List.of("11111111-1111-1111-1111-111111111111"));
        JwtTrust.Factory config = new JwtTrust.Factory();
        JwtTrust id = config.load(subject, JwtTrust.Kind.MICROSOFT_ID), access = config.load(api, JwtTrust.Kind.MICROSOFT_ACCESS);
        assertSame(id.signingSource(), access.signingSource());
        assertNotSame(access.signingSource(), new JwtTrust.Factory().load(api, JwtTrust.Kind.MICROSOFT_ACCESS).signingSource());
    }
}
