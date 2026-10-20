package com.networknt.auth.trust;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.http.SimpleResponse;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

class JwtTrustTest {
    private static RsaJsonWebKey internalKey, microsoftKey;
    private static final String TENANT = "22222222-2222-2222-2222-222222222222";
    private static final String CLIENT = "11111111-1111-1111-1111-111111111111";
    private static final String ISSUER = "https://login.microsoftonline.com/" + TENANT + "/v2.0";

    @BeforeAll static void keys() throws Exception {
        internalKey = RsaJwkGenerator.generateJwk(2048);
        microsoftKey = RsaJwkGenerator.generateJwk(2048);
        internalKey.setKeyId("same-kid"); microsoftKey.setKeyId("same-kid");
    }
    private static Map<String, Object> settings(JwtTrust.Kind kind) {
        Map<String, Object> map = new HashMap<>();
        map.put("issuer", kind == JwtTrust.Kind.INTERNAL_ACCESS ? "urn:light-oauth" : ISSUER);
        map.put("audience", kind == JwtTrust.Kind.MICROSOFT_ID ? CLIENT : "33333333-3333-3333-3333-333333333333");
        map.put("tenantId", TENANT);
        map.put("requiredScopes", List.of("gateway.read")); map.put("allowedClientIds", List.of(CLIENT));
        return map;
    }
    private static JwtClaims claims(JwtTrust.Kind kind) {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(kind == JwtTrust.Kind.INTERNAL_ACCESS ? "urn:light-oauth" : ISSUER);
        claims.setAudience(kind == JwtTrust.Kind.MICROSOFT_ID ? CLIENT : "33333333-3333-3333-3333-333333333333");
        claims.setSubject("user"); claims.setExpirationTimeMinutesInTheFuture(10);
        claims.setClaim("tid", TENANT); claims.setClaim("ver", "2.0");
        if (kind == JwtTrust.Kind.MICROSOFT_ACCESS) {
            claims.setClaim("azp", CLIENT); claims.setClaim("scp", "gateway.read other");
        } else if (kind == JwtTrust.Kind.MICROSOFT_ID) claims.setClaim("nonce", "login-nonce");
        claims.setClaim("csrf", "session-nonce");
        return claims;
    }
    private static String sign(JwtClaims claims, RsaJsonWebKey key) throws Exception {
        JsonWebSignature jws = new JsonWebSignature(); jws.setKey(key.getPrivateKey());
        jws.setKeyIdHeaderValue(key.getKeyId()); jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setPayload(claims.toJson()); return jws.getCompactSerialization();
    }
    private static JwtTrust trust(JwtTrust.Kind kind, RsaJsonWebKey key) {
        return new JwtTrust(settings(kind), kind, (jws, nesting) -> key.getPublicKey());
    }

    @Test void signingTrustIsIsolatedEvenWhenKidsCollide() throws Exception {
        JwtTrust internal = trust(JwtTrust.Kind.INTERNAL_ACCESS, internalKey);
        JwtTrust microsoft = trust(JwtTrust.Kind.MICROSOFT_ACCESS, microsoftKey);
        String goodInternal = sign(claims(JwtTrust.Kind.INTERNAL_ACCESS), internalKey);
        String forgedInternal = sign(claims(JwtTrust.Kind.INTERNAL_ACCESS), microsoftKey);
        String goodMicrosoft = sign(claims(JwtTrust.Kind.MICROSOFT_ACCESS), microsoftKey);
        String forgedMicrosoft = sign(claims(JwtTrust.Kind.MICROSOFT_ACCESS), internalKey);
        for (int i = 0; i < 3; i++) {
            assertNotNull(internal.verify(goodInternal, false)); assertNotNull(microsoft.verify(goodMicrosoft, false));
            assertThrows(InvalidJwtException.class, () -> internal.verify(forgedInternal, false));
            assertThrows(InvalidJwtException.class, () -> microsoft.verify(forgedMicrosoft, false));
        }
    }
    @Test void exactPolicyIsEnforcedOnRepeatedRequestsAndCleanup() throws Exception {
        for (JwtTrust.Kind kind : JwtTrust.Kind.values()) {
            JwtTrust trust = trust(kind, internalKey);
            for (String field : List.of("iss", "aud", "tid", "ver", "azp", "scp", "idtyp", "nonce")) {
                if (kind == JwtTrust.Kind.INTERNAL_ACCESS && !List.of("iss", "aud").contains(field)) continue;
                if (kind == JwtTrust.Kind.MICROSOFT_ID && List.of("azp").contains(field)) continue;
                if (kind == JwtTrust.Kind.MICROSOFT_ACCESS && field.equals("nonce")) continue;
                JwtClaims bad = claims(kind);
                if (field.equals("aud")) bad.setAudience("wrong");
                else bad.setClaim(field, field.equals("idtyp") ? "app" : field.equals("nonce") ? "" : "wrong");
                String token = sign(bad, internalKey);
                for (int i = 0; i < 2; i++) {
                    assertThrows(InvalidJwtException.class, () -> trust.verify(token, false), kind + ":" + field);
                    assertThrows(InvalidJwtException.class, () -> trust.verify(token, true), kind + ":" + field);
                }
            }
        }
    }
    @Test void purposeAndLifetimeCannotBeBypassed() throws Exception {
        JwtTrust id = trust(JwtTrust.Kind.MICROSOFT_ID, internalKey), api = trust(JwtTrust.Kind.MICROSOFT_ACCESS, internalKey);
        assertNotNull(id.verify(sign(claims(JwtTrust.Kind.MICROSOFT_ID), internalKey), false));
        assertNotNull(api.verify(sign(claims(JwtTrust.Kind.MICROSOFT_ACCESS), internalKey), false));
        assertThrows(InvalidJwtException.class, () -> api.verify(sign(claims(JwtTrust.Kind.MICROSOFT_ID), internalKey), false));
        assertThrows(InvalidJwtException.class, () -> id.verify(sign(claims(JwtTrust.Kind.MICROSOFT_ACCESS), internalKey), false));
        JwtTrust internal = trust(JwtTrust.Kind.INTERNAL_ACCESS, internalKey);
        JwtClaims expired = claims(JwtTrust.Kind.INTERNAL_ACCESS); expired.setExpirationTime(NumericDate.fromSeconds(1));
        String token = sign(expired, internalKey);
        assertTrue(assertThrows(InvalidJwtException.class, () -> internal.verify(token, false)).hasExpired());
        assertNotNull(internal.verify(token, true));
        expired.unsetClaim("exp"); assertThrows(InvalidJwtException.class, () -> internal.verify(sign(expired, internalKey), true));
        JwtClaims future = claims(JwtTrust.Kind.INTERNAL_ACCESS); future.setNotBefore(NumericDate.fromSeconds(NumericDate.now().getValue() + 300));
        assertThrows(InvalidJwtException.class, () -> internal.verify(sign(future, internalKey), true));
    }
    @Test void unknownKidUsesOnlyItsConfiguredSourceAndBoundedRefreshCache() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        JwksSource keys = source(requests, microsoftKey);
        JwtTrust internal = new JwtTrust(settings(JwtTrust.Kind.INTERNAL_ACCESS), JwtTrust.Kind.INTERNAL_ACCESS, keys);
        for (int i = 0; i < 5; i++) {
            RsaJsonWebKey key = internalKey; String original = key.getKeyId();
            try {
                key.setKeyId("random-" + i);
                InvalidJwtException rejected = assertThrows(InvalidJwtException.class, () -> internal.verify(sign(claims(JwtTrust.Kind.INTERNAL_ACCESS), key), false));
                assertEquals(i != 0, JwtTrust.unavailable(rejected), "only the initiating fresh fetch can confirm a missing ID");
            } finally { key.setKeyId(original); }
        }
        assertEquals(1, requests.get(), "different unknown IDs share endpoint-owned JWKS cache and refresh reprieve");
    }
    @Test void unavailableProviderIsUncertainButConfirmedAbsenceIsNot() throws Exception {
        JwksSource keys = new JwksSource("https://owned.example/keys", uri -> { throw new IOException("test outage"); });
        JwtTrust trust = new JwtTrust(settings(JwtTrust.Kind.INTERNAL_ACCESS), JwtTrust.Kind.INTERNAL_ACCESS, keys);
        InvalidJwtException failure = assertThrows(InvalidJwtException.class, () -> trust.verify(sign(claims(JwtTrust.Kind.INTERNAL_ACCESS), internalKey), true));
        assertTrue(JwtTrust.unavailable(failure));
    }
    @Test void replacementPolicyAndSourceDoNotReuseOldSigningTrust() throws Exception {
        AtomicInteger first = new AtomicInteger(), next = new AtomicInteger();
        JwtTrust old = new JwtTrust(settings(JwtTrust.Kind.INTERNAL_ACCESS), JwtTrust.Kind.INTERNAL_ACCESS, source(first, internalKey));
        String token = sign(claims(JwtTrust.Kind.INTERNAL_ACCESS), internalKey);
        assertNotNull(old.verify(token, false));
        JwtTrust replacement = new JwtTrust(settings(JwtTrust.Kind.INTERNAL_ACCESS), JwtTrust.Kind.INTERNAL_ACCESS, source(next, microsoftKey));
        assertThrows(InvalidJwtException.class, () -> replacement.verify(token, false));
        assertEquals(1, first.get()); assertEquals(1, next.get());
    }
    @Test void slowKeyLookupHasOneOwnerAndBoundedWaiters() throws Exception {
        var entered = new java.util.concurrent.CountDownLatch(1);
        var release = new java.util.concurrent.CountDownLatch(1);
        AtomicInteger requests = new AtomicInteger();
        JwksSource keys = new JwksSource("https://owned.example/keys", uri -> {
            requests.incrementAndGet(); entered.countDown();
            try { if (!release.await(8, java.util.concurrent.TimeUnit.SECONDS)) throw new IOException("test release timeout"); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IOException(e); }
            return new org.jose4j.http.Response(200, "OK", Map.of(), "{\"keys\":[" + internalKey.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY) + "]}");
        });
        JwtTrust trust = new JwtTrust(settings(JwtTrust.Kind.INTERNAL_ACCESS), JwtTrust.Kind.INTERNAL_ACCESS, keys);
        String token = sign(claims(JwtTrust.Kind.INTERNAL_ACCESS), internalKey);
        var owner = java.util.concurrent.CompletableFuture.supplyAsync(() -> {
            try { return trust.verify(token, false); }
            catch (Exception e) { throw new java.util.concurrent.CompletionException(e); }
        });
        try {
            assertTrue(entered.await(2, java.util.concurrent.TimeUnit.SECONDS));
            InvalidJwtException timeout = assertThrows(InvalidJwtException.class, () -> trust.verify(token, false));
            assertTrue(JwtTrust.unavailable(timeout)); assertFalse(owner.isDone()); assertEquals(1, requests.get());
        } finally { release.countDown(); }
        assertNotNull(owner.get(3, java.util.concurrent.TimeUnit.SECONDS));
        assertNotNull(trust.verify(token, false)); assertEquals(1, requests.get());
    }
    @Test void failedSourceHasBoundedRetryRateAcrossRandomKids() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        JwksSource keys = new JwksSource("https://owned.example/keys", uri -> { requests.incrementAndGet(); throw new IOException("test outage"); });
        JwtTrust trust = new JwtTrust(settings(JwtTrust.Kind.INTERNAL_ACCESS), JwtTrust.Kind.INTERNAL_ACCESS, keys);
        String token = sign(claims(JwtTrust.Kind.INTERNAL_ACCESS), internalKey);
        for (int i = 0; i < 5; i++) assertTrue(JwtTrust.unavailable(assertThrows(InvalidJwtException.class, () -> trust.verify(token, false))));
        assertEquals(1, requests.get());
    }

    @Test void v1MicrosoftClaimsUseAppidAndCannotUseV2AzpInstead() throws Exception {
        Map<String, Object> policy = settings(JwtTrust.Kind.MICROSOFT_ACCESS);
        String issuer = "https://sts.windows.net/" + TENANT + "/";
        policy.put("issuer", issuer);
        JwtTrust trust = new JwtTrust(policy, JwtTrust.Kind.MICROSOFT_ACCESS, (jws,nesting) -> internalKey.getPublicKey());
        JwtClaims claims = claims(JwtTrust.Kind.MICROSOFT_ACCESS);
        claims.setIssuer(issuer); claims.setClaim("ver", "1.0");
        assertThrows(InvalidJwtException.class, () -> trust.verify(sign(claims, internalKey), false));
        claims.setClaim("appid", CLIENT); claims.unsetClaim("azp");
        assertNotNull(trust.verify(sign(claims, internalKey), false));
        claims.setClaim("ver", "2.0");
        assertThrows(InvalidJwtException.class, () -> trust.verify(sign(claims, internalKey), false));
        policy.put("audience", "api://v1-gateway");
        JwtTrust v1Uri = new JwtTrust(policy, JwtTrust.Kind.MICROSOFT_ACCESS, (jws,nesting) -> internalKey.getPublicKey());
        claims.setClaim("ver", "1.0"); claims.setAudience("api://v1-gateway");
        assertNotNull(v1Uri.verify(sign(claims, internalKey), false));
    }
    @Test void encryptionOnlyKeysCannotAuthenticateEvenWithMatchingKid() throws Exception {
        RsaJsonWebKey key = RsaJwkGenerator.generateJwk(2048); key.setKeyId("encryption-key");
        key.setKeyOps(List.of("encrypt"));
        JwtTrust trust = new JwtTrust(settings(JwtTrust.Kind.INTERNAL_ACCESS), JwtTrust.Kind.INTERNAL_ACCESS, source(new AtomicInteger(), key));
        assertThrows(InvalidJwtException.class, () -> trust.verify(sign(claims(JwtTrust.Kind.INTERNAL_ACCESS), key), false));
    }

    @Test void invalidConfigurationFailsClosed() {
        assertThrows(IllegalArgumentException.class, () -> JwtTrust.load(null, JwtTrust.Kind.INTERNAL_ACCESS));
        Map<String, Object> bad = settings(JwtTrust.Kind.INTERNAL_ACCESS); bad.put("jwksUri", "http://unsafe/keys");
        assertThrows(IllegalArgumentException.class, () -> JwtTrust.load(bad, JwtTrust.Kind.INTERNAL_ACCESS));
        bad.put("jwksUri", "https://safe/keys"); bad.put("clockSkewSeconds", -1);
        assertThrows(IllegalArgumentException.class, () -> JwtTrust.load(bad, JwtTrust.Kind.INTERNAL_ACCESS));
        Map<String, Object> tenant = settings(JwtTrust.Kind.MICROSOFT_ACCESS); tenant.put("issuer", "https://login.microsoftonline.com/common/v2.0");
        assertThrows(IllegalArgumentException.class, () -> new JwtTrust(tenant, JwtTrust.Kind.MICROSOFT_ACCESS, (jws,nesting) -> internalKey.getPublicKey()));
    }
    private static JwksSource source(AtomicInteger requests, RsaJsonWebKey key) {
        JwksSource source = new JwksSource("https://owned.example/keys", uri -> {
            assertEquals("https://owned.example/keys", uri);
            requests.incrementAndGet();
            String body = "{\"keys\":[" + key.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY) + "]}";
            return new SimpleResponse() {
                public java.util.Collection<String> getHeaderNames() { return List.of(); }
                public int getStatusCode() { return 200; }
                public String getStatusMessage() { return "OK"; }
                public List<String> getHeaderValues(String name) { return List.of(); }
                public String getBody() { return body; }
            };
        });
        return source;
    }
}
