package com.networknt.auth;

import com.networknt.security.SecurityConfig;
import io.undertow.Undertow;
import io.undertow.util.Headers;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/** Local signatures and the isolated MSAL verifier; only key lookup is replaced to avoid external Entra calls. */
class MsalTokenValidationTest {
    static final String TENANT = "11111111-1111-1111-1111-111111111111";
    static final String AUDIENCE = "22222222-2222-2222-2222-222222222222";
    static final String CLIENT = "33333333-3333-3333-3333-333333333333";
    static final String ISSUER = "https://login.microsoftonline.com/" + TENANT + "/v2.0";
    private static final HttpClient HTTP = HttpClient.newHttpClient();
    private static RsaJsonWebKey key;
    private static Undertow server;
    private static URI base;
    private static MsalTokenVerifier realVerifier;

    @BeforeAll
    static void start() throws Exception {
        key = RsaJwkGenerator.generateJwk(2048);
        key.setKeyId("local-msal-test");
        SecurityConfig security = SecurityConfig.load("security-msal");
        MsalAuthHandler.requireUncachedVerifier(security);
        MsalTokenVerifier verifier = new MsalJwtVerifier((jws, nesting) -> key.getPublicKey(), security.getClockSkewInSeconds());
        realVerifier = verifier;
        MsalAuthHandler.installVerifierForTest(verifier);
        MsalAuthHandler handler = new MsalAuthHandler();
        handler.setNext(exchange -> exchange.getResponseSender().send(
                exchange.getRequestHeaders().getFirst(Headers.AUTHORIZATION)));
        server = Undertow.builder().addHttpListener(0, "127.0.0.1").setHandler(handler).build();
        server.start();
        base = URI.create("http://127.0.0.1:" +
                ((InetSocketAddress) server.getListenerInfo().getFirst().getAddress()).getPort());
    }

    @AfterAll
    static void stop() {
        if (server != null) server.stop();
        MsalAuthHandler.installVerifierForTest(null);
    }

    static JwtClaims validClaims() {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(ISSUER);
        claims.setAudience(AUDIENCE);
        claims.setSubject("local-user");
        claims.setClaim("tid", TENANT);
        claims.setClaim("ver", "2.0");
        claims.setClaim("azp", CLIENT);
        claims.setClaim("scp", "access_as_user extra_scope");
        claims.setExpirationTimeMinutesInTheFuture(5);
        return claims;
    }

    private static String sign(JwtClaims claims, RsaJsonWebKey signingKey) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setHeader("typ", "JWT"); // Both Entra ID and access tokens can use this header.
        jws.setKeyIdHeaderValue(key.getKeyId());
        jws.setKey(signingKey.getPrivateKey());
        return jws.getCompactSerialization();
    }

    private static HttpResponse<String> request(String token, boolean cookie) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(base.resolve(cookie ? "/api" : "/auth/ms/login"));
        if (cookie) {
            request.header("Cookie", "accessToken=" + token + "; csrf=local-csrf");
            request.header("X-CSRF-TOKEN", "local-csrf").GET();
        } else {
            request.header("Authorization", "Bearer " + token).POST(HttpRequest.BodyPublishers.noBody());
        }
        return HTTP.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static void assertRejected(String token) throws Exception {
        assertRejected(token, "ERR10000");
    }

    private static void assertRejected(String token, String code) throws Exception {
        // Repeat both paths: an earlier request must never turn rejection into acceptance.
        for (int repeat = 0; repeat < 2; repeat++) {
            for (boolean cookie : new boolean[]{false, true}) {
                HttpResponse<String> response = request(token, cookie);
                assertEquals(401, response.statusCode(), response.body());
                List<String> cookies = response.headers().allValues("Set-Cookie");
                assertEquals(cookie ? 2 : 0, cookies.size());
                assertTrue(cookies.stream().allMatch(value -> {
                    var cleared = io.undertow.util.Cookies.parseSetCookieHeader(value);
                    return cleared.getValue().isEmpty() && cleared.getExpires() != null
                            && cleared.getExpires().getTime() <= 0;
                }), cookies.toString());
                assertTrue(response.body().contains(code));
                assertTrue(response.body().contains("ERR10001".equals(code) ? "AUTH_TOKEN_EXPIRED" : "INVALID_AUTH_TOKEN"));
                assertFalse(response.body().contains(token));
                assertFalse(response.body().contains("local-user"));
            }
        }
    }

    @Test
    void validSignedDelegatedTokenWorksRepeatedlyOnBothPaths() throws Exception {
        String token = sign(validClaims(), key);
        for (int repeat = 0; repeat < 2; repeat++) {
            HttpResponse<String> login = request(token, false);
            assertEquals(200, login.statusCode());
            assertEquals(2, login.headers().allValues("Set-Cookie").size());
            HttpResponse<String> api = request(token, true);
            assertEquals(200, api.statusCode());
            assertEquals("Bearer " + token, api.body());
        }
    }

    @TestFactory
    Stream<DynamicTest> rejectsUntrustedSignedClaims() {
        Map<String, Consumer<JwtClaims>> cases = new LinkedHashMap<>();
        cases.put("wrong issuer", c -> c.setIssuer("https://attacker.example/" + TENANT + "/v2.0"));
        cases.put("missing issuer", c -> c.unsetClaim("iss"));
        cases.put("wrong tenant", c -> c.setClaim("tid", "44444444-4444-4444-4444-444444444444"));
        cases.put("missing tenant", c -> c.unsetClaim("tid"));
        cases.put("wrong API audience", c -> c.setAudience("https://graph.microsoft.com"));
        cases.put("missing audience", c -> c.unsetClaim("aud"));
        cases.put("multiple audiences", c -> c.setAudience(AUDIENCE, "other-api"));
        cases.put("wrong client", c -> c.setClaim("azp", "44444444-4444-4444-4444-444444444444"));
        cases.put("missing client", c -> c.unsetClaim("azp"));
        cases.put("v1 client claim in v2 token", c -> { c.unsetClaim("azp"); c.setClaim("appid", CLIENT); });
        cases.put("wrong scope", c -> c.setClaim("scp", "access_as_user_extra"));
        cases.put("missing scopes", c -> c.unsetClaim("scp"));
        cases.put("malformed scopes", c -> c.setClaim("scp", List.of("access_as_user")));
        cases.put("malformed tenant", c -> c.setClaim("tid", List.of(TENANT)));
        cases.put("ID token for same registration", c -> { c.unsetClaim("scp"); c.setClaim("nonce", "id-token"); });
        cases.put("app-only roles token", c -> { c.unsetClaim("scp"); c.setClaim("roles", List.of("access_as_user")); });
        cases.put("app token with scopes", c -> c.setClaim("idtyp", "app"));
        cases.put("missing version", c -> c.unsetClaim("ver"));
        cases.put("unsupported version", c -> c.setClaim("ver", "3.0"));
        cases.put("version issuer mismatch", c -> c.setClaim("ver", "1.0"));
        cases.put("missing subject", c -> c.unsetClaim("sub"));
        cases.put("expired", c -> c.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() - 120)));
        cases.put("missing expiry", c -> c.unsetClaim("exp"));
        cases.put("future nbf", c -> c.setNotBefore(NumericDate.fromSeconds(NumericDate.now().getValue() + 300)));
        return cases.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(), () -> {
            JwtClaims claims = validClaims();
            entry.getValue().accept(claims);
            assertRejected(sign(claims, key), "expired".equals(entry.getKey()) ? "ERR10001" : "ERR10000");
        }));
    }

    @Test
    void rejectsSignatureFromUntrustedKey() throws Exception {
        assertRejected(sign(validClaims(), RsaJwkGenerator.generateJwk(2048)));
    }

    @Test
    void rejectsMalformedJwt() throws Exception {
        assertRejected("not.a.jwt");
    }

    @Test
    void rejectsHmacKeyConfusionAndUnsignedTokens() throws Exception {
        JsonWebSignature hmac = new JsonWebSignature();
        hmac.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        hmac.setKey(new javax.crypto.spec.SecretKeySpec(key.getPublicKey().getEncoded(), "HmacSHA256"));
        hmac.setPayload(validClaims().toJson());
        assertRejected(hmac.getCompactSerialization());
        var encoder = java.util.Base64.getUrlEncoder().withoutPadding();
        String unsigned = encoder.encodeToString("{\"alg\":\"none\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8))
                + "." + encoder.encodeToString(validClaims().toJson().getBytes(java.nio.charset.StandardCharsets.UTF_8)) + ".";
        assertRejected(unsigned);
    }

    @Test
    void acceptsExplicitV1PolicyAndRejectsV2ClientClaimSubstitution() throws Exception {
        String issuer = "https://sts.windows.net/" + TENANT + "/";
        MsalTokenPolicy policy = new MsalTokenPolicy(TENANT, issuer, "api://example",
                List.of("access_as_user"), List.of(CLIENT));
        JwtClaims claims = validClaims();
        claims.setIssuer(issuer);
        claims.setAudience("api://example");
        claims.setClaim("ver", "1.0");
        claims.unsetClaim("azp");
        claims.setClaim("appid", CLIENT);
        // Verify a real signature before checking the v1 trust policy too.
        JwtClaims verified = new org.jose4j.jwt.consumer.JwtConsumerBuilder()
                .setVerificationKey(key.getPublicKey()).setExpectedAudience("api://example")
                .setExpectedIssuer(issuer).setRequireExpirationTime().build()
                .processToClaims(sign(claims, key));
        assertDoesNotThrow(() -> policy.validate(verified, 0));
        verified.unsetClaim("appid");
        verified.setClaim("azp", CLIENT);
        assertThrows(MsalTokenPolicy.RejectedTokenException.class, () -> policy.validate(verified, 0));
    }

    @Test
    void configuredSkewIsUsedByVerifierAndPolicy() throws Exception {
        assertEquals(60, SecurityConfig.load("security-msal").getClockSkewInSeconds());
        JwtClaims claims = validClaims();
        claims.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() - 20));
        String token = sign(claims, key);
        var login = request(token, false);
        assertEquals(200, login.statusCode(), login.body());
        var api = request(token, true);
        assertEquals(200, api.statusCode(), api.body());
        claims = validClaims();
        claims.setNotBefore(NumericDate.fromSeconds(NumericDate.now().getValue() + 20));
        assertEquals(200, request(sign(claims, key), false).statusCode());
        assertEquals(200, request(sign(claims, key), true).statusCode());
        claims.setNotBefore(NumericDate.fromSeconds(NumericDate.now().getValue() + 120));
        assertRejected(sign(claims, key));
    }

    @Test
    void resolverProgrammingErrorRemainsServerFailureAndKeepsCookies() throws Exception {
        MsalAuthHandler.installVerifierForTest(jwt -> { throw new NumberFormatException("resolver configuration is invalid"); });
        try {
            HttpResponse<String> response = request(sign(validClaims(), key), true);
            assertEquals(500, response.statusCode());
            assertTrue(response.headers().allValues("Set-Cookie").isEmpty());
        } finally {
            MsalAuthHandler.installVerifierForTest(realVerifier);
        }
    }

    @Test
    void keyLookupFailureRejectsRequestButKeepsSessionCookies() throws Exception {
        MsalAuthHandler.installVerifierForTest(jwt -> {
            throw new InvalidJwtException("key lookup", new org.jose4j.jwt.consumer.ErrorCodeValidator.Error(
                    org.jose4j.jwt.consumer.ErrorCodes.MISCELLANEOUS, "key lookup"),
                    new org.jose4j.lang.UnresolvableKeyException("local key lookup unavailable"), null);
        });
        try {
            for (boolean cookie : new boolean[]{true, false}) {
                HttpResponse<String> response = request(sign(validClaims(), key), cookie);
                assertEquals(401, response.statusCode(), response.body());
                assertTrue(response.body().contains("ERR10000"), response.body());
                assertTrue(response.headers().allValues("Set-Cookie").isEmpty());
            }
        } finally {
            MsalAuthHandler.installVerifierForTest(realVerifier);
        }
    }

    @Test
    void csrfFailureKeepsValidSessionCookies() throws Exception {
        String token = sign(validClaims(), key);
        HttpResponse<String> response = HTTP.send(HttpRequest.newBuilder(base.resolve("/api"))
                .header("Cookie", "accessToken=" + token + "; csrf=local-csrf").GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(401, response.statusCode());
        assertTrue(response.body().contains("ERR10036"));
        assertTrue(response.headers().allValues("Set-Cookie").isEmpty());
    }
}
