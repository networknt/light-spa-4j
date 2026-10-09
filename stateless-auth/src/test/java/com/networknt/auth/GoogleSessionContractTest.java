package com.networknt.auth;

import com.networknt.config.Config;
import com.networknt.config.JsonMapper;
import com.networknt.monad.Success;
import io.undertow.Undertow;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.Headers;
import org.jose4j.jwk.*;
import org.jose4j.jws.*;
import org.jose4j.jwt.*;
import org.junit.jupiter.api.*;
import javax.net.ssl.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

/** Actual Java OAuth serialization, session cookies and JWT verification against a local TLS fixture.
 * The fixture enforces the current light-oauth UUID/type/uid contract; it is not the Rust server. */
class GoogleSessionContractTest {
    private static final String USER = "01964b05-5532-7c79-8cde-191dcbd421ba";
    private Undertow oauth, gateway;
    private String base;
    private RsaJsonWebKey key;
    private Map<String, Object> gis;
    private Object oldOrigin;
    private StatelessAuthConfig auth;
    private String oldRedirect, oldDeny;
    private boolean invalidToken;
    private final AtomicReference<Map<String, String>> form = new AtomicReference<>();
    private final AtomicReference<Map<String, Object>> identity = new AtomicReference<>();
    @BeforeEach void start() throws Exception {
        key = RsaJwkGenerator.generateJwk(2048); key.setKeyId(UUID.randomUUID().toString());
        oauth = Undertow.builder().addHttpsListener(5882, "localhost", tls()).setHandler(this::oauth).build(); oauth.start();
        gis = Config.getInstance().getJsonMapConfig("google-sign-in");
        oldOrigin = gis.put("allowedOrigin", "https://signin.example");
        auth = StatelessAuthConfig.load(); oldRedirect = auth.getRedirectUri(); oldDeny = auth.getDenyUri();
        auth.setRedirectUri("https://portal.example/#/dashboard"); auth.setDenyUri(null);
        GoogleAuthHandler handler = new GoogleAuthHandler((token, audience, nonce) -> {
            if (!nonce.equals(token)) throw new IllegalArgumentException();
            JwtClaims claims = new JwtClaims(); claims.setSubject("123456789"); claims.setClaim("email", "google@gmail.com"); return claims;
        }, (data, bootstrap) -> {
            identity.set(data);
            return Success.of(JsonMapper.toJson(Map.of("userId", USER, "email", "stored@example.org", "userType", "C")));
        });
        gateway = Undertow.builder().addHttpListener(0, "127.0.0.1").setHandler(handler).build(); gateway.start();
        base = "http://127.0.0.1:" + ((InetSocketAddress) gateway.getListenerInfo().get(0).getAddress()).getPort();
    }
    @AfterEach void stop() {
        if (gateway != null) gateway.stop(); if (oauth != null) oauth.stop();
        if (gis != null) { if (oldOrigin == null) gis.remove("allowedOrigin"); else gis.put("allowedOrigin", oldOrigin); }
        if (auth != null) { auth.setRedirectUri(oldRedirect); auth.setDenyUri(oldDeny); }
    }
    private static SSLContext tls() throws Exception {
        KeyStore store = KeyStore.getInstance("JKS");
        try (var stream = Config.getInstance().getInputStreamFromFile("server.keystore")) { store.load(stream, "password".toCharArray()); }
        KeyManagerFactory manager = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        manager.init(store, "password".toCharArray()); SSLContext context = SSLContext.getInstance("TLS");
        context.init(manager.getKeyManagers(), null, null); return context;
    }
    private String token(boolean expired, boolean wrongKey, String csrf) throws Exception {
        JwtClaims claims = new JwtClaims(); claims.setIssuer("urn:com:networknt:oauth2:v1"); claims.setAudience("urn:com.networknt");
        claims.setIssuedAtToNow(); claims.setExpirationTime(NumericDate.fromSeconds(System.currentTimeMillis()/1000 + (expired ? -3600 : 600)));
        claims.setClaim("uid", USER); claims.setClaim("uty", "C"); claims.setClaim("role", "user");
        claims.setClaim("csrf", csrf); claims.setStringListClaim("scp", List.of("portal.r"));
        JsonWebSignature signature = new JsonWebSignature(); signature.setPayload(claims.toJson());
        signature.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256); signature.setKeyIdHeaderValue(key.getKeyId());
        signature.setKey(wrongKey ? RsaJwkGenerator.generateJwk(2048).getPrivateKey() : key.getPrivateKey());
        return signature.getCompactSerialization();
    }
    private void oauth(HttpServerExchange exchange) throws Exception {
        if (exchange.isInIoThread()) { exchange.dispatch(this::oauth); return; }
        exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "application/json");
        if (exchange.getRequestPath().contains("/keys")) {
            exchange.getResponseSender().send(new JsonWebKeySet(key).toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)); return;
        }
        exchange.startBlocking(); Map<String, String> values = new HashMap<>();
        for (String part : new String(exchange.getInputStream().readAllBytes(), StandardCharsets.UTF_8).split("&")) {
            String[] pair = part.split("=", 2);
            values.put(URLDecoder.decode(pair[0], StandardCharsets.UTF_8), pair.length == 2 ? URLDecoder.decode(pair[1], StandardCharsets.UTF_8) : "");
        }
        form.set(values);
        if (!USER.equals(values.get("userId")) || !"C".equals(values.get("userType")) || !"client_authenticated_user".equals(values.get("grant_type"))) {
            exchange.setStatusCode(400); exchange.getResponseSender().send("{}"); return;
        }
        exchange.getResponseSender().send(JsonMapper.toJson(Map.of("access_token", invalidToken ? "invalid.jwt" : token(false, false, values.get("csrf")),
                "refresh_token", "fixture-refresh", "token_type", "Bearer", "expires_in", 600)));
    }
    private HttpResponse<String> request(String path, String body, String cookie) throws Exception {
        var builder = HttpRequest.newBuilder(URI.create(base + path)).header("Origin", "https://signin.example")
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body));
        if (cookie != null) builder.header("Cookie", cookie);
        return HttpClient.newHttpClient().send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }
    private HttpResponse<String> login() throws Exception {
        var challenge = request("/google?challenge=1", "{}", null);
        assertEquals(200, challenge.statusCode());
        var data = JsonMapper.string2Map(challenge.body());
        return request("/google", JsonMapper.toJson(Map.of("credential", data.get("nonce"), "challengeId", data.get("challengeId"), "state", "a&b")),
                challenge.headers().firstValue("set-cookie").orElseThrow().split(";", 2)[0]);
    }
    @Test void mintsSessionWithUuidAndStoredTypeUsingActualOauthSerializer() throws Exception {
        var reply = login(); assertEquals(200, reply.statusCode());
        assertEquals(USER, form.get().get("userId")); assertEquals("C", form.get().get("userType"));
        assertEquals(List.of("portal.r"), JsonMapper.string2Map(reply.body()).get("scopes"));
        assertTrue(reply.headers().allValues("set-cookie").stream().anyMatch(cookie -> cookie.startsWith("userId=" + USER)));
        assertTrue(reply.headers().allValues("set-cookie").stream().anyMatch(cookie -> cookie.startsWith("accessToken=")));
        assertEquals("https://portal.example/#/dashboard?state=a%26b", JsonMapper.string2Map(reply.body()).get("redirectUri"));
    }
    @Test void linksWithVerifiedUidWithoutMintingSession() throws Exception {
        String session = "accessToken=" + token(false, false, "fixture-csrf");
        var challenge = request("/google/link?challenge=1", "{}", session); assertEquals(200, challenge.statusCode());
        var data = JsonMapper.string2Map(challenge.body());
        var reply = request("/google/link", JsonMapper.toJson(Map.of("credential", data.get("nonce"), "challengeId", data.get("challengeId"))),
                session + "; " + challenge.headers().firstValue("set-cookie").orElseThrow().split(";", 2)[0]);
        assertEquals(200, reply.statusCode()); assertEquals(true, JsonMapper.string2Map(reply.body()).get("linked"));
        assertEquals(USER, identity.get().get("targetUserId")); assertNull(form.get());
        assertFalse(reply.headers().allValues("set-cookie").stream().anyMatch(cookie -> cookie.startsWith("accessToken=")));
    }
    @Test void expiredAndWrongSignatureSessionsCannotLink() throws Exception {
        assertEquals(401, request("/google/link?challenge=1", "{}", "accessToken=" + token(true, false, "csrf")).statusCode());
        assertEquals(401, request("/google/link?challenge=1", "{}", "accessToken=" + token(false, true, "csrf")).statusCode());
        assertNull(identity.get()); assertNull(form.get());
    }
    @Test void absentRedirectIsSuccessfulEmptyResponse() throws Exception {
        for (String redirect : Arrays.asList(null, "")) {
            auth.setRedirectUri(redirect); var reply = login();
            assertEquals(200, reply.statusCode()); assertEquals("", reply.body());
        }
    }
    @Test void invalidOauthJwtKeepsErrorAndDoesNotEmitSuccessCookies() throws Exception {
        invalidToken = true; var reply = login(); assertTrue(reply.statusCode() >= 400);
        assertFalse(reply.body().contains("redirectUri"));
        assertFalse(reply.headers().allValues("set-cookie").stream().anyMatch(cookie -> cookie.startsWith("accessToken=")));
    }
}
