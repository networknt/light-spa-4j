package com.networknt.auth;

import com.networknt.config.Config;
import com.networknt.config.JsonMapper;
import com.networknt.monad.Success;
import io.undertow.Undertow;
import io.undertow.server.HttpServerExchange;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.*;
import java.net.*;
import java.net.http.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

/** Real HTTP boundary; identity verification and OAuth session minting are local test doubles. */
class GoogleAuthHandlerTest {
    private Undertow server;
    private String base;
    private Map<String, Object> config;
    private Object oldOrigin;
    private String session;
    private boolean invalidAccount;
    private final AtomicInteger issued = new AtomicInteger();
    private static final String USER = "01964b05-5532-7c79-8cde-191dcbd421ba";
    @BeforeEach void start() {
        config = Config.getInstance().getJsonMapConfig("google-sign-in");
        oldOrigin = config.put("allowedOrigin", "https://signin.example");
        GoogleAuthHandler handler = new GoogleAuthHandler((token, audience, nonce) -> {
            if (!token.equals(nonce)) throw new IllegalArgumentException();
            JwtClaims claims = new JwtClaims(); claims.setSubject("123456789");
            claims.setClaim("email", "user@gmail.com"); return claims;
        }, (identity, token) -> Success.of(invalidAccount ? "{}" : JsonMapper.toJson(Map.of("userId", USER, "email", "stored@example.com", "userType", "E")))) {
            @Override protected String currentUser(HttpServerExchange exchange) {
                if (session == null) throw new IllegalArgumentException(); return session;
            }
            @Override protected void issueSession(HttpServerExchange exchange, Map<String, Object> account,
                                                 String state, StatelessAuthConfig auth) {
                issued.incrementAndGet(); exchange.getResponseSender().send(state);
            }
        };
        server = Undertow.builder().addHttpListener(0, "127.0.0.1").setHandler(handler).build(); server.start();
        base = "http://127.0.0.1:" + ((InetSocketAddress)server.getListenerInfo().get(0).getAddress()).getPort();
    }
    @AfterEach void stop() { server.stop(); if (oldOrigin == null) config.remove("allowedOrigin"); else config.put("allowedOrigin", oldOrigin); }
    private HttpResponse<String> request(String path, String body, String cookie, String origin) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(base + path));
        if (origin != null) request.header("Origin", origin);
        if (cookie != null) request.header("Cookie", cookie);
        if (body == null) request.GET(); else request.header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body));
        return HttpClient.newHttpClient().send(request.build(), HttpResponse.BodyHandlers.ofString());
    }
    private String[] challenge(String path) throws Exception {
        var reply = request(path + "?challenge=1", "{}", null, "https://signin.example");
        assertEquals(200, reply.statusCode());
        String cookie = reply.headers().firstValue("set-cookie").orElseThrow();
        for (String flag : List.of("Secure", "HttpOnly", "SameSite=None", "path=/")) assertTrue(cookie.toLowerCase().contains(flag.toLowerCase()));
        return new String[]{(String) JsonMapper.string2Map(reply.body()).get("nonce"), cookie.split(";", 2)[0], (String) JsonMapper.string2Map(reply.body()).get("challengeId")};
    }
    private String body(String nonce, String id) { return JsonMapper.toJson(Map.of("credential", nonce, "state", "a&b", "challengeId", id)); }
    @Test void originAndLegacyCodeAreRejected() throws Exception {
        assertEquals(403, request("/google?challenge=1", "{}", null, null).statusCode());
        assertEquals(403, request("/google?challenge=1", "{}", null, "https://evil.example").statusCode());
        assertEquals(405, request("/google?code=secret", null, null, "https://signin.example").statusCode());
        assertEquals(0, issued.get());
    }
    @Test void singleUseChallengePreservesState() throws Exception {
        var c = challenge("/google");
        var reply = request("/google", body(c[0], c[2]), c[1], "https://signin.example");
        assertEquals(200, reply.statusCode()); assertEquals("a&b", reply.body());
        assertEquals(403, request("/google", body(c[0], c[2]), c[1], "https://signin.example").statusCode());
        assertEquals(1, issued.get());
    }
    @Test void invalidCredentialConsumesChallengeWithoutSession() throws Exception {
        var c = challenge("/google");
        assertEquals(401, request("/google", body("wrong", c[2]), c[1], "https://signin.example").statusCode());
        assertEquals(403, request("/google", body(c[0], c[2]), c[1], "https://signin.example").statusCode());
        assertEquals(0, issued.get());
    }
    @Test void malformedAndDuplicateInputsCannotMintSession() throws Exception {
        for (String body : List.of("{", "{\"credential\":\"a\",\"credential\":\"b\"}", "{\"credential\":\"a\",\"state\":123}", "{\"credential\":\"a\",\"unexpected\":true}"))
            assertEquals(400, request("/google", body, null, "https://signin.example").statusCode());
        assertEquals(403, request("/google", body("x", "a".repeat(22)), null, "https://signin.example").statusCode());
        assertEquals(0, issued.get());
    }
    @Test void linkingRequiresSameAuthenticatedAccountAndDoesNotMintSession() throws Exception {
        assertEquals(401, request("/google/link?challenge=1", "{}", null, "https://signin.example").statusCode());
        session = USER; var switched = challenge("/google/link"); session = UUID.randomUUID().toString();
        assertEquals(403, request("/google/link", body(switched[0], switched[2]), switched[1], "https://signin.example").statusCode());
        session = USER; var linked = challenge("/google/link");
        var reply = request("/google/link", body(linked[0], linked[2]), linked[1], "https://signin.example");
        assertEquals(200, reply.statusCode()); assertTrue(reply.body().contains("\"linked\":true")); assertEquals(0, issued.get());
    }
    @Test void independentTabsKeepTheirChallenges() throws Exception {
        var first = challenge("/google"); var second = challenge("/google");
        assertNotEquals(first[1].split("=")[0], second[1].split("=")[0]);
        String cookies = first[1] + "; " + second[1];
        assertEquals(200, request("/google", body(first[0], first[2]), cookies, "https://signin.example").statusCode());
        assertEquals(200, request("/google", body(second[0], second[2]), cookies, "https://signin.example").statusCode());
        assertEquals(2, issued.get());
    }
    @Test void invalidServiceAccountFailsClosed() throws Exception {
        invalidAccount = true; var c = challenge("/google");
        assertEquals(503, request("/google", body(c[0], c[2]), c[1], "https://signin.example").statusCode()); assertEquals(0, issued.get());
    }
}
