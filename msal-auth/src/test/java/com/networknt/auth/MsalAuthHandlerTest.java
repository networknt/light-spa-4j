package com.networknt.auth;

import io.undertow.Undertow;
import io.undertow.server.HttpHandler;
import io.undertow.util.Headers;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;

class MsalAuthHandlerTest {
    private static Undertow server;
    private static URI baseUri;
    private static String csrf() { return MsalAuthConfig.load().getSessionCsrf().issue("entra-token"); }
    private static final HttpClient CLIENT = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();

    @BeforeAll
    static void start() {
        MsalTokenVerifier verifier = jwt -> {
                JwtClaims claims = new JwtClaims();
                claims.setExpirationTimeMinutesInTheFuture(10);
                claims.setSubject("test-user");
                claims.setIssuer("https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0");
                claims.setAudience("22222222-2222-2222-2222-222222222222");
                claims.setClaim("tid", "11111111-1111-1111-1111-111111111111");
                claims.setClaim("ver", "2.0");
                claims.setClaim("azp", "33333333-3333-3333-3333-333333333333");
                claims.setClaim("scp", "access_as_user");
                return claims;
        };
        MsalAuthHandler.installVerifierForTest(verifier);
        HttpHandler terminal = exchange -> {
            String authorization = exchange.getRequestHeaders().getFirst(Headers.AUTHORIZATION);
            exchange.getResponseSender().send(authorization == null ? "anonymous" : authorization);
        };
        MsalAuthHandler handler = new MsalAuthHandler();
        handler.setNext(terminal);
        server = Undertow.builder().addHttpListener(0, "127.0.0.1").setHandler(handler).build();
        server.start();
        InetSocketAddress address = (InetSocketAddress) server.getListenerInfo().getFirst().getAddress();
        baseUri = URI.create("http://127.0.0.1:" + address.getPort());
    }

    @AfterAll
    static void stop() {
        if (server != null) server.stop();
        MsalAuthHandler.installVerifierForTest(null);
    }

    @Test
    void loginCreatesAccessAndCsrfCookies() throws Exception {
        HttpResponse<String> response = send("/auth/ms/login", "POST", "Authorization", "Bearer entra-token");
        Assertions.assertEquals(200, response.statusCode());
        Assertions.assertEquals("{\"message\":\"success\"}", response.body());
        List<String> cookies = response.headers().allValues("Set-Cookie");
        Assertions.assertTrue(cookies.stream().anyMatch(v -> v.startsWith("accessToken=entra-token") && v.contains("HttpOnly")));
        Assertions.assertTrue(cookies.stream().anyMatch(v -> v.startsWith("csrf=") && !v.contains("HttpOnly")));
        Assertions.assertEquals("no-store", response.headers().firstValue("Cache-Control").orElse(null));
    }

    @Test
    void loginAndLogoutRejectLegacyGet() throws Exception {
        HttpResponse<String> login = send("/auth/ms/login", "GET", null, null);
        Assertions.assertEquals(405, login.statusCode());
        Assertions.assertEquals("POST", login.headers().firstValue("Allow").orElse(null));
        HttpResponse<String> logout = send("/auth/ms/logout", "GET", null, null);
        Assertions.assertEquals(405, logout.statusCode());
        Assertions.assertEquals("POST", logout.headers().firstValue("Allow").orElse(null));
    }

    @Test
    void sessionRequiresDoubleSubmitCsrfAndInjectsAuthorization() throws Exception {
        String csrf = csrf();
        HttpResponse<String> missing = send("/api", "GET", "Cookie", "accessToken=entra-token; csrf=" + csrf);
        Assertions.assertEquals(401, missing.statusCode());
        Assertions.assertTrue(missing.body().contains("ERR10036"));

        HttpRequest request = HttpRequest.newBuilder(baseUri.resolve("/api"))
                .header("Cookie", "accessToken=entra-token; csrf=" + csrf)
                .header("X-CSRF-TOKEN", csrf).GET().build();
        HttpResponse<String> valid = CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
        Assertions.assertEquals(200, valid.statusCode());
        Assertions.assertEquals("Bearer entra-token", valid.body());
    }

    @Test
    void websocketSubprotocolWorksButQueryIsRejected() throws Exception {
        String csrf = csrf();
        HttpRequest websocket = HttpRequest.newBuilder(baseUri.resolve("/api"))
                .header("Cookie", "accessToken=entra-token; csrf=" + csrf)
                .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
                .header("Sec-WebSocket-Version", "13")
                .header("Origin", "https://portal.test")
                .header("Sec-WebSocket-Protocol", "chat, csrf." + csrf).GET().build();
        Assertions.assertEquals(200, CLIENT.send(websocket, HttpResponse.BodyHandlers.ofString()).statusCode());
        Assertions.assertEquals(401, send("/api?csrf=secret", "GET", "Cookie",
                "accessToken=entra-token; csrf=" + csrf).statusCode());
    }

    @Test
    void logoutEnforcesCsrfAndDeletesBothCookies() throws Exception {
        String csrf = csrf();
        HttpResponse<String> rejected = send("/auth/ms/logout", "POST", "Cookie",
                "accessToken=entra-token; csrf=" + csrf);
        Assertions.assertEquals(401, rejected.statusCode());
        Assertions.assertTrue(rejected.body().contains("ERR10036"));

        HttpRequest request = HttpRequest.newBuilder(baseUri.resolve("/auth/ms/logout"))
                .header("Cookie", "accessToken=entra-token; csrf=" + csrf)
                .header("X-CSRF-TOKEN", csrf)
                .POST(HttpRequest.BodyPublishers.noBody()).build();
        HttpResponse<String> response = CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
        Assertions.assertEquals(204, response.statusCode());
        Assertions.assertEquals("", response.body());
        List<String> cookies = response.headers().allValues("Set-Cookie");
        Assertions.assertTrue(cookies.stream().anyMatch(v -> v.startsWith("accessToken=") && v.contains("Expires=Thu, 01-Jan-1970")), cookies.toString());
        Assertions.assertTrue(cookies.stream().anyMatch(v -> v.startsWith("csrf=") && v.contains("Expires=Thu, 01-Jan-1970")), cookies.toString());
    }

    @Test
    void optionsFallsThroughForCors() throws Exception {
        Assertions.assertEquals(200, send("/auth/ms/login", "OPTIONS", null, null).statusCode());
    }

    @Test
    void plantedCrossSessionAndTamperedValuesCannotAuthorizeRequestsOrLogout() throws Exception {
        String otherSession = MsalAuthConfig.load().getSessionCsrf().issue("other-access-token");
        String original = csrf();
        for (String value : List.of("attacker-chosen", otherSession, original.substring(0, original.length() - 8) + "AAAAAAAA")) {
            for (String path : List.of("/api", "/auth/ms/logout")) {
                HttpRequest.Builder request = HttpRequest.newBuilder(baseUri.resolve(path))
                        .header("Cookie", "accessToken=entra-token; csrf=" + value).header("X-CSRF-TOKEN", value);
                request.method(path.equals("/api") ? "GET" : "POST", HttpRequest.BodyPublishers.noBody());
                HttpResponse<String> response = CLIENT.send(request.build(), HttpResponse.BodyHandlers.ofString());
                Assertions.assertEquals(401, response.statusCode());
                Assertions.assertFalse(response.body().contains(value));
                Assertions.assertTrue(response.headers().allValues("Set-Cookie").isEmpty());
            }
        }
    }

    @Test
    void queryWithValidHeaderAndUntrustedWebsocketOriginsAreRejected() throws Exception {
        String csrf = csrf();
        HttpRequest request = HttpRequest.newBuilder(baseUri.resolve("/api?csrf=" + csrf))
                .header("Cookie", "accessToken=entra-token; csrf=" + csrf).header("X-CSRF-TOKEN", csrf).GET().build();
        Assertions.assertEquals(401, CLIENT.send(request, HttpResponse.BodyHandlers.ofString()).statusCode());
        for (String origin : List.of("null", "https://evil.test", "")) {
            var builder = HttpRequest.newBuilder(baseUri.resolve("/api"))
                    .header("Cookie", "accessToken=entra-token; csrf=" + csrf)
                    .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==").header("Sec-WebSocket-Version", "13")
                    .header("Sec-WebSocket-Protocol", "chat, csrf." + csrf);
            if (!origin.isEmpty()) builder.header("Origin", origin);
            Assertions.assertEquals(401, CLIENT.send(builder.GET().build(), HttpResponse.BodyHandlers.ofString()).statusCode());
        }
    }

    @Test
    void logoutRequiresAccessTokenBindingAndRemainsIdempotentWithoutSession() throws Exception {
        String csrf = csrf();
        var partial = HttpRequest.newBuilder(baseUri.resolve("/auth/ms/logout"))
                .header("Cookie", "csrf=" + csrf).header("X-CSRF-TOKEN", csrf)
                .POST(HttpRequest.BodyPublishers.noBody()).build();
        Assertions.assertEquals(401, CLIENT.send(partial, HttpResponse.BodyHandlers.ofString()).statusCode());
        Assertions.assertEquals(204, send("/auth/ms/logout", "POST", null, null).statusCode());
    }

    @Test
    void cookieLifetimeIsBoundedByTokenExpiry() {
        JwtClaims longLived = new JwtClaims();
        longLived.setExpirationTimeMinutesInTheFuture(10);
        Assertions.assertTrue(MsalAuthHandler.cookieMaxAge(longLived, 60) <= 60);

        JwtClaims expired = new JwtClaims();
        expired.setExpirationTimeMinutesInTheFuture(-1);
        Assertions.assertEquals(0, MsalAuthHandler.cookieMaxAge(expired, 3600));

        JwtClaims noExpiry = new JwtClaims();
        Assertions.assertEquals(0, MsalAuthHandler.cookieMaxAge(noExpiry, 3600));
    }

    private static HttpResponse<String> send(String path, String method, String header, String value) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(baseUri.resolve(path));
        if (header != null) builder.header(header, value);
        builder.method(method, HttpRequest.BodyPublishers.noBody());
        return CLIENT.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }
}
