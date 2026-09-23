package com.networknt.auth;

import com.networknt.security.JwtVerifier;
import com.networknt.security.SecurityConfig;
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
    private static final HttpClient CLIENT = HttpClient.newHttpClient();

    @BeforeAll
    static void start() {
        SecurityConfig config = SecurityConfig.load("security-msal");
        JwtVerifier verifier = new JwtVerifier(config) {
            @Override
            public JwtClaims verifyJwt(String jwt, boolean ignoreExpiry, boolean isToken,
                                       String pathPrefix, String requestPath, List<String> jwkServiceIds) {
                JwtClaims claims = new JwtClaims();
                claims.setExpirationTimeMinutesInTheFuture(10);
                claims.setSubject("test-user");
                return claims;
            }
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
        HttpResponse<String> missing = send("/api", "GET", "Cookie", "accessToken=entra-token; csrf=secret");
        Assertions.assertEquals(401, missing.statusCode());
        Assertions.assertTrue(missing.body().contains("ERR10036"));

        HttpRequest request = HttpRequest.newBuilder(baseUri.resolve("/api"))
                .header("Cookie", "accessToken=entra-token; csrf=secret")
                .header("X-CSRF-TOKEN", "secret").GET().build();
        HttpResponse<String> valid = CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
        Assertions.assertEquals(200, valid.statusCode());
        Assertions.assertEquals("Bearer entra-token", valid.body());
    }

    @Test
    void websocketSubprotocolAndQueryCanSupplyCsrf() throws Exception {
        HttpRequest websocket = HttpRequest.newBuilder(baseUri.resolve("/api"))
                .header("Cookie", "accessToken=entra-token; csrf=secret")
                .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
                .header("Sec-WebSocket-Version", "13")
                .header("Sec-WebSocket-Protocol", "chat, csrf.secret").GET().build();
        Assertions.assertEquals(200, CLIENT.send(websocket, HttpResponse.BodyHandlers.ofString()).statusCode());
        Assertions.assertEquals(200, send("/api?csrf=secret", "GET", "Cookie",
                "accessToken=entra-token; csrf=secret").statusCode());
    }

    @Test
    void logoutEnforcesCsrfAndDeletesBothCookies() throws Exception {
        HttpResponse<String> rejected = send("/auth/ms/logout", "POST", "Cookie",
                "accessToken=entra-token; csrf=secret");
        Assertions.assertEquals(401, rejected.statusCode());
        Assertions.assertTrue(rejected.body().contains("ERR10036"));

        HttpRequest request = HttpRequest.newBuilder(baseUri.resolve("/auth/ms/logout"))
                .header("Cookie", "accessToken=entra-token; csrf=secret")
                .header("X-CSRF-TOKEN", "secret")
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
