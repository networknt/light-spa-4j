package com.networknt.auth;

import com.networknt.client.Http2Client;
import com.networknt.client.simplepool.SimpleConnectionState;
import com.networknt.config.Config;
import com.networknt.exception.ClientException;
import com.networknt.httpstring.HttpStringConstants;
import com.networknt.security.KeyUtil;
import io.undertow.Handlers;
import io.undertow.Undertow;
import io.undertow.UndertowOptions;
import io.undertow.client.ClientConnection;
import io.undertow.client.ClientRequest;
import io.undertow.client.ClientResponse;
import io.undertow.server.HttpHandler;
import io.undertow.util.Headers;
import io.undertow.util.HttpString;
import io.undertow.util.Methods;
import io.undertow.util.StatusCodes;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.junit.jupiter.api.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xnio.IoUtils;
import org.xnio.OptionMap;
import org.xnio.XnioWorker;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public class MsalTokenExchangeHandlerTest {
    static final Logger logger = LoggerFactory.getLogger(MsalTokenExchangeHandlerTest.class);

    static Undertow authServer = null;
    static Undertow tokenServer = null;
    // this is to simulate the randomly generated csrfToken for testing only to ensure
    // both header csrf and jwt csrf tokens are the same.
    static String csrfToken = "UniqueCsrfToken";
    static SSLContext sslContext;
    private static XnioWorker worker;

    private static final String SERVER_KEY_STORE = "server.keystore";
    private static final String SERVER_TRUST_STORE = "server.truststore";
    private static final char[] STORE_PASSWORD = "password".toCharArray();
    final Http2Client client = Http2Client.getInstance();

    private static final javax.net.ssl.SSLSocketFactory PREVIOUS_HTTPS_FACTORY = javax.net.ssl.HttpsURLConnection.getDefaultSSLSocketFactory();
    @org.junit.jupiter.api.AfterAll
    static void restoreHttpsTrust() { javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(PREVIOUS_HTTPS_FACTORY); }

    private static volatile boolean jwksUnavailable;
    private static volatile boolean invalidIssuedPolicy;
    private static final java.util.concurrent.atomic.AtomicInteger tokenRequests = new java.util.concurrent.atomic.AtomicInteger();
    private static volatile boolean secondaryJwksUnavailable;
    private static volatile CountDownLatch secondaryEntered;
    private static volatile CountDownLatch secondaryRelease;
    private static final java.util.concurrent.atomic.AtomicInteger secondaryRequests = new java.util.concurrent.atomic.AtomicInteger();
    private static volatile boolean secondaryHasRetiredKey;
    private static final java.util.concurrent.atomic.AtomicInteger keyRequests = new java.util.concurrent.atomic.AtomicInteger();


    private static volatile CountDownLatch slowRefreshEntered;
    private static volatile CountDownLatch slowRefreshRelease;

    @BeforeAll
    public static void setUp() throws IOException {
        sslContext = createSSLContext(loadKeyStore(SERVER_KEY_STORE), loadKeyStore(SERVER_TRUST_STORE), false);
        javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(
                createSSLContext(loadKeyStore(SERVER_KEY_STORE), loadKeyStore(SERVER_KEY_STORE), true).getSocketFactory());

        if(authServer == null) {
            logger.info("starting server");
            HttpHandler handler = getTestHandler();
            MsalTokenExchangeHandler msalTokenExchangeHandler = new MsalTokenExchangeHandler();
            msalTokenExchangeHandler.setNext(handler);
            handler = msalTokenExchangeHandler;
            HttpHandler requestHandler = handler;
            authServer = Undertow.builder()
                    .addHttpsListener(7080, "localhost", sslContext)
                    .setServerOption(UndertowOptions.ENABLE_HTTP2, true)
                    .setHandler(exchange -> exchange.dispatch(requestHandler))
                    .build();
            authServer.start();
        }

        if(tokenServer == null) {
            logger.info("starting oauth token server");
            tokenServer = Undertow.builder()
                    .addHttpsListener(5882, "localhost", sslContext)
                    .setServerOption(UndertowOptions.ENABLE_HTTP2, true)
                    .setHandler(Handlers.header(Handlers.path()
                                    .addPrefixPath("/secondary/keys", initial -> initial.dispatch(exchange -> {
                                        secondaryRequests.incrementAndGet();
                                        if (secondaryEntered != null) {
                                            secondaryEntered.countDown();
                                            if (!secondaryRelease.await(8, TimeUnit.SECONDS)) throw new IllegalStateException("Test release timed out");
                                        }
                                        if (secondaryJwksUnavailable) {
                                            exchange.setStatusCode(503);
                                            exchange.getResponseSender().send("Secondary JWKS unavailable");
                                        } else {
                                            exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "application/json");
                                            String keys = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"Tj_l_tIBTginOtQbL0Pv5w\",\"n\":\"0YRbWAb1FGDpPUUcrIpJC6BwlswlKMS-z2wMAobdo0BNxNa7hG_gIHVPkXu14Jfo1JhUhS4wES3DdY3a6olqPcRN1TCCUVHd-1TLd1BBS-yq9tdJ6HCewhe5fXonaRRKwutvoH7i_eR4m3fQ1GoVzVAA3IngpTr4ptnM3Ef3fj-5wZYmitzrRUyQtfARTl3qGaXP_g8pHFAP0zrNVvOnV-jcNMKm8YZNcgcs1SuLSFtUDXpf7Nr2_xOhiNM-biES6Dza1sMLrlxULFuctudO9lykB7yFh3LHMxtIZyIUHuy0RbjuOGC5PmDowLttZpPI_j4ynJHAaAWr8Ddz764WdQ\",\"e\":\"AQAB\"}]}";
                                            exchange.getResponseSender().send(secondaryHasRetiredKey ? keys.replace("Tj_l_tIBTginOtQbL0Pv5w", "retired-key") : keys);
                                        }
                                    }))
                                    .addPrefixPath("/oauth2/N2CMw0HGQXeLvC1wBfln2A/keys", (exchange) -> {
                                        keyRequests.incrementAndGet();
                                        if (jwksUnavailable) {
                                            exchange.setStatusCode(503);
                                            exchange.getResponseSender().send("JWKS temporarily unavailable");
                                            return;
                                        }
                                        exchange.getResponseHeaders().add(new HttpString("Content-Type"), "application/json");
                                        exchange.getResponseSender().send("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"Tj_l_tIBTginOtQbL0Pv5w\",\"n\":\"0YRbWAb1FGDpPUUcrIpJC6BwlswlKMS-z2wMAobdo0BNxNa7hG_gIHVPkXu14Jfo1JhUhS4wES3DdY3a6olqPcRN1TCCUVHd-1TLd1BBS-yq9tdJ6HCewhe5fXonaRRKwutvoH7i_eR4m3fQ1GoVzVAA3IngpTr4ptnM3Ef3fj-5wZYmitzrRUyQtfARTl3qGaXP_g8pHFAP0zrNVvOnV-jcNMKm8YZNcgcs1SuLSFtUDXpf7Nr2_xOhiNM-biES6Dza1sMLrlxULFuctudO9lykB7yFh3LHMxtIZyIUHuy0RbjuOGC5PmDowLttZpPI_j4ynJHAaAWr8Ddz764WdQ\",\"e\":\"AQAB\"}]}");
                                    })
                                    .addPrefixPath("/oauth2/N2CMw0HGQXeLvC1wBfln2A/token", (exchange) -> {
                                        // Dispatch to a worker thread so startBlocking + readAllBytes
                                        // works correctly under HTTP/2 (avoids UT000126).
                                        if (exchange.isInIoThread()) {
                                            exchange.dispatch((ex) -> {
                                                handleTokenRequest(ex);
                                            });
                                            return;
                                        }
                                        handleTokenRequest(exchange);
                                    }),
                            Headers.SERVER_STRING, "U-tow"))
                    .build();
            tokenServer.start();
        }


    }

    @AfterAll
    public static void tearDown() throws Exception {
        if(authServer != null) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException ignored) {

            }
            authServer.stop();
            logger.info("The server is stopped.");
        }
        if(tokenServer != null) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException ignored) {
            }
            tokenServer.stop();
            System.out.println("The oauth token server is stopped.");
            try {
                Thread.sleep(100);
            } catch (InterruptedException ignored) {
            }
        }
    }

    private static void handleTokenRequest(io.undertow.server.HttpServerExchange exchange) {
        exchange.startBlocking();
        // Parse the POST body to extract the csrf value so the mock
        // server mirrors it into the JWT, just as a real token server would.
        String csrfValue = null;
        try {
            byte[] bodyBytes = exchange.getInputStream().readAllBytes();
            String body = new String(bodyBytes, java.nio.charset.StandardCharsets.UTF_8);
            if (body.contains("slow-refresh")) {
                slowRefreshEntered.countDown();
                if (!slowRefreshRelease.await(8, TimeUnit.SECONDS)) throw new IllegalStateException("Test release timed out");
            }
            if (body.contains("rust-dead-refresh") || body.contains("plain-error-refresh")) {
                exchange.setStatusCode(400);
                exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/plain; charset=utf-8");
                String message = "Refresh service unavailable";
                if (body.contains("rust-dead-refresh")) {
                    message = body.contains("client") ? "Client ID mismatch" : body.contains("provider") ? "Provider ID mismatch"
                            : body.contains("host") ? "Auth host mismatch" : "Refresh token not found";
                }
                exchange.getResponseSender().send(message);
                return;
            }
            if (body.contains("delayed-error-refresh")) {
                Thread.sleep(2200);
                exchange.setStatusCode(503);
                exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/plain");
                exchange.getResponseSender().send("Temporarily unavailable");
                return;
            }
            if (body.contains("invalid-refresh")) {
                exchange.setStatusCode(404);
                exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "application/json");
                exchange.getResponseSender().send("{\"statusCode\":404,\"code\":\"ERR12029\",\"message\":\"REFRESH_TOKEN_NOT_FOUND\",\"description\":\"Test invalid refresh\"}");
                return;
            }
            if (body.contains("unknown-refresh")) {
                exchange.setStatusCode(400);
                exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "application/json");
                exchange.getResponseSender().send("{\"statusCode\":400,\"code\":\"UNKNOWN_PROVIDER_ERROR\",\"message\":\"UNKNOWN\"}");
                return;
            }
            if (body.contains("transient-refresh") || body.contains("network-error-refresh")) {
                int status = body.contains("network-error-refresh") ? 401 : 503;
                exchange.setStatusCode(status);
                exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "application/json");
                exchange.getResponseSender().send("{\"statusCode\":" + status + ",\"code\":\"ERR10053\",\"message\":\"ESTABLISH_CONNECTION_ERROR\",\"description\":\"Test temporary failure\"}");
                return;
            }
            for (String param : body.split("&")) {
                int eqIdx = param.indexOf('=');
                if (eqIdx > 0) {
                    String key = URLDecoder.decode(param.substring(0, eqIdx), java.nio.charset.StandardCharsets.UTF_8);
                    if ("csrf".equals(key)) {
                        csrfValue = URLDecoder.decode(param.substring(eqIdx + 1), java.nio.charset.StandardCharsets.UTF_8);
                        break;
                    }
                }
            }
        } catch (Exception e) {
            logger.error("Failed to parse POST body for CSRF value in mock token server", e);
        }
        // Create a token with 600 second expiry (matches the JWT exp claim).
        try {
            Map<String, Object> map = new HashMap<>();
            tokenRequests.incrementAndGet();
            JwtClaims issued = getTestClaims(csrfValue != null ? csrfValue : csrfToken);
            if (invalidIssuedPolicy) issued.setAudience("wrong-provider-audience");
            String token = getJwt(issued);
            map.put("access_token", token);
            map.put("token_type", "Bearer");
            map.put("refresh_token", "refresh_token_value");
            map.put("expires_in", 600);
            exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "application/json");
            exchange.getResponseSender().send(ByteBuffer.wrap(
                    Config.getInstance().getMapper().writeValueAsBytes(map)));
        } catch (Exception e) {
            logger.error("Failed to generate token in mock token server", e);
            exchange.setStatusCode(500);
            exchange.getResponseSender().send("Internal Server Error");
        }
    }

    static HttpHandler getTestHandler() {
        return exchange -> {
            exchange.getResponseHeaders().put(new HttpString("X-Test-Next"), "true");
            if("/api".equals(exchange.getRequestPath())) {
                String authorization = exchange.getRequestHeaders().getFirst(Headers.AUTHORIZATION);
                String lightToken = exchange.getRequestHeaders().getFirst("X-Light-Token");
                exchange.getResponseSender().send("Authorization=" + authorization + ";X-Light-Token=" + lightToken);
            } else {
                exchange.setStatusCode(StatusCodes.NO_CONTENT);
                exchange.endExchange();
            }
        };
    }

    @Test
    public void testExchangeIdPolicyRejectsWrongClaimsBeforeCallingProvider() throws Exception {
        int before = tokenRequests.get();
        for (String field : new String[]{"iss", "tid", "aud", "ver", "scp", "nonce", "idtyp"}) {
            JwtClaims claims = getMicrosoftClaims(false);
            claims.setClaim(field, field.equals("idtyp") ? "app" : field.equals("nonce") ? "" : "wrong");
            ClientResponse response = sendRequest(Methods.POST, "/auth/ms/exchange", null, null, null, getJwt(claims), null);
            Assertions.assertEquals(StatusCodes.UNAUTHORIZED, response.getResponseCode(), field);
            Assertions.assertNull(response.getResponseHeaders().get(Headers.SET_COOKIE));
            Assertions.assertNull(response.getResponseHeaders().getFirst("X-Test-Next"));
        }
        Assertions.assertEquals(before, tokenRequests.get());
    }

    @Test
    public void testIdSubjectExchangeAndReturnedInternalTokenPolicy() throws Exception {
        String id = getMicrosoftJwt(false);
        ClientResponse accepted = sendRequest(Methods.POST, "/auth/ms/exchange", null, null, null, id, null);
        Assertions.assertEquals(StatusCodes.OK, accepted.getResponseCode());
        Assertions.assertNotNull(issuedCookie(accepted, "accessToken"));
        invalidIssuedPolicy = true;
        try {
            ClientResponse rejected = sendRequest(Methods.POST, "/auth/ms/exchange", null, null, null, id, null);
            Assertions.assertEquals(StatusCodes.UNAUTHORIZED, rejected.getResponseCode());
            Assertions.assertNull(rejected.getResponseHeaders().get(Headers.SET_COOKIE));
        } finally { invalidIssuedPolicy = false; }
    }

    @Test
    public void testAzureAccessPolicyRejectsIdAndWrongAccessClaimsOnEveryRequest() throws Exception {
        MsalExchangeConfig config = MsalExchangeConfig.load();
        String oldMode = config.getAuthorizationToken();
        config.setAuthorizationToken(MsalExchangeConfig.AUTHORIZATION_TOKEN_AZURE_MSAL);
        String csrf = com.networknt.auth.csrf.Csrf.nonce();
        String internal = getJwt(600, csrf);
        try {
            for (String field : new String[]{"iss", "aud", "tid", "ver", "azp", "scp", "idtyp", "id-token"}) {
                JwtClaims claims = getMicrosoftClaims(!field.equals("id-token"));
                if (!field.equals("id-token")) claims.setClaim(field, field.equals("idtyp") ? "app" : "wrong");
                String cookies = "accessToken=" + internal + "; csrf=" + csrf + "; msalAccessToken=" + getJwt(claims);
                for (int retry = 0; retry < 2; retry++) {
                    ClientResponse response = sendRequest(Methods.POST, "/api", cookies, csrf, "https://portal.test");
                    Assertions.assertEquals(StatusCodes.UNAUTHORIZED, response.getResponseCode(), field);
                    Assertions.assertNull(response.getResponseHeaders().getFirst("X-Test-Next"));
                }
            }
        } finally { config.setAuthorizationToken(oldMode); }
    }

    @Test
    public void testWrongSessionIssuerAndAudienceNeverReachDownstream() throws Exception {
        String csrf = com.networknt.auth.csrf.Csrf.nonce();
        for (String field : new String[]{"iss", "aud"}) {
            JwtClaims claims = getTestClaims(csrf);
            claims.setClaim(field, "wrong-" + field);
            ClientResponse response = sendRequest(Methods.POST, "/api", "accessToken=" + getJwt(claims) + "; csrf=" + csrf, csrf, "https://portal.test");
            Assertions.assertEquals(StatusCodes.UNAUTHORIZED, response.getResponseCode());
            Assertions.assertNull(response.getResponseHeaders().getFirst("X-Test-Next"));
            Assertions.assertNull(response.getResponseHeaders().get(Headers.SET_COOKIE));
        }
    }

    @Test
    public void testWrongProviderTokenCannotEstablishRenewOrRecoverSession() throws Exception {
        invalidIssuedPolicy = true;
        String csrf = com.networknt.auth.csrf.Csrf.nonce();
        try {
            for (boolean existing : new boolean[]{false, true}) {
                String cookies = "refreshToken=invalid-issued-policy-" + java.util.UUID.randomUUID() + "; csrf=" + csrf
                        + (existing ? "; accessToken=" + getJwt(30, csrf) : "");
                ClientResponse response = sendRequest(Methods.POST, "/api", cookies, existing ? csrf : null, "https://portal.test");
                Assertions.assertEquals(StatusCodes.UNAUTHORIZED, response.getResponseCode());
                Assertions.assertNull(response.getResponseHeaders().get(Headers.SET_COOKIE));
                Assertions.assertNull(response.getResponseHeaders().getFirst("X-Test-Next"));
            }
        } finally { invalidIssuedPolicy = false; }
    }

    @Test
    public void testPolicyReloadAndFailedSnapshots() throws Exception {
        java.util.Map<String, Object> original = Config.getInstance().getJsonMapConfig("msal-exchange");
        var first = MsalExchangeConfig.load();
        try {
            java.util.Map<String, Object> invalid = new java.util.HashMap<>(original);
            invalid.remove("internalTokenTrust");
            Config.getInstance().putInConfigCache("msal-exchange", invalid);
            RuntimeException failure = Assertions.assertThrows(IllegalArgumentException.class, MsalExchangeConfig::load);
            Assertions.assertSame(failure, Assertions.assertThrows(IllegalArgumentException.class, MsalExchangeConfig::load));
            java.util.Map<String, Object> disabled = new java.util.HashMap<>(invalid);
            disabled.put("enabled", false);
            Config.getInstance().putInConfigCache("msal-exchange", disabled);
            Assertions.assertFalse(MsalExchangeConfig.load().isEnabled());
            java.util.Map<String, Object> replacement = new java.util.HashMap<>(original);
            Config.getInstance().putInConfigCache("msal-exchange", replacement);
            Assertions.assertNotSame(first.getInternalTokenTrust(), MsalExchangeConfig.load().getInternalTokenTrust(), "replacement owns a fresh signing resolver/cache");
        } finally {
            Config.getInstance().putInConfigCache("msal-exchange", original);
            MsalExchangeConfig.load();
        }
    }

    @Test
    @Disabled
    public void testTokenExchange() throws ClientException {

        final CountDownLatch latch = new CountDownLatch(1);
        final AtomicReference<ClientResponse> reference = new AtomicReference<>();
        String requestUri = "/auth/ms/exchange";
        SimpleConnectionState.ConnectionToken connectionToken = null;

        try {
            connectionToken = client.borrow(new URI("https://localhost:7080"), Http2Client.WORKER, client.getDefaultXnioSsl(), Http2Client.BUFFER_POOL, OptionMap.create(UndertowOptions.ENABLE_HTTP2, true));
            ClientConnection connection = (ClientConnection) connectionToken.getRawConnection();
            ClientRequest request = new ClientRequest().setPath(requestUri).setMethod(Methods.POST);
            //customized header parameters
            request.getRequestHeaders().put(new HttpString("host"), "localhost");
            // please replace the following with your own bearer token from microsoft identity platform.
            request.getRequestHeaders().put(Headers.AUTHORIZATION, "Bearer your_token");
            connection.sendRequest(request, client.createClientCallback(reference, latch));
            latch.await();
        } catch (Exception e) {
            logger.error("Exception: ", e);
            throw new ClientException(e);
        } finally {
            client.restore(connectionToken);
        }
        int statusCode = reference.get().getResponseCode();
        String body = reference.get().getAttachment(Http2Client.RESPONSE_BODY);
        Assertions.assertEquals(200, statusCode);
        logger.debug("response body = " + body);
        Assertions.assertTrue(body.indexOf("scopes") > 0);
    }

    @Test
    public void testPostExchangeWithoutBearerUsesExchangeContract() throws Exception {
        ClientResponse response = sendRequest(Methods.POST, "/auth/ms/exchange", null);

        Assertions.assertEquals(StatusCodes.UNAUTHORIZED, response.getResponseCode());
        Assertions.assertTrue(response.getAttachment(Http2Client.RESPONSE_BODY).contains("ERR11647"));
        Assertions.assertEquals("no-store", response.getResponseHeaders().getFirst(Headers.CACHE_CONTROL));
    }

    @Test
    public void testLegacyGetExchangeIsRejectedAndObserved() throws Exception {
        long before = MsalTokenExchangeHandler.legacyGetCount("exchange");
        ClientResponse response = sendRequest(Methods.GET, "/auth/ms/exchange", null);

        Assertions.assertEquals(StatusCodes.METHOD_NOT_ALLOWED, response.getResponseCode());
        Assertions.assertEquals("POST", response.getResponseHeaders().getFirst(Headers.ALLOW));
        Assertions.assertEquals("no-store", response.getResponseHeaders().getFirst(Headers.CACHE_CONTROL));
        Assertions.assertTrue(response.getAttachment(Http2Client.RESPONSE_BODY).contains("ERR10008"));
        Assertions.assertNull(response.getResponseHeaders().get(Headers.SET_COOKIE));
        Assertions.assertNull(response.getResponseHeaders().getFirst("X-Test-Next"));
        Assertions.assertEquals(before + 1, MsalTokenExchangeHandler.legacyGetCount("exchange"));
    }

    @Test
    public void testPostLogoutIsIdempotentNoContentAndClearsOwnedCookies() throws Exception {
        ClientResponse response = sendRequest(Methods.POST, "/auth/ms/logout", null);

        Assertions.assertEquals(StatusCodes.NO_CONTENT, response.getResponseCode());
        Assertions.assertNull(response.getResponseHeaders().getFirst(Headers.CONTENT_TYPE));
        Assertions.assertNull(response.getResponseHeaders().getFirst(Headers.CONTENT_LENGTH));
        Assertions.assertEquals("no-store", response.getResponseHeaders().getFirst(Headers.CACHE_CONTROL));
        String body = response.getAttachment(Http2Client.RESPONSE_BODY);
        Assertions.assertTrue(body == null || body.isEmpty());
        List<String> cookies = response.getResponseHeaders().get(Headers.SET_COOKIE);
        for (String name : Arrays.asList("accessToken", "refreshToken", "csrf", "userId", "userType",
                "roles", "host", "email", "eid", MsalExchangeConfig.DEFAULT_MSAL_ACCESS_TOKEN_COOKIE)) {
            Assertions.assertTrue(cookies.stream().anyMatch(value -> value.startsWith(name + "=")
                            && value.contains("Expires=Thu, 01-Jan-1970 00:00:00 GMT")),
                    "missing deletion cookie for " + name + " in " + cookies);
        }
    }

    @Test
    public void testLogoutCsrfObserveOnlyCountsWouldRejectAndStillClearsCookies() throws Exception {
        MsalExchangeConfig config = MsalExchangeConfig.load();
        boolean original = config.isLogoutCsrfEnforced();
        Assertions.assertTrue(original, "shipped default must enforce session-bound logout");
        config.setLogoutCsrfEnforced(false);
        try {
            long before = MsalTokenExchangeHandler.logoutCsrfWouldRejectCount();
            ClientResponse response = sendRequest(Methods.POST, "/auth/ms/logout", "accessToken=expired");

            Assertions.assertEquals(StatusCodes.NO_CONTENT, response.getResponseCode());
            Assertions.assertEquals(before + 1, MsalTokenExchangeHandler.logoutCsrfWouldRejectCount());
            Assertions.assertNotNull(response.getResponseHeaders().get(Headers.SET_COOKIE));
        } finally {
            config.setLogoutCsrfEnforced(original);
        }
    }

    @Test
    public void testLogoutCsrfMatchingValuesAllowExpiredSessionCleanup() throws Exception {
        MsalExchangeConfig config = MsalExchangeConfig.load();
        boolean original = config.isLogoutCsrfEnforced();
        config.setLogoutCsrfEnforced(true);
        try {
            long before = MsalTokenExchangeHandler.logoutCsrfWouldRejectCount();
            ClientResponse response = sendRequest(Methods.POST, "/auth/ms/logout",
                    "accessToken=" + getJwt(-600, "matching") + "; csrf=matching", "matching");

            Assertions.assertEquals(StatusCodes.NO_CONTENT, response.getResponseCode());
            Assertions.assertEquals(before, MsalTokenExchangeHandler.logoutCsrfWouldRejectCount());
            Assertions.assertNotNull(response.getResponseHeaders().get(Headers.SET_COOKIE));
        } finally {
            config.setLogoutCsrfEnforced(original);
        }
    }

    @Test
    public void testLogoutCsrfEnforcementSeparatesMissingHeaderFromInvalidCookie() throws Exception {
        MsalExchangeConfig config = MsalExchangeConfig.load();
        boolean original = config.isLogoutCsrfEnforced();
        config.setLogoutCsrfEnforced(true);
        try {
            ClientResponse missingHeader = sendRequest(Methods.POST, "/auth/ms/logout",
                    "accessToken=expired");
            Assertions.assertEquals(StatusCodes.BAD_REQUEST, missingHeader.getResponseCode());
            Assertions.assertTrue(missingHeader.getAttachment(Http2Client.RESPONSE_BODY).contains("ERR10036"));
            Assertions.assertNull(missingHeader.getResponseHeaders().get(Headers.SET_COOKIE));

            ClientResponse missingCookie = sendRequest(Methods.POST, "/auth/ms/logout",
                    "accessToken=expired", "header-secret");
            ClientResponse mismatch = sendRequest(Methods.POST, "/auth/ms/logout",
                    "accessToken=expired; csrf=cookie-secret", "header-secret");
            Assertions.assertEquals(StatusCodes.BAD_REQUEST, missingCookie.getResponseCode());
            Assertions.assertEquals(StatusCodes.BAD_REQUEST, mismatch.getResponseCode());
            Assertions.assertEquals(missingCookie.getAttachment(Http2Client.RESPONSE_BODY),
                    mismatch.getAttachment(Http2Client.RESPONSE_BODY));
            Assertions.assertTrue(mismatch.getAttachment(Http2Client.RESPONSE_BODY).contains("ERR11649"));
            Assertions.assertFalse(mismatch.getAttachment(Http2Client.RESPONSE_BODY).contains("header-secret"));
            Assertions.assertFalse(mismatch.getAttachment(Http2Client.RESPONSE_BODY).contains("cookie-secret"));
            Assertions.assertNull(mismatch.getResponseHeaders().get(Headers.SET_COOKIE));
        } finally {
            config.setLogoutCsrfEnforced(original);
        }
    }

    @Test
    public void testLegacyGetLogoutIsRejectedAndObserved() throws Exception {
        long before = MsalTokenExchangeHandler.legacyGetCount("logout");
        ClientResponse response = sendRequest(Methods.GET, "/auth/ms/logout", null);

        Assertions.assertEquals(StatusCodes.METHOD_NOT_ALLOWED, response.getResponseCode());
        Assertions.assertEquals("POST", response.getResponseHeaders().getFirst(Headers.ALLOW));
        Assertions.assertTrue(response.getAttachment(Http2Client.RESPONSE_BODY).contains("ERR10008"));
        Assertions.assertNull(response.getResponseHeaders().get(Headers.SET_COOKIE));
        Assertions.assertNull(response.getResponseHeaders().getFirst("X-Test-Next"));
        Assertions.assertEquals(before + 1, MsalTokenExchangeHandler.legacyGetCount("logout"));
        Assertions.assertEquals("no-store", response.getResponseHeaders().getFirst(Headers.CACHE_CONTROL));
    }

    @Test
    public void testWrongMethodIsStructuredAndDoesNotReachNextHandler() throws Exception {
        ClientResponse response = sendRequest(Methods.DELETE, "/auth/ms/logout", null);

        Assertions.assertEquals(StatusCodes.METHOD_NOT_ALLOWED, response.getResponseCode());
        Assertions.assertEquals("POST", response.getResponseHeaders().getFirst(Headers.ALLOW));
        Assertions.assertEquals("no-store", response.getResponseHeaders().getFirst(Headers.CACHE_CONTROL));
        Assertions.assertTrue(response.getAttachment(Http2Client.RESPONSE_BODY).contains("ERR10008"));
        Assertions.assertNull(response.getResponseHeaders().get(Headers.SET_COOKIE));
    }

    @Test
    public void testWrongExchangeMethodHasNoCookieSideEffects() throws Exception {
        ClientResponse response = sendRequest(Methods.DELETE, "/auth/ms/exchange", null);

        Assertions.assertEquals(StatusCodes.METHOD_NOT_ALLOWED, response.getResponseCode());
        Assertions.assertEquals("POST", response.getResponseHeaders().getFirst(Headers.ALLOW));
        Assertions.assertEquals("no-store", response.getResponseHeaders().getFirst(Headers.CACHE_CONTROL));
        Assertions.assertTrue(response.getAttachment(Http2Client.RESPONSE_BODY).contains("ERR10008"));
        Assertions.assertNull(response.getResponseHeaders().get(Headers.SET_COOKIE));
        Assertions.assertNull(response.getResponseHeaders().getFirst("X-Test-Next"));
    }

    @Test
    public void testOptionsPassesThroughWithoutStampingAuthResponseHeaders() throws Exception {
        for(String path : Arrays.asList("/auth/ms/exchange", "/auth/ms/logout")) {
            ClientResponse response = sendRequest(Methods.OPTIONS, path, null);

            Assertions.assertEquals(StatusCodes.NO_CONTENT, response.getResponseCode());
            Assertions.assertEquals("true", response.getResponseHeaders().getFirst("X-Test-Next"));
            Assertions.assertNull(response.getResponseHeaders().getFirst(Headers.CACHE_CONTROL));
            Assertions.assertNull(response.getResponseHeaders().get(Headers.SET_COOKIE));
        }
    }

    @Test
    public void testWrongPathContinuesToNextHandler() throws Exception {
        ClientResponse response = sendRequest(Methods.GET, "/api", null);

        Assertions.assertEquals(StatusCodes.OK, response.getResponseCode());
        Assertions.assertTrue(response.getAttachment(Http2Client.RESPONSE_BODY).startsWith("Authorization="));
        Assertions.assertNull(response.getResponseHeaders().getFirst(Headers.CACHE_CONTROL));
    }

    private ClientResponse sendRequest(HttpString method, String path, String cookie) throws Exception {
        return sendRequest(method, path, cookie, null);
    }

    private ClientResponse sendRequest(HttpString method, String path, String cookie, String csrf) throws Exception {
        return sendRequest(method, path, cookie, csrf, null);
    }

    private ClientResponse sendRequest(HttpString method, String path, String cookie, String csrf, String origin) throws Exception {
        return sendRequest(method, path, cookie, csrf, origin, null, null);
    }
    private ClientResponse sendRequest(HttpString method, String path, String cookie, String csrf, String origin, String subject, String apiToken) throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<ClientResponse> reference = new AtomicReference<>();
        SimpleConnectionState.ConnectionToken token = client.borrow(
                new URI("https://localhost:7080"), Http2Client.WORKER, Http2Client.SSL,
                Http2Client.BUFFER_POOL, OptionMap.create(UndertowOptions.ENABLE_HTTP2, true));
        try {
            ClientConnection connection = (ClientConnection) token.getRawConnection();
            ClientRequest request = new ClientRequest().setPath(path).setMethod(method);
            if (subject != null) request.getRequestHeaders().put(Headers.AUTHORIZATION, "Bearer " + subject);
            if (apiToken != null) request.getRequestHeaders().put(new HttpString(MsalExchangeConfig.DEFAULT_MSAL_ACCESS_TOKEN_HEADER), "Bearer " + apiToken);
            if (origin != null) request.getRequestHeaders().put(Headers.ORIGIN, origin);
            request.getRequestHeaders().put(Headers.HOST, "localhost");
            if (cookie != null) request.getRequestHeaders().put(Headers.COOKIE, cookie);
            if (csrf != null) request.getRequestHeaders().put(HttpStringConstants.CSRF_TOKEN, csrf);
            connection.sendRequest(request, client.createClientCallback(reference, latch));
            Assertions.assertTrue(latch.await(10, TimeUnit.SECONDS), "latch timed out waiting for response");
            return reference.get();
        } finally {
            client.restore(token);
        }
    }


    @Test
    public void testPlantedCsrfAndCrossSessionValuesCannotAuthorizeRequestsOrLogout() throws Exception {
        String jwt = getJwt(600, "victim-session-value");
        String cookies = "accessToken=" + jwt + "; csrf=attacker-chosen";
        for (String path : new String[]{"/api", "/auth/ms/logout"}) {
            ClientResponse rejected = sendRequest(path.equals("/api") ? Methods.GET : Methods.POST,
                    path, cookies, "attacker-chosen");
            Assertions.assertEquals(path.equals("/api") ? StatusCodes.UNAUTHORIZED : StatusCodes.BAD_REQUEST, rejected.getResponseCode());
            String body = rejected.getAttachment(Http2Client.RESPONSE_BODY);
            Assertions.assertFalse(body.contains("attacker-chosen"));
            Assertions.assertFalse(body.contains("victim-session-value"));
            Assertions.assertNull(rejected.getResponseHeaders().get(Headers.SET_COOKIE));
        }
        ClientResponse invalid = sendRequest(Methods.POST, "/auth/ms/logout", "accessToken=not-a-jwt; csrf=matching", "matching");
        Assertions.assertEquals(StatusCodes.BAD_REQUEST, invalid.getResponseCode());
        ClientResponse partial = sendRequest(Methods.POST, "/auth/ms/logout", "refreshToken=opaque; csrf=matching", "matching");
        Assertions.assertEquals(StatusCodes.BAD_REQUEST, partial.getResponseCode());
    }

    @Test
    public void testQueryFallbackAndRefreshOnlyRecoveryAreRejected() throws Exception {
        String jwt = getJwt(600, "session-value");
        String cookie = "accessToken=" + jwt + "; csrf=session-value";
        for (String header : new String[]{null, "session-value"}) {
            ClientResponse response = sendRequest(Methods.GET, "/api?csrf=session-value", cookie, header);
            Assertions.assertEquals(StatusCodes.UNAUTHORIZED, response.getResponseCode());
            Assertions.assertTrue(response.getAttachment(Http2Client.RESPONSE_BODY).contains("ERR10039"));
            Assertions.assertNull(response.getResponseHeaders().get(Headers.SET_COOKIE));
        }
        ClientResponse refresh = sendRequest(Methods.GET, "/api", "refreshToken=opaque; csrf=planted", "planted");
        Assertions.assertEquals(StatusCodes.UNAUTHORIZED, refresh.getResponseCode());
        Assertions.assertNull(refresh.getResponseHeaders().get(Headers.SET_COOKIE));
    }


    @Test
    public void testRenewalPreservesVerifiedCsrfAndSeparatesSessionContexts() throws Exception {
        String refresh = "csrf-renewal-test-" + java.util.UUID.randomUUID();
        for (String csrf : new String[]{com.networknt.auth.csrf.Csrf.nonce(), com.networknt.auth.csrf.Csrf.nonce()}) {
            String jwt = getJwt(30, csrf);
            String cookie = "accessToken=" + jwt + "; refreshToken=" + refresh + "; csrf=" + csrf;
            ClientResponse renewed = sendRequest(Methods.GET, "/api", cookie, csrf);
            Assertions.assertEquals(StatusCodes.OK, renewed.getResponseCode());
            List<String> cookies = renewed.getResponseHeaders().get(Headers.SET_COOKIE);
            Assertions.assertNotNull(cookies);
            Assertions.assertTrue(cookies.stream().anyMatch(value -> value.startsWith("csrf=" + csrf + ";")), cookies.toString());
        }
    }

    @Test
    public void testConcurrentRenewalReturnsConsistentCsrfCookiePairs() throws Exception {
        String csrf = com.networknt.auth.csrf.Csrf.nonce();
        String jwt = getJwt(30, csrf);
        String cookies = "accessToken=" + jwt + "; csrf=" + csrf + "; refreshToken=concurrent-" + java.util.UUID.randomUUID();
        var requests = new java.util.ArrayList<java.util.concurrent.CompletableFuture<ClientResponse>>();
        for (int i = 0; i < 4; i++) requests.add(java.util.concurrent.CompletableFuture.supplyAsync(() -> {
            try { return sendRequest(Methods.GET, "/api", cookies, csrf); }
            catch (Exception e) { throw new java.util.concurrent.CompletionException(e); }
        }));
        for (var request : requests) {
            ClientResponse response = request.get(10, TimeUnit.SECONDS);
            Assertions.assertEquals(StatusCodes.OK, response.getResponseCode());
            List<String> issued = response.getResponseHeaders().get(Headers.SET_COOKIE);
            Assertions.assertTrue(issued.stream().anyMatch(value -> value.startsWith("csrf=" + csrf + ";")));
        }
    }


    @Test
    public void testRefreshOnlyRotatesWithoutExecutingThenAllowsExplicitRetry() throws Exception {
        ClientResponse recovered = sendRequest(Methods.POST, "/api", "accessToken=; refreshToken=recovery-" + java.util.UUID.randomUUID() + "; csrf=planted", "planted", "https://portal.test");
        Assertions.assertEquals(StatusCodes.CONFLICT, recovered.getResponseCode());
        Assertions.assertTrue(recovered.getAttachment(Http2Client.RESPONSE_BODY).contains("SPA_SESSION_REFRESHED"));
        Assertions.assertFalse(recovered.getAttachment(Http2Client.RESPONSE_BODY).contains("ERR10000"));
        Assertions.assertTrue(recovered.getAttachment(Http2Client.RESPONSE_BODY).contains("SESSION_REFRESHED"));
        Assertions.assertNull(recovered.getResponseHeaders().getFirst("X-Test-Next"));
        Assertions.assertEquals("true", recovered.getResponseHeaders().getFirst("X-Session-Refreshed"));
        String csrf = issuedCookie(recovered, "csrf");
        String access = issuedCookie(recovered, "accessToken");
        Assertions.assertTrue(com.networknt.auth.csrf.Csrf.isNonce(csrf));
        Assertions.assertNotEquals("planted", csrf);
        ClientResponse retry = sendRequest(Methods.GET, "/api", "accessToken=" + access + "; csrf=" + csrf, csrf);
        Assertions.assertEquals(StatusCodes.OK, retry.getResponseCode());
    }

    @Test
    public void testLegacyRenewalUpgradesNonceWithoutExecutingTheOriginalRequest() throws Exception {
        String legacy = "legacy-uuid-csrf-value";
        ClientResponse response = sendRequest(Methods.POST, "/api", "accessToken=" + getJwt(30, legacy)
                + "; csrf=" + legacy + "; refreshToken=legacy-" + java.util.UUID.randomUUID(), legacy);
        Assertions.assertEquals(StatusCodes.CONFLICT, response.getResponseCode());
        Assertions.assertTrue(response.getAttachment(Http2Client.RESPONSE_BODY).contains("SPA_SESSION_REFRESHED"));
        Assertions.assertEquals("true", response.getResponseHeaders().getFirst("X-Session-Refreshed"));
        Assertions.assertNull(response.getResponseHeaders().getFirst("X-Test-Next"));
        Assertions.assertTrue(com.networknt.auth.csrf.Csrf.isNonce(issuedCookie(response, "csrf")));
        Assertions.assertNotEquals(legacy, issuedCookie(response, "csrf"));
    }

    @Test
    public void testTrustedLogoutCanClearPartialOrUnverifiableSessions() throws Exception {
        for (String cookie : new String[]{"refreshToken=expired-access; csrf=stale", "csrf=orphan", "accessToken=broken; csrf=old"}) {
            ClientResponse rejected = sendRequest(Methods.POST, "/auth/ms/logout", cookie, null, "https://evil.test");
            Assertions.assertEquals(StatusCodes.BAD_REQUEST, rejected.getResponseCode());
            Assertions.assertNull(rejected.getResponseHeaders().get(Headers.SET_COOKIE));
            ClientResponse cleared = sendRequest(Methods.POST, "/auth/ms/logout", cookie, null, "https://portal.test");
            Assertions.assertEquals(StatusCodes.NO_CONTENT, cleared.getResponseCode());
            Assertions.assertTrue(cleared.getResponseHeaders().get(Headers.SET_COOKIE).stream().anyMatch(value -> value.startsWith("refreshToken=;")));
        }
    }

    @Test
    public void testAnonymousQueriesOptionsAndNativeReadOnlyBrowserRequests() throws Exception {
        Assertions.assertEquals(StatusCodes.OK, sendRequest(Methods.GET, "/api?csrf=ordinary-data", null, null).getResponseCode());
        Assertions.assertEquals(StatusCodes.NO_CONTENT, sendRequest(Methods.OPTIONS, "/auth/ms/exchange?csrf=preflight-data", null, null).getResponseCode());
        String csrf = com.networknt.auth.csrf.Csrf.nonce();
        String cookie = "accessToken=" + getJwt(600, csrf) + "; csrf=" + csrf;
        Assertions.assertEquals(StatusCodes.OK, sendRequest(Methods.OPTIONS, "/api?csrf=ignored", cookie, null).getResponseCode());
        Assertions.assertEquals(StatusCodes.OK, sendRequest(Methods.GET, "/api", cookie, null, "https://portal.test").getResponseCode());
        Assertions.assertEquals(StatusCodes.UNAUTHORIZED, sendRequest(Methods.GET, "/api", cookie, null, "https://evil.test").getResponseCode());
        Assertions.assertEquals(StatusCodes.UNAUTHORIZED, sendRequest(Methods.POST, "/api", cookie, null, "https://portal.test").getResponseCode());
        Assertions.assertEquals(StatusCodes.UNAUTHORIZED, sendRequest(Methods.GET, "/api?csrf=" + csrf, cookie, null, "https://portal.test").getResponseCode());
    }


    @Test
    public void testFailedRecoveryClearsCookiesAndNeverExecutesRequest() throws Exception {
        ClientResponse response = sendRequest(Methods.POST, "/api", "refreshToken=invalid-refresh; csrf=stale", null, "https://portal.test");
        Assertions.assertEquals(StatusCodes.UNAUTHORIZED, response.getResponseCode());
        Assertions.assertNull(response.getResponseHeaders().getFirst("X-Test-Next"));
        Assertions.assertEquals("", issuedCookie(response, "refreshToken"));
        Assertions.assertEquals("", issuedCookie(response, "accessToken"));
        Assertions.assertEquals("", issuedCookie(response, "csrf"));
    }


    @Test
    public void testRustDeadRefreshClearsCookies() throws Exception {
        for (String reason : new String[]{"missing", "client", "provider", "host"}) {
            ClientResponse response = sendRequest(Methods.POST, "/api", "refreshToken=rust-dead-refresh-" + reason + "; csrf=stale", null, "https://portal.test");
            Assertions.assertEquals(StatusCodes.UNAUTHORIZED, response.getResponseCode(), reason);
            Assertions.assertEquals("", issuedCookie(response, "refreshToken"));
            Assertions.assertEquals("", issuedCookie(response, "accessToken"));
            Assertions.assertNull(response.getResponseHeaders().getFirst("X-Test-Next"));
        }
    }

    @Test
    public void testTemporaryRenewalNeverForwardsTokenExpiredDuringAttempt() throws Exception {
        String csrf = com.networknt.auth.csrf.Csrf.nonce();
        ClientResponse response = sendRequest(Methods.POST, "/api", "refreshToken=delayed-error-refresh; csrf=" + csrf
                + "; accessToken=" + getJwt(2, csrf), csrf, "https://portal.test");
        Assertions.assertEquals(StatusCodes.SERVICE_UNAVAILABLE, response.getResponseCode());
        Assertions.assertNull(response.getResponseHeaders().get(Headers.SET_COOKIE));
        Assertions.assertNull(response.getResponseHeaders().getFirst("X-Test-Next"));
    }

    @Test
    public void testRetiredKeyLogoutRequiresTrustedBrowser() throws Exception {
        String csrf = com.networknt.auth.csrf.Csrf.nonce();
        String token = retiredKeyJwt(csrf);
        String cookies = "accessToken=" + token + "; csrf=" + csrf;
        ClientResponse rejected = sendRequest(Methods.POST, "/auth/ms/logout", cookies, null, "https://evil.test");
        Assertions.assertEquals(StatusCodes.BAD_REQUEST, rejected.getResponseCode());
        Assertions.assertNull(rejected.getResponseHeaders().get(Headers.SET_COOKIE));
        ClientResponse cleaned = sendRequest(Methods.POST, "/auth/ms/logout", cookies, null, "https://portal.test");
        Assertions.assertEquals(StatusCodes.NO_CONTENT, cleaned.getResponseCode());
        Assertions.assertEquals("", issuedCookie(cleaned, "accessToken"));
    }

    private static String retiredKeyJwt(String csrf) throws Exception {
        String token = getJwt(600, csrf);
        String[] parts = token.split("\\.");
        String header = new String(java.util.Base64.getUrlDecoder().decode(parts[0]), java.nio.charset.StandardCharsets.UTF_8)
                .replace("Tj_l_tIBTginOtQbL0Pv5w", "retired-key");
        token = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes(java.nio.charset.StandardCharsets.UTF_8))
                + "." + parts[1] + "." + parts[2];
        return token;
    }







    @Test
    public void testTemporaryRecoveryAndRenewalFailuresPreserveCookies() throws Exception {
        for (String refresh : new String[]{"transient-refresh", "network-error-refresh", "unknown-refresh", "plain-error-refresh"}) {
            for (boolean hasAccess : new boolean[]{false, true}) {
                String csrf = com.networknt.auth.csrf.Csrf.nonce();
                String cookies = "refreshToken=" + refresh + "; csrf=" + csrf
                        + (hasAccess ? "; accessToken=" + getJwt(30, csrf) : "");
                ClientResponse response = sendRequest(Methods.POST, "/api", cookies, csrf, "https://portal.test");
                Assertions.assertEquals(hasAccess ? StatusCodes.OK : StatusCodes.SERVICE_UNAVAILABLE, response.getResponseCode());
                if (!hasAccess) Assertions.assertTrue(response.getAttachment(Http2Client.RESPONSE_BODY).contains("SPA_SESSION_TEMPORARY_FAILURE"));
                Assertions.assertNull(response.getResponseHeaders().get(Headers.SET_COOKIE));
                Assertions.assertEquals(hasAccess ? "true" : null, response.getResponseHeaders().getFirst("X-Test-Next"));
                Assertions.assertEquals(hasAccess ? null : "1", response.getResponseHeaders().getFirst(Headers.RETRY_AFTER));
            }
        }
    }

    @Test
    public void testWaiterTimeoutDoesNotEraseSuccessfulOwnerRecovery() throws Exception {
        slowRefreshEntered = new CountDownLatch(1);
        slowRefreshRelease = new CountDownLatch(1);
        String cookie = "refreshToken=slow-refresh-" + java.util.UUID.randomUUID() + "; csrf=stale";
        var owner = java.util.concurrent.CompletableFuture.supplyAsync(() -> {
            try { return sendRequest(Methods.POST, "/api", cookie, null, "https://portal.test"); }
            catch (Exception e) { throw new java.util.concurrent.CompletionException(e); }
        });
        try {
            Assertions.assertTrue(slowRefreshEntered.await(3, TimeUnit.SECONDS));
            ClientResponse waiter = sendRequest(Methods.POST, "/api", cookie, null, "https://portal.test");
            Assertions.assertEquals(StatusCodes.SERVICE_UNAVAILABLE, waiter.getResponseCode());
            Assertions.assertNull(waiter.getResponseHeaders().get(Headers.SET_COOKIE));
            Assertions.assertNull(waiter.getResponseHeaders().getFirst("X-Test-Next"));
        } finally {
            slowRefreshRelease.countDown();
        }
        ClientResponse completed = owner.get(5, TimeUnit.SECONDS);
        Assertions.assertEquals(StatusCodes.CONFLICT, completed.getResponseCode());
        String csrf = issuedCookie(completed, "csrf");
        Assertions.assertTrue(com.networknt.auth.csrf.Csrf.isNonce(csrf));
        Assertions.assertEquals(StatusCodes.OK, sendRequest(Methods.GET, "/api",
                "accessToken=" + issuedCookie(completed, "accessToken") + "; csrf=" + csrf, csrf).getResponseCode());
    }

    @Test
    public void testTrustedBrowserStillNeedsCsrfForAUsableLogoutSession() throws Exception {
        String csrf = com.networknt.auth.csrf.Csrf.nonce();
        String cookies = "accessToken=" + getJwt(600, csrf) + "; csrf=" + csrf;
        long before = MsalTokenExchangeHandler.logoutCsrfWouldRejectCount();
        for (String request : new String[]{null, "wrong"}) {
            ClientResponse rejected = sendRequest(Methods.POST, "/auth/ms/logout", cookies, request, "https://portal.test");
            Assertions.assertEquals(StatusCodes.BAD_REQUEST, rejected.getResponseCode());
            Assertions.assertNull(rejected.getResponseHeaders().get(Headers.SET_COOKIE));
        }
        Assertions.assertEquals(before + 2, MsalTokenExchangeHandler.logoutCsrfWouldRejectCount());
        Assertions.assertEquals(StatusCodes.NO_CONTENT, sendRequest(Methods.POST, "/auth/ms/logout", cookies, csrf, "https://portal.test").getResponseCode());
        MsalExchangeConfig config = MsalExchangeConfig.load();
        boolean original = config.isLogoutCsrfEnforced();
        try {
            config.setLogoutCsrfEnforced(false);
            Assertions.assertEquals(StatusCodes.NO_CONTENT, sendRequest(Methods.POST, "/auth/ms/logout", cookies, null, "https://portal.test").getResponseCode());
            Assertions.assertEquals(before + 3, MsalTokenExchangeHandler.logoutCsrfWouldRejectCount());
        } finally { config.setLogoutCsrfEnforced(original); }
    }

    private String issuedCookie(ClientResponse response, String name) {
        return response.getResponseHeaders().get(Headers.SET_COOKIE).stream()
                .filter(value -> value.startsWith(name + "="))
                .map(value -> io.undertow.util.Cookies.parseSetCookieHeader(value).getValue()).findFirst().orElseThrow();
    }

    private static String getJwt(int expiredInSeconds, String csrfToken) throws Exception {
        JwtClaims claims = getTestClaims(csrfToken);
        claims.setExpirationTime(NumericDate.fromMilliseconds(System.currentTimeMillis() + expiredInSeconds * 1000));
        if (expiredInSeconds < 0) {
            claims.setIssuedAt(NumericDate.fromSeconds(System.currentTimeMillis() / 1000 + expiredInSeconds - 600));
            claims.setNotBefore(NumericDate.fromSeconds(System.currentTimeMillis() / 1000 + expiredInSeconds - 600));
        }
        return getJwt(claims);
    }

    private static JwtClaims getTestClaims(String csrfToken) {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("urn:com:networknt:oauth2:v1");
        claims.setAudience("urn:com.networknt");
        claims.setExpirationTimeMinutesInTheFuture(10);
        claims.setGeneratedJwtId(); // a unique identifier for the token
        claims.setIssuedAtToNow();  // when the token was issued/created (now)
        claims.setNotBeforeMinutesInThePast(2); // time before which the token is not yet valid (2 minutes ago)
        claims.setClaim("version", "1.0");

        claims.setClaim("user_id", "steve");
        claims.setClaim("user_type", "EMPLOYEE");
        claims.setClaim("client_id", "aaaaaaaa-1234-1234-1234-bbbbbbbb");
        claims.setClaim("role", "user admin"); // set multiple roles separated by space
        if(csrfToken != null) claims.setClaim("csrf", csrfToken);
        List<String> scope = Arrays.asList("api.r", "api.w");
        claims.setStringListClaim("scope", scope); // multi-valued claims work too and will end up as a JSON array
        return claims;
    }

    private static String getMicrosoftJwt(boolean access) throws Exception { return getJwt(getMicrosoftClaims(access)); }
    private static JwtClaims getMicrosoftClaims(boolean access) throws Exception {
        JwtClaims claims = getTestClaims(null);
        claims.setIssuer("https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222/v2.0");
        claims.setAudience(access ? "api://gateway" : "11111111-1111-1111-1111-111111111111");
        claims.setSubject("fixture-user");
        claims.setClaim("tid", "22222222-2222-2222-2222-222222222222");
        claims.setClaim("ver", "2.0");
        if (access) {
            claims.setClaim("azp", "11111111-1111-1111-1111-111111111111");
            claims.setClaim("scp", "gateway.read");
        } else claims.setClaim("nonce", "fixture-login-nonce");
        return claims;
    }

    private static String getJwt(JwtClaims claims) throws Exception {
        String long_kid = "Tj_l_tIBTginOtQbL0Pv5w";
        String long_key = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDRhFtYBvUUYOk9RRysikkLoHCWzCUoxL7PbAwCht2jQE3E1ruEb+AgdU+Re7Xgl+jUmFSFLjARLcN1jdrqiWo9xE3VMIJRUd37VMt3UEFL7Kr210nocJ7CF7l9eidpFErC62+gfuL95Hibd9DUahXNUADcieClOvim2czcR/d+P7nBliaK3OtFTJC18BFOXeoZpc/+DykcUA/TOs1W86dX6Nw0wqbxhk1yByzVK4tIW1QNel/s2vb/E6GI0z5uIRLoPNrWwwuuXFQsW5y25072XKQHvIWHcsczG0hnIhQe7LRFuO44YLk+YOjAu21mk8j+PjKckcBoBavwN3PvrhZ1AgMBAAECggEBAMuDYGLqJydLV2PPfSHQFVH430RrOfEW4y2CC0xtCl8n+CKqXm0vaqq8qLRtUWa+yEexS/AtxDz7ke/fAfVt00f6JYxe2Ub6WcBnRlg4GaURV6P7zWu98UghWWkbvaphLpmVrdFdT0pFoi2JvcyG23SaMKwINbDpzlvsFgUm1q3GoCIZXRc8iAKT+Iil1QmGdacGni/D2WzPTLSf1/acZU2TsPBWLS/jsjPe4ac4IDpxssDC+w6QArZ8U64DKJ531C4tK9o+RArQzBrEaZc1mAlw7xAPr36tXvOTUycux6k07ERSIIze2okVmmewL6tX1cb7tY1F8T+ebKGD3xGEAYUCgYEA9Lpy4593uTBww7AupcZq2YL8qHUfnvxIWiFbeIznUezyYyRbjyLDYj+g7QfQJHk579UckDZZDcT3H+wdh1LxQ7HKDlYQn2zt8Kdufs5cvSObeGkSqSY26g4QDRcRcRO3xFs8bQ/CnPNT7hsWSY+8wnuRvjUTstMA1vx1+/HHZfMCgYEA2yq8yFogdd2/wUcFlqjPgbJ98X9ZNbZ06uUCur4egseVlSVE+R2pigVVwFCDQpseGu2GVgW5q8kgDGsaJuEVWIhGZvS9IHONBz/WB0PmOZjXlXOhmT6iT6m/9bAQk8MtOee77lUVvgf7FO8XDKtuPh6VGJpr+YJHxHoEX/dbo/cCgYAjwy9Q1hffxxVjc1aNwR4SJRMY5uy1BfbovOEqD6UqEq8lD8YVd6YHsHaqzK589f4ibwkaheajnXnjf1SdVuCM3OlDCQ6qzXdD6KO8AhoJRa/Ne8VPVJdHwsBTuWBCHviGyDJfWaM93k0QiYLLQyb5YKdenVEAm9cOk5wGMkHKQwKBgH050CASDxYJm/UNZY4N6nLKz9da0lg0Zl2IeKTG2JwU+cz8PIqyfhqUrchyuG0oQG1WZjlkkBAtnRg7YffxB8dMJh3RnPabz2ri+KGyFCu4vwVvylfLR+aIsVvqO66SCJdbZy/ogcHQwY/WhK8CjL0FsF8cbLFl1SfYKAPFTCFFAoGANmOKonyafvWqsSkcl6vUTYYq53IN+qt0IJTDB2cEIEqLXtNth48HvdQkxDF3y4cNLZevhyuIy0Z3yWGbZM2yWbDNn8Q2W5RTyajofQu1mIv2EBzLeOoaSBPLX4G6r4cODSwWbjOdaNxcXd0+uYeAWDuQUSnHpHFJ2r1cpL/9Nbs=";
        String jwt;

        PrivateKey privateKey = KeyUtil.deserializePrivateKey(long_key, KeyUtil.RSA);

        // A JWT is a JWS and/or a JWE with JSON claims as the payload.
        // In this example it is a JWS nested inside a JWE
        // So we first create a JsonWebSignature object.
        JsonWebSignature jws = new JsonWebSignature();

        // The payload of the JWS is JSON content of the JWT Claims
        jws.setPayload(claims.toJson());

        // The JWT is signed using the sender's private key
        jws.setKey(privateKey);
        jws.setKeyIdHeaderValue(long_kid);

        // Set the signature algorithm on the JWT/JWS that will integrity protect the claims
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

        // Sign the JWS and produce the compact serialization, which will be the inner JWT/JWS
        // representation, which is a string consisting of three dot ('.') separated
        // base64url-encoded parts in the form Header.Payload.Signature
        jwt = jws.getCompactSerialization();
        return jwt;
    }

    private static KeyStore loadKeyStore(final String name) throws IOException {
        final InputStream stream = Config.getInstance().getInputStreamFromFile(name);
        if(stream == null) {
            throw new RuntimeException("Could not load keystore");
        }
        try {
            KeyStore loadedKeystore = KeyStore.getInstance("JKS");
            loadedKeystore.load(stream, STORE_PASSWORD);

            return loadedKeystore;
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            throw new IOException(String.format("Unable to load KeyStore %s", name), e);
        } finally {
            IoUtils.safeClose(stream);
        }
    }

    private static SSLContext createSSLContext(final KeyStore keyStore, final KeyStore trustStore, boolean client) throws IOException {
        KeyManager[] keyManagers;
        try {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, STORE_PASSWORD);
            keyManagers = keyManagerFactory.getKeyManagers();
        } catch (NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException e) {
            throw new IOException("Unable to initialise KeyManager[]", e);
        }

        TrustManager[] trustManagers = null;
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);
            trustManagers = trustManagerFactory.getTrustManagers();
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            throw new IOException("Unable to initialise TrustManager[]", e);
        }

        SSLContext sslContext;
        try {
            if(!client) {
                sslContext = SSLContext.getInstance("TLS");
            } else {
                sslContext = SSLContext.getInstance("TLS");
            }
            sslContext.init(keyManagers, trustManagers, null);
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new IOException("Unable to create and initialise the SSLContext", e);
        }

        return sslContext;
    }

    @Test
    public void testCsrfInSecondSubprotocolHeader() throws Exception {
        // Test the subsequent-request CSRF validation flow directly.
        // We craft a JWT with a known CSRF claim, pass it as the accessToken cookie,
        // then verify the handler correctly extracts CSRF from a comma-separated
        // Sec-WebSocket-Protocol header (the updated logic, not the old startsWith approach).
        String testCsrf = "testCsrfValue123";
        String jwt = getJwt(600, testCsrf);

        final CountDownLatch latch = new CountDownLatch(1);
        final SimpleConnectionState.ConnectionToken connectionToken;

        try {
            connectionToken = client.borrow(new URI("https://localhost:7080"), Http2Client.WORKER, Http2Client.SSL, Http2Client.BUFFER_POOL, OptionMap.create(UndertowOptions.ENABLE_HTTP2, true));
        } catch (Exception e) {
            throw new ClientException(e);
        }

        final ClientConnection connection = (ClientConnection) connectionToken.getRawConnection();
        final AtomicReference<ClientResponse> reference = new AtomicReference<>();
        try {
            ClientRequest request = new ClientRequest().setPath("/api").setMethod(Methods.GET);
            // Set the crafted JWT as the accessToken cookie
            request.getRequestHeaders().put(Headers.COOKIE, "accessToken=" + jwt);
            // simulate a WebSocket upgrade request
            request.getRequestHeaders().put(Headers.UPGRADE, "websocket");
            request.getRequestHeaders().put(Headers.CONNECTION, "Upgrade");
            request.getRequestHeaders().put(Headers.ORIGIN, "https://portal.test");
            request.getRequestHeaders().put(new HttpString("Sec-WebSocket-Version"), "13");
            request.getRequestHeaders().put(new HttpString("Sec-WebSocket-Key"), "dGhlIHNhbXBsZSBub25jZQ==");
            // csrf token is the second subprotocol, not the first
            request.getRequestHeaders().put(new HttpString("Sec-WebSocket-Protocol"), "chat, csrf." + testCsrf);
            connection.sendRequest(request, client.createClientCallback(reference, latch));
            Assertions.assertTrue(latch.await(10, TimeUnit.SECONDS), "latch timed out waiting for response");
        } catch (Exception e) {
            logger.error("Exception: ", e);
            throw new ClientException(e);
        } finally {
            client.restore(connectionToken);
        }

        int statusCode = reference.get().getResponseCode();
        Assertions.assertEquals(StatusCodes.OK, statusCode);
    }

    @Test
    public void testAzureMsalPlacementPreservesAuthorizationAndInjectsLightToken() throws Exception {
        String testCsrf = "testCsrfValue123";
        String lightJwt = getJwt(600, testCsrf);
        String azureJwt = getMicrosoftJwt(true);
        MsalExchangeConfig config = MsalExchangeConfig.load();
        String originalAuthorizationToken = config.getAuthorizationToken();
        String originalLightTokenHeader = config.getLightTokenHeader();
        String originalMsalAccessTokenCookie = config.getMsalAccessTokenCookie();
        config.setAuthorizationToken(MsalExchangeConfig.AUTHORIZATION_TOKEN_AZURE_MSAL);
        config.setLightTokenHeader(MsalExchangeConfig.DEFAULT_LIGHT_TOKEN_HEADER);
        config.setMsalAccessTokenCookie(MsalExchangeConfig.DEFAULT_MSAL_ACCESS_TOKEN_COOKIE);

        final CountDownLatch latch = new CountDownLatch(1);
        final SimpleConnectionState.ConnectionToken connectionToken;

        try {
            connectionToken = client.borrow(new URI("https://localhost:7080"), Http2Client.WORKER, Http2Client.SSL, Http2Client.BUFFER_POOL, OptionMap.create(UndertowOptions.ENABLE_HTTP2, true));
        } catch (Exception e) {
            config.setAuthorizationToken(originalAuthorizationToken);
            config.setLightTokenHeader(originalLightTokenHeader);
            config.setMsalAccessTokenCookie(originalMsalAccessTokenCookie);
            throw new ClientException(e);
        }

        final ClientConnection connection = (ClientConnection) connectionToken.getRawConnection();
        final AtomicReference<ClientResponse> reference = new AtomicReference<>();
        try {
            ClientRequest request = new ClientRequest().setPath("/api").setMethod(Methods.GET);
            request.getRequestHeaders().put(Headers.COOKIE, "accessToken=" + lightJwt + "; " + MsalExchangeConfig.DEFAULT_MSAL_ACCESS_TOKEN_COOKIE + "=" + azureJwt);
            request.getRequestHeaders().put(new HttpString("X-CSRF-TOKEN"), testCsrf);
            connection.sendRequest(request, client.createClientCallback(reference, latch));
            Assertions.assertTrue(latch.await(10, TimeUnit.SECONDS), "latch timed out waiting for response");
        } catch (Exception e) {
            logger.error("Exception: ", e);
            throw new ClientException(e);
        } finally {
            config.setAuthorizationToken(originalAuthorizationToken);
            config.setLightTokenHeader(originalLightTokenHeader);
            config.setMsalAccessTokenCookie(originalMsalAccessTokenCookie);
            client.restore(connectionToken);
        }

        int statusCode = reference.get().getResponseCode();
        String body = reference.get().getAttachment(Http2Client.RESPONSE_BODY);
        Assertions.assertEquals(StatusCodes.OK, statusCode);
        Assertions.assertTrue(body.contains("Authorization=Bearer " + azureJwt));
        Assertions.assertTrue(body.contains("X-Light-Token=Bearer " + lightJwt));
    }

    @Test
    public void testAzureMsalExchangeStoresMsalAccessTokenCookie() throws Exception {
        String idJwt = getMicrosoftJwt(false);
        String azureAccessJwt = getMicrosoftJwt(true);
        MsalExchangeConfig config = MsalExchangeConfig.load();
        String originalAuthorizationToken = config.getAuthorizationToken();
        String originalExchangePath = config.getExchangePath();
        String originalLightTokenHeader = config.getLightTokenHeader();
        String originalMsalAccessTokenHeader = config.getMsalAccessTokenHeader();
        String originalMsalAccessTokenCookie = config.getMsalAccessTokenCookie();
        config.setAuthorizationToken(MsalExchangeConfig.AUTHORIZATION_TOKEN_AZURE_MSAL);
        config.setExchangePath("/api/ms/exchange");
        config.setLightTokenHeader(MsalExchangeConfig.DEFAULT_LIGHT_TOKEN_HEADER);
        config.setMsalAccessTokenHeader(MsalExchangeConfig.DEFAULT_MSAL_ACCESS_TOKEN_HEADER);
        config.setMsalAccessTokenCookie(MsalExchangeConfig.DEFAULT_MSAL_ACCESS_TOKEN_COOKIE);

        final CountDownLatch latch = new CountDownLatch(1);
        final SimpleConnectionState.ConnectionToken connectionToken;

        try {
            connectionToken = client.borrow(new URI("https://localhost:7080"), Http2Client.WORKER, Http2Client.SSL, Http2Client.BUFFER_POOL, OptionMap.create(UndertowOptions.ENABLE_HTTP2, true));
        } catch (Exception e) {
            config.setAuthorizationToken(originalAuthorizationToken);
            config.setExchangePath(originalExchangePath);
            config.setLightTokenHeader(originalLightTokenHeader);
            config.setMsalAccessTokenHeader(originalMsalAccessTokenHeader);
            config.setMsalAccessTokenCookie(originalMsalAccessTokenCookie);
            throw new ClientException(e);
        }

        final ClientConnection connection = (ClientConnection) connectionToken.getRawConnection();
        final AtomicReference<ClientResponse> reference = new AtomicReference<>();
        try {
            ClientRequest request = new ClientRequest().setPath("/api/ms/exchange").setMethod(Methods.POST);
            request.getRequestHeaders().put(Headers.AUTHORIZATION, "Bearer " + idJwt);
            request.getRequestHeaders().put(new HttpString(MsalExchangeConfig.DEFAULT_MSAL_ACCESS_TOKEN_HEADER), "Bearer " + azureAccessJwt);
            connection.sendRequest(request, client.createClientCallback(reference, latch));
            Assertions.assertTrue(latch.await(10, TimeUnit.SECONDS), "latch timed out waiting for response");
        } catch (Exception e) {
            logger.error("Exception: ", e);
            throw new ClientException(e);
        } finally {
            config.setAuthorizationToken(originalAuthorizationToken);
            config.setExchangePath(originalExchangePath);
            config.setLightTokenHeader(originalLightTokenHeader);
            config.setMsalAccessTokenHeader(originalMsalAccessTokenHeader);
            config.setMsalAccessTokenCookie(originalMsalAccessTokenCookie);
            client.restore(connectionToken);
        }

        Assertions.assertEquals(StatusCodes.OK, reference.get().getResponseCode());
        List<String> setCookies = reference.get().getResponseHeaders().get(Headers.SET_COOKIE);
        Assertions.assertNotNull(setCookies, "Expected Set-Cookie headers");
        Assertions.assertTrue(setCookies.stream().anyMatch(cookie -> cookie.startsWith(MsalExchangeConfig.DEFAULT_MSAL_ACCESS_TOKEN_COOKIE + "=" + azureAccessJwt)));
    }

    @Test
    public void testArrayConverter() {
        String[] scopes = {"abc", "efg"};
        String s = Arrays.toString(scopes);
        System.out.println(s);
    }

}
