package com.networknt.auth;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.classic.spi.ThrowableProxy;
import ch.qos.logback.core.read.ListAppender;
import com.networknt.client.oauth.TokenResponse;
import com.networknt.exception.ExpiredTokenException;
import com.networknt.security.JwtVerifier;
import com.networknt.security.SecurityConfig;
import com.networknt.security.VerificationException;
import io.undertow.Undertow;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.parallel.Isolated;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.*;

/** Local signed-token probes; no external OAuth/JWKS endpoint or real credentials. */
@Isolated
@Execution(ExecutionMode.SAME_THREAD)
class MsalSessionLoggingTest {
    private static final String ISSUER = "urn:com:networknt:oauth2:v1";
    private static final String AUDIENCE = "urn:com.networknt";
    private static final String CSRF = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("a28-nonce-fixture-0000000000000000".getBytes(StandardCharsets.UTF_8));
    private static KeyPair keys;
    @AutoClose private Probe probe;

    @BeforeAll static void keys() throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keys = generator.generateKeyPair();
    }
    @BeforeEach void setup() throws Exception { probe = new Probe(); probe.start(); }

    @Test void validSessionDoesNotLogJwtOrCsrf() throws Exception {
        assertEquals(200, probe.request(token(CSRF), CSRF, "").statusCode());
    }
    @Test void mismatchedSubmittedCsrfIsNotReflectedOrLogged() throws Exception {
        probe.watch.add("a28-header-csrf-canary");
        assertEquals(401, probe.request(token(CSRF), "a28-header-csrf-canary", "").statusCode());
    }
    @Test void decodedQueryControlCharactersCannotForgeTheCsrfDiagnostic() throws Exception {
        String input = "a28-query-csrf-canary\r\nforged-line=1";
        probe.watch.add("a28-query-csrf-canary");
        assertEquals(401, probe.request(token(CSRF), null,
                "?csrf=" + URLEncoder.encode(input, StandardCharsets.UTF_8)).statusCode());
    }
    @Test void signedClaimControlCharactersAreNotReflectedOrLogged() throws Exception {
        String claim = "a28-claim-csrf-canary\r\nforged-line=1";
        probe.watch.add("a28-claim-csrf-canary");
        assertEquals(401, probe.request(token(claim), CSRF, "").statusCode());
    }
    @Test void malformedAndTamperedCookieTokensAreRejectedWithoutRawThrowableLogs() throws Exception {
        assertEquals(401, probe.request("a28-malformed-token-canary", CSRF, "").statusCode());
        String valid = token(CSRF);
        int signature = valid.lastIndexOf('.') + 1;
        String tampered = valid.substring(0, signature) + (valid.charAt(signature) == 'A' ? 'B' : 'A')
                + valid.substring(signature + 1);
        assertEquals(401, probe.request(tampered, CSRF, "").statusCode());
    }
    @Test void invalidIssuedTokenCannotReachCookieIssuanceLogs() throws Exception {
        probe.issuedToken = "a28-issued-token-canary\r\nforged-line=1";
        probe.watch.add("a28-issued-token-canary");
        assertEquals(401, probe.request(null, null, "/issued").statusCode());
    }

    @Test void malformedMicrosoftCookieDoesNotReachVerifierLogs() throws Exception {
        MsalExchangeConfig config = MsalExchangeConfig.load();
        Field field = MsalExchangeConfig.class.getDeclaredField("authorizationToken");
        field.setAccessible(true);
        Object previous = field.get(config);
        probe.restore.add(() -> field.set(config, previous));
        field.set(config, "azure-msal");
        probe.extraCookie = "; msalAccessToken=a28-msal-token-canary";
        probe.watch.add("a28-msal-token-canary");
        assertEquals(401, probe.request(token(CSRF), CSRF, "").statusCode());
    }

    @Test void keyResolutionFailureIsRedactedAndRetainsServerError() throws Exception {
        probe.watch.add("a28-key-resolution-canary");
        Field field = MsalTokenExchangeHandler.class.getDeclaredField("internalJwtVerifier");
        field.setAccessible(true);
        field.set(null, new LocalLegacyVerifier() {
            @Override public JwtClaims verifyJwt(String jwt, boolean ignoreExpiry, boolean token,
                    String prefix, String path, List<String> services) {
                throw new VerificationException("a28-key-resolution-canary\r\nforged-line=1");
            }
        });
        assertEquals(500, probe.request(token(CSRF), CSRF, "").statusCode());
    }

    private String token(String csrf) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(ISSUER);
        claims.setAudience(AUDIENCE);
        claims.setExpirationTimeMinutesInTheFuture(30);
        claims.setClaim("csrf", csrf);
        claims.setClaim("uid", "a28-user-claim-canary");
        claims.setClaim("scp", List.of("audit.read"));
        JsonWebSignature signed = new JsonWebSignature();
        signed.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        signed.setKeyIdHeaderValue("a28-fixture-key");
        signed.setPayload(claims.toJson());
        signed.setKey(keys.getPrivate());
        return signed.getCompactSerialization();
    }

    private static class LocalLegacyVerifier extends JwtVerifier {
        LocalLegacyVerifier() { super(SecurityConfig.load("security-a28")); }
        @Override public JwtClaims verifyJwt(String jwt, boolean ignoreExpiry, boolean token)
                throws InvalidJwtException, ExpiredTokenException {
            return verifyJwt(jwt, ignoreExpiry, token, null, null, null);
        }
        @Override public JwtClaims verifyJwt(String jwt, boolean ignoreExpiry, boolean token,
                String prefix, String path, List<String> services) throws InvalidJwtException, ExpiredTokenException {
            return super.verifyJwt(jwt, ignoreExpiry, token, prefix, path, services,
                    (kid, endpoint) -> (jws, context) -> keys.getPublic());
        }
    }

    private static final class Probe implements AutoCloseable {
        final List<String> watch = new CopyOnWriteArrayList<>(List.of(CSRF, "a28-user-claim-canary"));
        final List<Executable> restore = new ArrayList<>();
        final List<Throwable> escaped = new CopyOnWriteArrayList<>();
        final ListAppender<ILoggingEvent> logs = new ListAppender<>() {
            @Override protected void append(ILoggingEvent event) {
                event.prepareForDeferredProcessing();
                super.append(event);
            }
        };
        Undertow server;
        HttpClient client;
        URI base;
        volatile String issuedToken;
        volatile String extraCookie = "";

        void start() throws Exception {
            MsalTokenExchangeHandler handler = new MsalTokenExchangeHandler();
            MsalExchangeConfig config = MsalExchangeConfig.load();
            installTrust(config, handler.getClass());
            Logger root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
            Level oldRoot = root.getLevel();
            restore.add(() -> root.setLevel(oldRoot));
            root.setLevel(Level.WARN);
            for (String name : new String[]{MsalTokenExchangeHandler.class.getName(), "com.networknt.handler.LightHttpHandler"}) {
                Logger logger = (Logger) LoggerFactory.getLogger(name);
                Level level = logger.getLevel();
                restore.add(() -> logger.setLevel(level));
                logger.setLevel(Level.TRACE);
            }
            logs.list = new CopyOnWriteArrayList<>();
            logs.start();
            root.addAppender(logs);
            restore.add(() -> root.detachAppender(logs));
            handler.setNext(exchange -> exchange.getResponseSender().send("ok"));
            server = Undertow.builder().addHttpListener(0, "127.0.0.1").setIoThreads(1).setWorkerThreads(2)
                    .setHandler(exchange -> exchange.dispatch(request -> {
                        if (request.getRequestPath().endsWith("/issued")) {
                            TokenResponse response = new TokenResponse();
                            response.setAccessToken(issuedToken);
                            response.setRefreshToken("a28-refresh-fixture");
                            response.setExpiresIn(1800);
                            if (handler.setCookies(request, response, CSRF, config) != null)
                                request.getResponseSender().send("ok");
                        } else {
                            try { handler.handleRequest(request); }
                            catch (Throwable failure) { escaped.add(failure); throw failure; }
                        }
                    })).build();
            server.start();
            int port = ((InetSocketAddress) server.getListenerInfo().getFirst().getAddress()).getPort();
            base = URI.create("http://127.0.0.1:" + port + "/portal/a28/resource");
            client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
        }

        void installTrust(MsalExchangeConfig config, Class<?> handler) throws Exception {
            // Only remote key acquisition is replaced; verification uses the branch's actual verifier.
            for (Field field : JwtVerifier.class.getDeclaredFields()) {
                if (Modifier.isStatic(field.getModifiers()) && !Modifier.isFinal(field.getModifiers())) {
                    field.setAccessible(true);
                    Object previous = field.get(null);
                    restore.add(() -> field.set(null, previous));
                }
            }
            Field field = handler.getDeclaredField("internalJwtVerifier");
            field.setAccessible(true);
            Object previous = field.get(null);
            restore.add(() -> field.set(null, previous));
            field.set(null, new LocalLegacyVerifier());
        }

        HttpResponse<String> request(String token, String csrf, String suffix) throws Exception {
            URI uri = URI.create(base + suffix);
            var request = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(5));
            if (token != null) {
                watch.add(token);
                request.header("Cookie", "accessToken=" + token + "; csrf=" + CSRF + extraCookie);
            }
            if (csrf != null) request.header("X-CSRF-TOKEN", csrf);
            HttpResponse<String> response = client.send(request.GET().build(), HttpResponse.BodyHandlers.ofString());
            privateText(response.body());
            return response;
        }

        void privateText(String text) { for (String marker : watch) assertFalse(text.contains(marker), "Credential/canary leaked: " + marker); }
        void privateValue(Object value) {
            if (value instanceof byte[] bytes) privateText(new String(bytes, StandardCharsets.UTF_8));
            else if (value instanceof char[] chars) privateText(new String(chars));
            else if (value instanceof Object[] array) for (Object item : array) privateValue(item);
            else if (value instanceof Map<?, ?> map) map.forEach((key, item) -> { privateValue(key); privateValue(item); });
            else privateText(String.valueOf(value));
        }
        void privateThrowable(IThrowableProxy throwable) {
            if (throwable == null) return;
            privateText(String.valueOf(throwable.getMessage()));
            privateThrowable(throwable.getCause());
            if (throwable.getSuppressed() != null) for (var suppressed : throwable.getSuppressed()) privateThrowable(suppressed);
        }
        @Override public void close() {
            List<Executable> actions = new ArrayList<>();
            if (server != null) actions.add(server::stop);
            if (client != null) actions.add(client::close);
            actions.addAll(restore);
            actions.add(() -> {
                for (Throwable failure : escaped) privateThrowable(new ThrowableProxy(failure));
                for (ILoggingEvent event : logs.list) {
                    privateText(event.getFormattedMessage());
                    privateValue(event.getArgumentArray());
                    privateValue(event.getMDCPropertyMap());
                    privateThrowable(event.getThrowableProxy());
                }
            });
            actions.add(logs::stop);
            assertAll("Release fixture state and verify canary-free logs", actions);
        }
    }
}
