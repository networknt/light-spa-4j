package com.networknt.auth;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.classic.spi.ThrowableProxy;
import ch.qos.logback.core.read.ListAppender;
import com.networknt.client.oauth.TokenResponse;
import io.undertow.Undertow;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.parallel.Isolated;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Field;
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
class StatelessSessionLoggingTest {
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

        void start() throws Exception {
            StatelessAuthHandler handler = new StatelessAuthHandler();
            StatelessAuthConfig config = StatelessAuthConfig.load();
            installTrust(config, handler.getClass());
            Logger root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
            Level oldRoot = root.getLevel();
            restore.add(() -> root.setLevel(oldRoot));
            root.setLevel(Level.WARN);
            for (String name : new String[]{StatelessAuthHandler.class.getName(), "com.networknt.handler.LightHttpHandler"}) {
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

        void installTrust(StatelessAuthConfig config, Class<?> handler) throws Exception {
            Field field = StatelessAuthConfig.class.getDeclaredField("tokenTrustVerifier");
            field.setAccessible(true);
            Object previous = field.get(config);
            restore.add(() -> field.set(config, previous));
            var constructor = com.networknt.auth.trust.JwtTrust.class.getDeclaredConstructor(
                    Map.class, com.networknt.auth.trust.JwtTrust.Kind.class, VerificationKeyResolver.class);
            constructor.setAccessible(true);
            VerificationKeyResolver resolver = (jws, context) -> keys.getPublic();
            field.set(config, constructor.newInstance(Map.of("issuer", ISSUER, "audience", AUDIENCE),
                    com.networknt.auth.trust.JwtTrust.Kind.INTERNAL_ACCESS, resolver));
        }

        HttpResponse<String> request(String token, String csrf, String suffix) throws Exception {
            URI uri = URI.create(base + suffix);
            var request = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(5));
            if (token != null) {
                watch.add(token);
                request.header("Cookie", "accessToken=" + token + "; csrf=" + CSRF);
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
