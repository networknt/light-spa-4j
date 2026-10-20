package com.networknt.auth;

import com.networknt.config.Config;
import com.networknt.security.JwtVerifier;
import com.networknt.security.SecurityConfig;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import io.undertow.Undertow;
import org.jose4j.http.Get;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import com.networknt.config.JsonMapper;

import static org.junit.jupiter.api.Assertions.*;

/** Production jose4j resolver, HTTPS fetch and endpoint-owned caches, with colliding provider kids. */
class MsalSigningIsolationTest {
    @Test
    void realResolversAndGlobalLegacyVerifierCannotCrossSigningTrustInEitherOrder() throws Exception {
        X509Certificate cert;
        try (var input = getClass().getResourceAsStream("/config/msal-isolation-cert.pem")) {
            cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
        }
        String pem;
        try (var input = getClass().getResourceAsStream("/config/msal-isolation-key.pem")) {
            pem = new String(input.readAllBytes(), StandardCharsets.US_ASCII)
                    .replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
        }
        PrivateKey foreignPrivate = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem)));
        RsaJsonWebKey foreign = new RsaJsonWebKey((RSAPublicKey) cert.getPublicKey());
        foreign.setPrivateKey(foreignPrivate);
        foreign.setKeyId("collision");
        RsaJsonWebKey microsoft = RsaJwkGenerator.generateJwk(2048);
        microsoft.setKeyId("collision");
        AtomicReference<RsaJsonWebKey> microsoftKey = new AtomicReference<>(microsoft);

        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        char[] password = "local-test-only".toCharArray();
        store.setKeyEntry("tls", foreignPrivate, password, new java.security.cert.Certificate[]{cert});
        KeyManagerFactory km = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        km.init(store, password);
        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(km.getKeyManagers(), null, null);
        HttpsServer keys = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        keys.setHttpsConfigurator(new HttpsConfigurator(ssl));
        keys.createContext("/msal", exchange -> {
            byte[] json = new JsonWebKeySet(microsoftKey.get()).toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Cache-Control", "max-age=3600");
            exchange.sendResponseHeaders(200, json.length);
            exchange.getResponseBody().write(json);
            exchange.close();
        });
        keys.createContext("/other", exchange -> {
            byte[] json = new JsonWebKeySet(foreign).toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY).getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, json.length);
            exchange.getResponseBody().write(json);
            exchange.close();
        });
        keys.start();
        try {
            String uri = "https://localhost:" + keys.getAddress().getPort();
            // Also exercise the unmodified production factory in a fresh JVM. Only its
            // JVM trust store and administrator-configured JWKS URI point at local TLS.
            Path directory = Files.createTempDirectory("msal-production-isolation-");
            KeyStore trust = KeyStore.getInstance("PKCS12");
            trust.load(null, null);
            trust.setCertificateEntry("local", cert);
            Path trustFile = directory.resolve("trust.p12");
            try (var output = Files.newOutputStream(trustFile)) { trust.store(output, password); }
            var config = new java.util.HashMap<String, Object>(MsalAuthConfig.load().getMappedConfig());
            config.put("jwksUri", uri + "/msal");
            Files.writeString(directory.resolve("msal-auth.yml"), JsonMapper.toJson(config));
            Files.writeString(directory.resolve("security-msal.yml"), "enableJwtCache: false\njwt:\n  clockSkewInSeconds: 60\n");
            Files.writeString(directory.resolve("own-token"), sign(microsoft));
            Path log = directory.resolve("probe.log");
            Process process = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                    "-Dlight-4j-config-dir=" + directory, "-Djavax.net.ssl.trustStore=" + trustFile,
                    "-Djavax.net.ssl.trustStorePassword=local-test-only", "-cp", System.getProperty("java.class.path"),
                    ProductionProbe.class.getName(), directory.toString()).redirectErrorStream(true).redirectOutput(log.toFile()).start();
            boolean completed = process.waitFor(30, TimeUnit.SECONDS);
            if (!completed) process.destroyForcibly();
            assertTrue(completed, "production probe timeout");
            assertEquals(0, process.exitValue(), Files.readString(log));
            for (boolean legacyFirst : new boolean[]{false, true}) {
                MsalAuthHandler.installVerifierForTest(null);
                JwtVerifier legacy = legacyFirst ? new JwtVerifier(SecurityConfig.load("security-isolation-other")) : null;
                HttpsJwks source = trustedSource(uri + "/msal", cert);
                MsalJwtVerifier msal = new MsalJwtVerifier(source, 60);
                MsalJwtVerifier other = new MsalJwtVerifier(trustedSource(uri + "/other", cert), 60);
                if (!legacyFirst) legacy = new JwtVerifier(SecurityConfig.load("security-isolation-other"));
                String ownToken = sign(microsoft);
                String foreignToken = sign(foreign);
                assertNotNull(legacy.verifyJwt(foreignToken, false, true));
                assertNotNull(other.verify(foreignToken));
                assertThrows(org.jose4j.jwt.consumer.InvalidJwtException.class, () -> other.verify(ownToken));
                assertNotNull(msal.verify(ownToken));
                assertThrows(org.jose4j.jwt.consumer.InvalidJwtException.class, () -> msal.verify(foreignToken));
                // The exact endpoint resolver/cache used above also drives the HTTP handler.
                MsalAuthHandler.installVerifierForTest(msal);
                MsalAuthHandler handler = new MsalAuthHandler();
                handler.setNext(exchange -> exchange.getResponseSender().send("downstream"));
                Undertow gateway = Undertow.builder().addHttpListener(0, "127.0.0.1").setHandler(handler).build();
                gateway.start();
                try {
                    int port = ((InetSocketAddress) gateway.getListenerInfo().getFirst().getAddress()).getPort();
                    HttpClient client = HttpClient.newHttpClient();
                    URI login = URI.create("http://127.0.0.1:" + port + "/auth/ms/login");
                    for (int repeat = 0; repeat < 2; repeat++) {
                        var accepted = client.send(request(login, ownToken), HttpResponse.BodyHandlers.ofString());
                        assertEquals(200, accepted.statusCode());
                        assertEquals(2, accepted.headers().allValues("Set-Cookie").size());
                        var rejected = client.send(request(login, foreignToken), HttpResponse.BodyHandlers.ofString());
                        assertEquals(401, rejected.statusCode());
                        assertTrue(rejected.headers().allValues("Set-Cookie").isEmpty());
                    }
                } finally { gateway.stop(); }
            }
            // New kid rotation fetches the configured endpoint only.
            HttpsJwks source = trustedSource(uri + "/msal", cert);
            source.setRefreshReprieveThreshold(0);
            MsalJwtVerifier rotating = new MsalJwtVerifier(source, 60);
            assertNotNull(rotating.verify(sign(microsoft)));
            RsaJsonWebKey next = RsaJwkGenerator.generateJwk(2048);
            next.setKeyId("rotated");
            microsoftKey.set(next);
            assertNotNull(rotating.verify(sign(next)));
            assertThrows(org.jose4j.jwt.consumer.InvalidJwtException.class, () -> rotating.verify(sign(foreign)));
        } finally {
            keys.stop(0);
            MsalAuthHandler.installVerifierForTest(null);
        }
    }

    public static class ProductionProbe {
        public static void main(String[] args) throws Exception {
            Path directory = Path.of(args[0]);
            String pem;
            try (var input = ProductionProbe.class.getResourceAsStream("/config/msal-isolation-key.pem")) {
                pem = new String(input.readAllBytes(), StandardCharsets.US_ASCII)
                        .replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
            }
            PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem)));
            JsonWebSignature jws = new JsonWebSignature();
            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
            jws.setKeyIdHeaderValue("collision");
            jws.setHeader("jku", MsalAuthConfig.load().getJwksUri().replace("/msal", "/other"));
            jws.setPayload(MsalTokenValidationTest.validClaims().toJson());
            jws.setKey(key);
            String foreign = jws.getCompactSerialization();
            String own = Files.readString(directory.resolve("own-token"));
            for (boolean first : new boolean[]{false, true}) {
                MsalAuthHandler.installVerifierForTest(null);
                JwtVerifier legacy = first ? new JwtVerifier(SecurityConfig.load("security-isolation-other")) : null;
                MsalAuthHandler handler = new MsalAuthHandler(); // no verifier/resolver injection
                if (!first) legacy = new JwtVerifier(SecurityConfig.load("security-isolation-other"));
                assertNotNull(legacy.verifyJwt(foreign, false, true));
                handler.setNext(exchange -> exchange.getResponseSender().send("downstream"));
                Undertow gateway = Undertow.builder().addHttpListener(0, "127.0.0.1").setHandler(handler).build();
                gateway.start();
                try {
                    int port = ((InetSocketAddress) gateway.getListenerInfo().getFirst().getAddress()).getPort();
                    URI uri = URI.create("http://127.0.0.1:" + port + "/auth/ms/login");
                    var client = HttpClient.newHttpClient();
                    var accepted = client.send(request(uri, own), HttpResponse.BodyHandlers.ofString());
                    assertEquals(200, accepted.statusCode(), accepted.body());
                    assertEquals(2, accepted.headers().allValues("Set-Cookie").size());
                    var rejected = client.send(request(uri, foreign), HttpResponse.BodyHandlers.ofString());
                    assertEquals(401, rejected.statusCode(), rejected.body());
                    assertTrue(rejected.headers().allValues("Set-Cookie").isEmpty());
                    assertNotNull(legacy.verifyJwt(foreign, false, true));
                } finally { gateway.stop(); }
            }
            // A changed administrator-configured endpoint must get a new key cache.
            var changed = new java.util.HashMap<String, Object>(MsalAuthConfig.load().getMappedConfig());
            changed.put("jwksUri", changed.get("jwksUri").toString().replace("/msal", "/other"));
            Files.writeString(directory.resolve("msal-auth.yml"), JsonMapper.toJson(changed));
            Config.getInstance().clearConfigCache("msal-auth");
            MsalAuthHandler reloaded = new MsalAuthHandler();
            reloaded.setNext(exchange -> exchange.getResponseSender().send("downstream"));
            Undertow gateway = Undertow.builder().addHttpListener(0, "127.0.0.1").setHandler(reloaded).build();
            gateway.start();
            try {
                int port = ((InetSocketAddress) gateway.getListenerInfo().getFirst().getAddress()).getPort();
                URI uri = URI.create("http://127.0.0.1:" + port + "/auth/ms/login");
                var client = HttpClient.newHttpClient();
                assertEquals(401, client.send(request(uri, own), HttpResponse.BodyHandlers.ofString()).statusCode());
                assertEquals(200, client.send(request(uri, foreign), HttpResponse.BodyHandlers.ofString()).statusCode());
            } finally { gateway.stop(); }
        }
    }

    private static HttpsJwks trustedSource(String uri, X509Certificate cert) {
        Get get = new Get();
        get.setTrustedCertificates(cert);
        get.setRetries(0);
        HttpsJwks source = new HttpsJwks(uri);
        source.setSimpleHttpGet(get); // Only TLS trust is local-test-specific; resolver/cache are production classes.
        return source;
    }

    private static String sign(RsaJsonWebKey key) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKeyIdHeaderValue(key.getKeyId());
        jws.setKey(key.getPrivateKey());
        jws.setPayload(MsalTokenValidationTest.validClaims().toJson());
        return jws.getCompactSerialization();
    }

    private static HttpRequest request(URI uri, String token) {
        return HttpRequest.newBuilder(uri).header("Authorization", "Bearer " + token)
                .POST(HttpRequest.BodyPublishers.noBody()).build();
    }
}
