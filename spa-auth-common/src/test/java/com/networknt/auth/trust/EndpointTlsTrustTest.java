package com.networknt.auth.trust;

import com.sun.net.httpserver.HttpsServer;
import com.sun.net.httpserver.HttpsConfigurator;
import org.jose4j.jwk.*;
import org.jose4j.jws.*;
import org.jose4j.jwt.*;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import javax.net.ssl.*;
import java.net.InetSocketAddress;
import java.nio.file.*;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class EndpointTlsTrustTest {
    @TempDir Path directory;
    @Test void additionalPrivateCaIsEndpointLocalAndPreservesPublicRoots() throws Exception {
        String previousStore = System.getProperty("javax.net.ssl.trustStore");
        SSLSocketFactory previousFactory = HttpsURLConnection.getDefaultSSLSocketFactory();
        TrustManagerFactory defaults = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        defaults.init((KeyStore) null);
        Set<String> publicRoots = new HashSet<>();
        for (var manager : defaults.getTrustManagers()) if (manager instanceof X509TrustManager trust)
            for (var root : trust.getAcceptedIssuers()) publicRoots.add(Base64.getEncoder().encodeToString(root.getEncoded()));
        assertFalse(publicRoots.isEmpty());
        KeyStore fixture = KeyStore.getInstance("JKS");
        try (var input = getClass().getResourceAsStream("/trust-test.keystore")) { fixture.load(input, "password".toCharArray()); }
        String alias = Collections.list(fixture.aliases()).stream().filter(a -> {
            try { return fixture.isKeyEntry(a); } catch (Exception e) { throw new RuntimeException(e); }
        }).findFirst().orElseThrow();
        X509Certificate certificate = (X509Certificate) fixture.getCertificate(alias);
        Path ca = directory.resolve("local-test-ca.pem");
        Files.writeString(ca, "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, new byte[]{10}).encodeToString(certificate.getEncoded()) + "\n-----END CERTIFICATE-----\n");
        KeyManagerFactory km = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()); km.init(fixture, "password".toCharArray());
        SSLContext ssl = SSLContext.getInstance("TLS"); ssl.init(km.getKeyManagers(), null, null);
        RsaJsonWebKey key = RsaJwkGenerator.generateJwk(2048); key.setKeyId("tls-test");
        HttpsServer server = HttpsServer.create(new InetSocketAddress("localhost", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(ssl));
        server.createContext("/keys", exchange -> {
            byte[] body = new JsonWebKeySet(key).toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY).getBytes(java.nio.charset.StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length); exchange.getResponseBody().write(body); exchange.close();
        });
        server.start();
        try {
            String uri = "https://localhost:" + server.getAddress().getPort() + "/keys";
            JwtClaims claims = new JwtClaims(); claims.setIssuer("owned"); claims.setAudience("gateway"); claims.setExpirationTimeMinutesInTheFuture(5);
            JsonWebSignature jws = new JsonWebSignature(); jws.setKey(key.getPrivateKey()); jws.setKeyIdHeaderValue(key.getKeyId());
            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256); jws.setPayload(claims.toJson()); String token = jws.getCompactSerialization();
            Map<String, Object> plain = Map.of("issuer", "owned", "audience", "gateway", "jwksUri", uri);
            JwtTrust.Factory policies = new JwtTrust.Factory();
            Map<String, Object> local = new HashMap<>(plain); local.put("additionalCaFiles", List.of(ca.toString()));
            JwtTrust privateCa = policies.load(local, JwtTrust.Kind.INTERNAL_ACCESS), publicOnly = policies.load(plain, JwtTrust.Kind.INTERNAL_ACCESS);
            assertNotSame(privateCa.signingSource(), publicOnly.signingSource());
            assertNotNull(privateCa.verify(token, false));
            assertTrue(JwtTrust.unavailable(assertThrows(InvalidJwtException.class, () -> publicOnly.verify(token, false))));
            assertEquals(previousStore, System.getProperty("javax.net.ssl.trustStore"));
            assertSame(previousFactory, HttpsURLConnection.getDefaultSSLSocketFactory());
            TrustManagerFactory after = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); after.init((KeyStore) null);
            Set<String> remaining = new HashSet<>();
            for (var manager : after.getTrustManagers()) if (manager instanceof X509TrustManager trust)
                for (var root : trust.getAcceptedIssuers()) remaining.add(Base64.getEncoder().encodeToString(root.getEncoded()));
            assertEquals(publicRoots, remaining);
        } finally { server.stop(0); }
    }
}
