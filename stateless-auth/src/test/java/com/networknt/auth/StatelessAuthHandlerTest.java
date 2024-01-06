/*
 * Copyright (c) 2016 Network New Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.networknt.auth;

import com.networknt.client.Http2Client;
import com.networknt.config.Config;
import com.networknt.exception.ClientException;
import com.networknt.security.KeyUtil;
import io.undertow.Handlers;
import io.undertow.Undertow;
import io.undertow.UndertowOptions;
import io.undertow.client.ClientConnection;
import io.undertow.client.ClientRequest;
import io.undertow.client.ClientResponse;
import io.undertow.server.HttpHandler;
import io.undertow.server.RoutingHandler;
import io.undertow.util.Headers;
import io.undertow.util.HttpString;
import io.undertow.util.Methods;
import io.undertow.util.StatusCodes;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xnio.IoUtils;
import org.xnio.OptionMap;
import org.xnio.XnioWorker;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;


/**
 * Both API server and OAuth token server must be listening to HTTPS and HTTP/2. If you are
 * using another OAuth 2.0 provider that doesn't support HTTP/2, please update statelessAuth.yml
 * to make enableHttp2 false.
 *
 * @author Steve Hu
 *
 */
public class StatelessAuthHandlerTest {
    static final Logger logger = LoggerFactory.getLogger(StatelessAuthHandlerTest.class);

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

    @BeforeAll
    public static void setUp() throws IOException {
        sslContext = createSSLContext(loadKeyStore(SERVER_KEY_STORE), loadKeyStore(SERVER_TRUST_STORE), false);

        if(authServer == null) {
            logger.info("starting server");
            HttpHandler handler = getTestHandler();
            StatelessAuthHandler statelessAuthHandler = new StatelessAuthHandler();
            statelessAuthHandler.setNext(handler);
            handler = statelessAuthHandler;
            authServer = Undertow.builder()
                    .addHttpsListener(7080, "localhost", sslContext)
                    .setServerOption(UndertowOptions.ENABLE_HTTP2, true)
                    .setHandler(handler)
                    .build();
            authServer.start();
        }

        if(tokenServer == null) {
            logger.info("starting oauth token server");
            tokenServer = Undertow.builder()
                    .addHttpsListener(5882, "localhost", sslContext)
                    .setServerOption(UndertowOptions.ENABLE_HTTP2, true)
                    .setHandler(Handlers.header(Handlers.path()
                                    .addPrefixPath("/oauth2/N2CMw0HGQXeLvC1wBfln2A/keys", (exchange) -> {
                                        exchange.getResponseHeaders().add(new HttpString("Content-Type"), "application/json");
                                        exchange.getResponseSender().send("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"Tj_l_tIBTginOtQbL0Pv5w\",\"n\":\"0YRbWAb1FGDpPUUcrIpJC6BwlswlKMS-z2wMAobdo0BNxNa7hG_gIHVPkXu14Jfo1JhUhS4wES3DdY3a6olqPcRN1TCCUVHd-1TLd1BBS-yq9tdJ6HCewhe5fXonaRRKwutvoH7i_eR4m3fQ1GoVzVAA3IngpTr4ptnM3Ef3fj-5wZYmitzrRUyQtfARTl3qGaXP_g8pHFAP0zrNVvOnV-jcNMKm8YZNcgcs1SuLSFtUDXpf7Nr2_xOhiNM-biES6Dza1sMLrlxULFuctudO9lykB7yFh3LHMxtIZyIUHuy0RbjuOGC5PmDowLttZpPI_j4ynJHAaAWr8Ddz764WdQ\",\"e\":\"AQAB\"}]}");
                                    })
                                    .addPrefixPath("/oauth2/token", (exchange) -> {
                                        // create a token that expired in 5 seconds.
                                        Map<String, Object> map = new HashMap<>();
                                        String token = getJwt(600, csrfToken);
                                        map.put("access_token", token);
                                        map.put("token_type", "Bearer");
                                        map.put("expires_in", 5);
                                        exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "application/json");
                                        exchange.getResponseSender().send(ByteBuffer.wrap(
                                                Config.getInstance().getMapper().writeValueAsBytes(map)));
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

    static RoutingHandler getTestHandler() {
        return Handlers.routing()
                .add(Methods.GET, "/authorization", exchange -> {
                    exchange.getResponseSender().send("OK");
                });
    }

    @Test
    public void testAuthWithCode() throws Exception {
        final Http2Client client = Http2Client.getInstance();
        final CountDownLatch latch = new CountDownLatch(1);
        final ClientConnection connection;
        try {
            connection = client.connect(new URI("https://localhost:7080"), Http2Client.WORKER, Http2Client.SSL, Http2Client.BUFFER_POOL, OptionMap.create(UndertowOptions.ENABLE_HTTP2, true)).get();
        } catch (Exception e) {
            throw new ClientException(e);
        }
        final AtomicReference<ClientResponse> reference = new AtomicReference<>();
        try {
            ClientRequest request = new ClientRequest().setPath("/authorization?code=abc").setMethod(Methods.GET);
            connection.sendRequest(request, client.createClientCallback(reference, latch));
            latch.await();
        } catch (Exception e) {
            logger.error("Exception: ", e);
            throw new ClientException(e);
        } finally {
            IoUtils.safeClose(connection);
        }
        int statusCode = reference.get().getResponseCode();
        Assertions.assertEquals(StatusCodes.OK, statusCode);
    }

    @Test
    public void testAuthGetWithoutCode() throws Exception {
        final Http2Client client = Http2Client.getInstance();
        final CountDownLatch latch = new CountDownLatch(1);
        final ClientConnection connection;
        try {
            connection = client.connect(new URI("https://localhost:7080"), Http2Client.WORKER, Http2Client.SSL, Http2Client.BUFFER_POOL, OptionMap.create(UndertowOptions.ENABLE_HTTP2, true)).get();
        } catch (Exception e) {
            throw new ClientException(e);
        }
        final AtomicReference<ClientResponse> reference = new AtomicReference<>();
        try {
            ClientRequest request = new ClientRequest().setPath("/authorization").setMethod(Methods.GET);
            connection.sendRequest(request, client.createClientCallback(reference, latch));
            latch.await();
        } catch (Exception e) {
            logger.error("Exception: ", e);
            throw new ClientException(e);
        } finally {
            IoUtils.safeClose(connection);
        }
        int statusCode = reference.get().getResponseCode();
        String body = reference.get().getAttachment(Http2Client.RESPONSE_BODY);
        logger.debug("statusCode = " + statusCode);
        logger.debug("body = " + body);
        Assertions.assertEquals(400, statusCode);
        Assertions.assertTrue(body.contains("ERR10035"));

    }

    private static String getJwt(int expiredInSeconds, String csrfToken) throws Exception {
        JwtClaims claims = getTestClaims(csrfToken);
        claims.setExpirationTime(NumericDate.fromMilliseconds(System.currentTimeMillis() + expiredInSeconds * 1000));
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
        if(csrfToken != null) claims.setClaim("csrf", csrfToken);
        List<String> scope = Arrays.asList("api.r", "api.w");
        claims.setStringListClaim("scope", scope); // multi-valued claims work too and will end up as a JSON array
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
    public void testArrayConverer() {
        String[] scopes = {"abc", "efg"};
        String s = Arrays.toString(scopes);
        System.out.println(s);
    }

}
