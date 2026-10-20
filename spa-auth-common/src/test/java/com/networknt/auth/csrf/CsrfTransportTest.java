package com.networknt.auth.csrf;

import io.undertow.Undertow;
import org.junit.jupiter.api.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class CsrfTransportTest {
    private static Undertow server;
    private static int port;
    @BeforeAll static void start() {
        var handshake = new io.undertow.websockets.WebSocketProtocolHandshakeHandler(
                List.of(new io.undertow.websockets.core.protocol.version13.Hybi13Handshake(Set.of("chat"), false)),
                (io.undertow.websockets.WebSocketConnectionCallback) (exchange, channel) -> channel.resumeReceives());
        server = Undertow.builder().setIoThreads(1).setWorkerThreads(2).addHttpListener(0, "127.0.0.1").setHandler(exchange -> {
            try {
                Csrf.request(exchange, exchange.getRequestPath().equals("/disabled-socket") ? Set.of() : Set.of("https://portal.test"));
                if (exchange.getRequestPath().equals("/real-socket")) {
                    handshake.handleRequest(exchange);
                    return;
                }
                String protocols = exchange.getRequestHeaders().getFirst("Sec-WebSocket-Protocol");
                exchange.getResponseSender().send(protocols == null ? "downstream" : protocols);
            } catch (IllegalArgumentException e) {
                exchange.setStatusCode(401);
                exchange.getResponseSender().send("rejected");
            }
        }).build();
        server.start();
        port = ((InetSocketAddress) server.getListenerInfo().getFirst().getAddress()).getPort();
    }
    @AfterAll static void stop() { server.stop(); }

    private static String send(String path, String headers) throws Exception {
        try (Socket socket = new Socket("127.0.0.1", port)) {
            socket.setSoTimeout(5000);
            String request = "GET " + path + " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n" + headers + "\r\n";
            socket.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
            return new String(socket.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        }
    }
    private static String websocket(String origin, String protocol) {
        return "Upgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
                + (origin == null ? "" : "Origin: " + origin + "\r\n") + "Sec-WebSocket-Protocol: " + protocol + "\r\n";
    }
    private static void rejected(String response) { assertTrue(response.startsWith("HTTP/1.1 401"), response); assertFalse(response.contains("downstream")); }

    @Test void headersWorkButQueryNeverReachesDownstream() throws Exception {
        assertTrue(send("/api", "X-CSRF-TOKEN: valid\r\n").endsWith("downstream"));
        rejected(send("/api?csrf=valid", ""));
        rejected(send("/api?csrf=valid", "X-CSRF-TOKEN: valid\r\n"));
        rejected(send("/api?%63srf=valid", "X-CSRF-TOKEN: valid\r\n"));
        rejected(send("/api", ""));
        rejected(send("/api", "X-CSRF-TOKEN: " + "x".repeat(513) + "\r\n"));
    }

    @Test void trustedWebsocketStripsCredentialAndPreservesApplicationProtocol() throws Exception {
        String response = send("/socket", websocket("https://portal.test", "chat, csrf.valid"));
        assertTrue(response.startsWith("HTTP/1.1 200"), response);
        assertTrue(response.endsWith("chat"), response);
        assertFalse(response.contains("csrf.valid"));
        rejected(send("/socket", websocket("https://portal.test", "csrf.valid")));
    }

    @Test void untrustedMissingNullAndMalformedOriginsFailEvenWithHeader() throws Exception {
        for (String origin : Arrays.asList(null, "null", "https://evil.test", "https://portal.test.evil", "https://portal.test/"))
            rejected(send("/socket", websocket(origin, "chat, csrf.valid") + "X-CSRF-TOKEN: valid\r\n"));
        rejected(send("/disabled-socket", websocket("https://portal.test", "chat, csrf.valid")));
    }

    @Test void invalidUpgradesAndAmbiguousTransportsFail() throws Exception {
        rejected(send("/socket", "Sec-WebSocket-Protocol: csrf.valid\r\n"));
        rejected(send("/socket", websocket("https://portal.test", "chat, csrf.valid, csrf.valid")));
        rejected(send("/socket", websocket("https://portal.test", "chat, csrf.valid") + "X-CSRF-TOKEN: different\r\n"));
        rejected(send("/socket", websocket("https://portal.test", "chat, csrf.valid").replace("Version: 13", "Version: 12")));
        rejected(send("/socket", websocket("https://portal.test", "chat, csrf.valid").replace("dGhlIHNhbXBsZSBub25jZQ==", "invalid")));
        rejected(send("/api", "X-CSRF-TOKEN: one\r\nX-CSRF-TOKEN: two\r\n"));
    }

    @Test void originConfigurationIsExplicitAndValidated() {
        assertEquals(Set.of(), Csrf.origins(null));
        assertEquals(Set.of("https://portal.test"), Csrf.origins("https://portal.test"));
        assertEquals(Set.of("https://portal.test"), Csrf.origins(List.of("https://portal.test")));
        for (String setting : List.of("*", "null", "https://user@portal.test", "https://portal.test/", "https://portal.test?x=1", "https://portal.test:99999"))
            assertThrows(IllegalArgumentException.class, () -> Csrf.origins(setting));
    }

    @Test void actualUpgradeNegotiatesApplicationProtocolWithoutCredential() throws Exception {
        try (Socket socket = new Socket("127.0.0.1", port)) {
            socket.setSoTimeout(5000);
            String request = "GET /real-socket HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\n"
                    + websocket("https://portal.test", "chat, csrf.valid") + "\r\n";
            socket.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
            var reader = new java.io.BufferedReader(new java.io.InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
            String status = reader.readLine();
            assertTrue(status.startsWith("HTTP/1.1 101"), status);
            Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            for (String line; (line = reader.readLine()) != null && !line.isEmpty();) {
                int colon = line.indexOf(':');
                headers.put(line.substring(0, colon), line.substring(colon + 1).trim());
            }
            assertEquals("chat", headers.get("Sec-WebSocket-Protocol"));
            assertFalse(headers.toString().contains("csrf.valid"));
        }
    }
}
