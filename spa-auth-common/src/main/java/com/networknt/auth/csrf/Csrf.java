package com.networknt.auth.csrf;

import io.undertow.server.HttpServerExchange;
import io.undertow.util.Headers;
import io.undertow.util.HttpString;
import io.undertow.util.Methods;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

/** Shared fail-closed CSRF transport policy. Never include credentials in exception messages. */
public final class Csrf {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final HttpString HEADER = new HttpString("X-CSRF-TOKEN");
    private static final HttpString PROTOCOL = new HttpString("Sec-WebSocket-Protocol");
    public static final int MAX_LENGTH = 512;

    private Csrf() { }

    public static String nonce() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static boolean equal(String left, String right) {
        return bounded(left) && bounded(right) && MessageDigest.isEqual(digest(left), digest(right));
    }

    public static byte[] digest(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static boolean bounded(String value) {
        return value != null && !value.isBlank() && value.length() <= MAX_LENGTH;
    }

    public static void rejectQuery(HttpServerExchange exchange) {
        if (exchange.getQueryParameters().containsKey("csrf")) throw invalid();
    }

    /** A comma-separated list or a native YAML list; empty means no cookie-authenticated WebSockets. */
    public static Set<String> origins(Object setting) {
        if (setting == null || "".equals(setting)) return Set.of();
        Collection<?> values;
        if (setting instanceof String text) values = Arrays.asList(text.split(",", -1));
        else if (setting instanceof Collection<?> collection) values = collection;
        else throw new IllegalArgumentException("websocketAllowedOrigins must be a list or CSV string");
        Set<String> result = new HashSet<>();
        for (Object value : values) {
            if (!(value instanceof String text)) throw new IllegalArgumentException("Invalid WebSocket origin configuration");
            text = text.trim();
            if (!origin(text)) throw new IllegalArgumentException("Invalid WebSocket origin configuration");
            result.add(text);
        }
        return Set.copyOf(result);
    }

    private static boolean origin(String text) {
        try {
            URI uri = URI.create(text);
            return ("https".equals(uri.getScheme()) || "http".equals(uri.getScheme()))
                    && uri.getHost() != null && uri.getRawUserInfo() == null && uri.getRawQuery() == null
                    && uri.getRawFragment() == null && uri.getRawPath().isEmpty()
                    && uri.getPort() >= -1 && uri.getPort() <= 65535;
        } catch (IllegalArgumentException e) { return false; }
    }

    /** Validate before forwarding any cookie-authenticated request, including refresh recovery. */
    public static String request(HttpServerExchange exchange, Set<String> allowedOrigins) {
        rejectQuery(exchange);
        String header = single(exchange, HEADER);
        String protocols = single(exchange, PROTOCOL);
        String key = single(exchange, new HttpString("Sec-WebSocket-Key"));
        String version = single(exchange, new HttpString("Sec-WebSocket-Version"));
        boolean websocket = key != null || version != null || protocols != null
                || "websocket".equalsIgnoreCase(exchange.getRequestHeaders().getFirst(Headers.UPGRADE));
        String protocolToken = null;
        List<String> applicationProtocols = new ArrayList<>();
        if (websocket) {
            // Key/version survive HTTP/2 proxying, unlike hop-by-hop Upgrade/Connection headers.
            // An HTTP/1.1 gateway behind such a proxy still receives a GET handshake.
            if (!Methods.GET.equals(exchange.getRequestMethod()) || !"13".equals(version) || key == null) throw invalid();
            try { if (Base64.getDecoder().decode(key).length != 16) throw invalid(); }
            catch (IllegalArgumentException e) { throw invalid(); }
            String upgrade = exchange.getRequestHeaders().getFirst(Headers.UPGRADE);
            if (upgrade != null && !"websocket".equalsIgnoreCase(upgrade)) throw invalid();
            String origin = single(exchange, Headers.ORIGIN);
            if (origin == null || !origin(origin) || !allowedOrigins.contains(origin)) throw invalid();
            if (protocols != null) {
                if (protocols.length() > 4096) throw invalid();
                for (String protocol : protocols.split(",", -1)) {
                    protocol = protocol.trim();
                    if (!protocol.matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+")) throw invalid();
                    if (protocol.startsWith("csrf.")) {
                        if (protocolToken != null) throw invalid();
                        protocolToken = protocol.substring(5);
                    } else applicationProtocols.add(protocol);
                }
            }
            // Browsers require a negotiated protocol when any protocols were offered.
            // A credential cannot double as the negotiated application protocol.
            if (protocolToken != null && applicationProtocols.isEmpty()) throw invalid();
        }
        if (header != null && protocolToken != null && !equal(header, protocolToken)) throw invalid();
        String value = header != null ? header : protocolToken;
        if (!bounded(value)) throw invalid();
        // Downstream handshake handlers must never select or echo the credential subprotocol.
        if (websocket && protocols != null) {
            if (applicationProtocols.isEmpty()) exchange.getRequestHeaders().remove(PROTOCOL);
            else exchange.getRequestHeaders().put(PROTOCOL, String.join(", ", applicationProtocols));
        }
        return value;
    }

    private static String single(HttpServerExchange exchange, HttpString name) {
        var values = exchange.getRequestHeaders().get(name);
        if (values == null) return null;
        if (values.size() != 1) throw invalid();
        return values.getFirst();
    }

    public static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Invalid CSRF transport or value");
    }
}
