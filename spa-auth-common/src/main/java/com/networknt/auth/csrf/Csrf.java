package com.networknt.auth.csrf;

import com.networknt.httpstring.HttpStringConstants;
import com.networknt.utility.Constants;
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
import java.util.regex.Pattern;

/** Shared fail-closed CSRF transport policy. Never include credentials in exception messages. */
public final class Csrf {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final HttpString HEADER = HttpStringConstants.CSRF_TOKEN;
    private static final HttpString PROTOCOL = new HttpString("Sec-WebSocket-Protocol");
    private static final HttpString FETCH_SITE = new HttpString("Sec-Fetch-Site");
    private static final HttpString KEY = new HttpString("Sec-WebSocket-Key");
    private static final HttpString VERSION = new HttpString("Sec-WebSocket-Version");
    private static final Pattern SUBPROTOCOL = Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]+");
    private static final Pattern NONCE = Pattern.compile("[A-Za-z0-9_-]{43}");
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
        if (exchange.getQueryParameters().containsKey(Constants.CSRF)) throw invalid();
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
            String normalized = origin(text);
            if (normalized == null) throw new IllegalArgumentException("Invalid WebSocket origin configuration");
            result.add(normalized);
        }
        return Set.copyOf(result);
    }

    private static String origin(String text) {
        try {
            URI uri = URI.create(text);
            String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
            if (!("https".equals(scheme) || "http".equals(scheme)) || uri.getHost() == null
                    || uri.getRawUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null
                    || !uri.getRawPath().isEmpty() || uri.getPort() < -1 || uri.getPort() > 65535) return null;
            int port = uri.getPort();
            boolean defaultPort = port == -1 || (scheme.equals("https") && port == 443) || (scheme.equals("http") && port == 80);
            return scheme + "://" + uri.getHost().toLowerCase(Locale.ROOT) + (defaultPort ? "" : ":" + port);
        } catch (IllegalArgumentException e) { return null; }
    }

    public static boolean isNonce(String value) {
        if (value == null || !NONCE.matcher(value).matches()) return false;
        try { return Base64.getUrlEncoder().withoutPadding().encodeToString(Base64.getUrlDecoder().decode(value)).equals(value); }
        catch (IllegalArgumentException e) { return false; }
    }

    /** Browser provenance only: not a substitute for API authorization or CSRF on unsafe requests. */
    public static boolean trustedBrowser(HttpServerExchange exchange, Set<String> allowedOrigins) {
        try {
            String supplied = single(exchange, Headers.ORIGIN);
            if (supplied != null) {
                String normalized = origin(supplied);
                if (normalized == null) return false;
                // Browser-authenticated metadata describes the public request, including across TLS
                // termination/Host rewriting. An external site cannot set this forbidden header.
                if ("same-origin".equals(single(exchange, FETCH_SITE))) return true;
                // Host is the browser's target authority; forwarding headers are deliberately ignored.
                String target = origin(exchange.getRequestScheme() + "://" + exchange.getHostAndPort());
                return normalized.equals(target) || allowedOrigins.contains(normalized);
            }
            return "same-origin".equals(single(exchange, FETCH_SITE));
        } catch (IllegalArgumentException e) { return false; }
    }

    /** Restricted to non-authorizing rotation/cleanup, never downstream request execution. */
    public static boolean recoveryAllowed(HttpServerExchange exchange, Set<String> allowedOrigins) {
        try {
            rejectQuery(exchange);
            return trustedBrowser(exchange, allowedOrigins) && !isWebsocket(exchange);
        } catch (IllegalArgumentException e) { return false; }
    }

    private static boolean isWebsocket(HttpServerExchange exchange) {
        return exchange.getRequestHeaders().contains(KEY) || exchange.getRequestHeaders().contains(VERSION)
                || exchange.getRequestHeaders().contains(PROTOCOL)
                || "websocket".equalsIgnoreCase(exchange.getRequestHeaders().getFirst(Headers.UPGRADE));
    }

    /** Validate before forwarding any cookie-authenticated request, including refresh recovery. */
    public static String request(HttpServerExchange exchange, Set<String> allowedOrigins) {
        return request(exchange, allowedOrigins, null);
    }

    /** Native read-only browser requests can use a bound cookie plus trusted browser provenance. */
    public static String request(HttpServerExchange exchange, Set<String> allowedOrigins, String boundCookie) {
        return request(exchange, allowedOrigins, allowedOrigins, boundCookie);
    }

    public static String request(HttpServerExchange exchange, Set<String> allowedOrigins, Set<String> browserOrigins, String boundCookie) {
        rejectQuery(exchange);
        String header = single(exchange, HEADER);
        if (header != null && header.isBlank()) header = null;
        String protocols = single(exchange, PROTOCOL);
        String key = single(exchange, KEY);
        String version = single(exchange, VERSION);
        boolean websocket = isWebsocket(exchange);
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
            String normalized = origin == null ? null : origin(origin);
            if (normalized == null || !allowedOrigins.contains(normalized)) throw invalid();
            if (protocols != null) {
                if (protocols.length() > 4096) throw invalid();
                for (String protocol : protocols.split(",", -1)) {
                    protocol = protocol.trim();
                    if (!SUBPROTOCOL.matcher(protocol).matches()) throw invalid();
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
        if (value == null && !websocket && (Methods.GET.equals(exchange.getRequestMethod()) || Methods.HEAD.equals(exchange.getRequestMethod()))
                && trustedBrowser(exchange, browserOrigins)) value = boundCookie;
        if (!bounded(value)) throw value == null || value.isBlank() ? new Failure("ERR10036") : invalid();
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
        return new Failure("ERR10039");
    }

    public static String code(IllegalArgumentException error) {
        return error instanceof Failure failure ? failure.code : "ERR10039";
    }

    private static final class Failure extends IllegalArgumentException {
        private final String code;
        private Failure(String code) { super("Invalid CSRF transport or value"); this.code = code; }
    }
}
