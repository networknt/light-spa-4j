package com.networknt.auth;

import io.undertow.server.HttpServerExchange;
import io.undertow.util.HeaderValues;
import java.net.InetAddress;
import java.util.*;

/** Forwarded addresses are authoritative only across explicitly trusted proxy hops. */
final class GoogleChallengeSource {
    private GoogleChallengeSource() { }
    static String address(HttpServerExchange exchange, Map<String, Object> config) {
        HeaderValues values = exchange.getRequestHeaders().get("X-Forwarded-For");
        return address(exchange.getSourceAddress().getAddress().getHostAddress(),
                values == null ? null : String.join(",", values), config.get("trustedProxyAddresses"));
    }
    static String address(String peer, String forwarded, Object configured) {
        Set<String> trusted = new HashSet<>();
        Collection<?> entries;
        if (configured == null || "".equals(configured)) entries = List.of();
        else if (configured instanceof String text) entries = Arrays.asList(text.split(",", -1));
        else if (configured instanceof Collection<?> list) entries = list;
        else throw new IllegalStateException("Invalid trusted proxy configuration");
        for (Object entry : entries) {
            try { trusted.add(literal((String) entry)); }
            catch (Exception failure) { throw new IllegalStateException("Invalid trusted proxy configuration"); }
        }
        String current = literal(peer);
        if (!trusted.contains(current)) return current;
        // Never charge a proxy's shared budget when its required forwarding metadata is absent/invalid.
        if (forwarded == null || forwarded.isBlank() || forwarded.length() > 2048)
            throw new IllegalArgumentException("Invalid proxy address chain");
        String[] hops = forwarded.split(",", -1);
        if (hops.length > 32) throw new IllegalArgumentException("Proxy chain too long");
        for (int i = hops.length - 1; i >= 0 && trusted.contains(current); i--) current = literal(hops[i]);
        if (trusted.contains(current)) throw new IllegalArgumentException("No client address in proxy chain");
        return current;
    }
    private static String literal(String input) {
        if (input == null) throw new IllegalArgumentException("Missing IP address");
        String value = input.trim();
        // Restrict getByName to numeric literals: no DNS, ports, zones or hostnames.
        if (value.contains(":")) {
            if (!value.matches("[0-9a-fA-F:.]+"))
                throw new IllegalArgumentException("Invalid IPv6 address");
        } else {
            String[] parts = value.split("\\.", -1);
            if (parts.length != 4) throw new IllegalArgumentException("Invalid IPv4 address");
            for (String part : parts) {
                if (!part.matches("0|[1-9][0-9]{0,2}") || Integer.parseInt(part) > 255)
                    throw new IllegalArgumentException("Invalid IPv4 address");
            }
        }
        try { return InetAddress.getByName(value).getHostAddress(); }
        catch (Exception failure) { throw new IllegalArgumentException("Invalid IP address"); }
    }
}
