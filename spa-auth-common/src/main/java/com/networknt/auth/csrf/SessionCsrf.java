package com.networknt.auth.csrf;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/** Immutable per-configuration signing key snapshot. No key material in diagnostics. */
public final class SessionCsrf {
    private final String activeId;
    private final Map<String, SecretKeySpec> keys;

    /** Keys are comma-separated id=unpadded-Base64URL-secret entries, loaded via secret configuration. */
    public SessionCsrf(String activeId, String setting) {
        try {
            if (activeId == null || !activeId.matches("[A-Za-z0-9_-]{1,32}") || setting == null || setting.length() > 8192)
                throw new IllegalArgumentException();
            Map<String, SecretKeySpec> parsed = new HashMap<>();
            for (String entry : setting.split(",", -1)) {
                String[] parts = entry.trim().split("=", -1);
                if (parts.length != 2 || !parts[0].matches("[A-Za-z0-9_-]{1,32}") || !parts[1].matches("[A-Za-z0-9_-]+"))
                    throw new IllegalArgumentException();
                byte[] bytes = Base64.getUrlDecoder().decode(parts[1]);
                if (bytes.length < 32 || parsed.putIfAbsent(parts[0], new SecretKeySpec(bytes, "HmacSHA256")) != null)
                    throw new IllegalArgumentException();
            }
            if (!parsed.containsKey(activeId)) throw new IllegalArgumentException();
            this.activeId = activeId;
            this.keys = Map.copyOf(parsed);
        } catch (IllegalArgumentException e) {
            // Do not attach the decoder's exception: it can contain secret input.
            throw new IllegalArgumentException("msal-auth requires a valid csrfSigningKeyId and csrfSigningKeys (at least 32 bytes per key)");
        }
    }

    public String issue(String accessToken) {
        String prefix = "v1." + activeId + "." + Csrf.nonce();
        return prefix + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(mac(keys.get(activeId), prefix, accessToken));
    }

    public boolean verify(String value, String accessToken) {
        if (value == null || value.length() > Csrf.MAX_LENGTH || accessToken == null || accessToken.isBlank()) return false;
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4 || !"v1".equals(parts[0]) || !parts[1].matches("[A-Za-z0-9_-]{1,32}")
                || !parts[2].matches("[A-Za-z0-9_-]{43}") || !parts[3].matches("[A-Za-z0-9_-]{43}")) return false;
        SecretKeySpec key = keys.get(parts[1]);
        if (key == null) return false;
        try {
            byte[] nonce = Base64.getUrlDecoder().decode(parts[2]);
            byte[] signature = Base64.getUrlDecoder().decode(parts[3]);
            // Reject noncanonical encodings, including unused Base64 bits.
            if (!Base64.getUrlEncoder().withoutPadding().encodeToString(nonce).equals(parts[2])
                    || !Base64.getUrlEncoder().withoutPadding().encodeToString(signature).equals(parts[3])) return false;
            return MessageDigest.isEqual(signature, mac(key, String.join(".", parts[0], parts[1], parts[2]), accessToken));
        } catch (IllegalArgumentException e) { return false; }
    }

    private static byte[] mac(SecretKeySpec key, String prefix, String token) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            mac.update("light-spa-msal-csrf\0".getBytes(StandardCharsets.US_ASCII));
            mac.update(prefix.getBytes(StandardCharsets.US_ASCII));
            mac.update((byte) 0);
            return mac.doFinal(Csrf.digest(token));
        } catch (GeneralSecurityException e) { throw new IllegalStateException("CSRF cryptography unavailable", e); }
    }
}
