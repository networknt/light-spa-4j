package com.networknt.auth.csrf;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

/** Immutable per-configuration signing key snapshot. No key material in diagnostics. */
public final class SessionCsrf {
    private final String activeId;
    private final Map<String, SigningKey> keys;
    private static final Pattern ID = Pattern.compile("[A-Za-z0-9_-]{1,32}");
    private static final Pattern BASE64 = Pattern.compile("[A-Za-z0-9_-]+");
    private static final Pattern ENCODED_32 = Pattern.compile("[A-Za-z0-9_-]{43}");

    /** Keys are comma-separated id=unpadded-Base64URL-secret entries, loaded via secret configuration. */
    public SessionCsrf(String activeId, String setting) {
        try {
            if (activeId == null || !ID.matcher(activeId).matches() || setting == null || setting.length() > 8192)
                throw new IllegalArgumentException();
            Map<String, SigningKey> parsed = new HashMap<>();
            for (String entry : setting.split(",", -1)) {
                String[] parts = entry.trim().split("=", -1);
                if (parts.length != 2 || !ID.matcher(parts[0]).matches() || !BASE64.matcher(parts[1]).matches())
                    throw new IllegalArgumentException();
                byte[] bytes = Base64.getUrlDecoder().decode(parts[1]);
                if (bytes.length < 32 || parsed.putIfAbsent(parts[0], new SigningKey(bytes)) != null)
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
        if (parts.length != 4 || !"v1".equals(parts[0]) || !ID.matcher(parts[1]).matches()
                || !ENCODED_32.matcher(parts[2]).matches() || !ENCODED_32.matcher(parts[3]).matches()) return false;
        SigningKey key = keys.get(parts[1]);
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

    private static byte[] mac(SigningKey key, String prefix, String token) {
        Mac mac = key.newMac();
        mac.update("light-spa-msal-csrf\0".getBytes(StandardCharsets.US_ASCII));
        mac.update(prefix.getBytes(StandardCharsets.US_ASCII));
        mac.update((byte) 0);
        return mac.doFinal(Csrf.digest(token));
    }

    private static final class SigningKey {
        private final SecretKeySpec secret;
        private final Mac prototype;
        SigningKey(byte[] bytes) {
            secret = new SecretKeySpec(bytes, "HmacSHA256");
            prototype = initialized();
        }
        private Mac initialized() {
            try {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(secret);
                return mac;
            } catch (GeneralSecurityException e) { throw new IllegalStateException("CSRF cryptography unavailable", e); }
        }
        Mac newMac() {
            // Clone an initialized, never-mutated template; support noncloneable JCA providers too.
            try { return (Mac) prototype.clone(); }
            catch (CloneNotSupportedException e) { return initialized(); }
        }
    }
}
