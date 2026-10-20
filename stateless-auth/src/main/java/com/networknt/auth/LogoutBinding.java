package com.networknt.auth;

import com.networknt.auth.csrf.Csrf;
import com.networknt.security.JwtVerifier;
import com.networknt.client.AuthServerConfig;
import com.networknt.client.ClientConfig;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import com.networknt.client.oauth.OauthHelper;
import com.networknt.client.oauth.TokenKeyRequest;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwk.JsonWebKeySet;
import com.networknt.security.VerificationException;
import com.networknt.utility.Constants;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.UnresolvableKeyException;

/** Classifies the cookie pair independently of the request's untrusted CSRF transport. */
final class LogoutBinding {
    enum State { USABLE, UNUSABLE, UNKNOWN }

    // One bounded snapshot, not an attacker-controlled map of negative key IDs.
    // Confirmation only: normal verification and its key cache remain authoritative.
    private static final long KEY_SNAPSHOT_TTL = TimeUnit.SECONDS.toNanos(5);
    private static volatile KeySnapshot keySnapshot;

    private LogoutBinding() { }

    static void clearKeySnapshot() { keySnapshot = null; }

    private static synchronized State confirmMissingKey(String kid) throws Exception {
        ClientConfig config = ClientConfig.get();
        List<AuthServerConfig> providers = new ArrayList<>();
        if (config.getOAuth().isMultipleAuthServers()) {
            var configured = config.getOAuth().getToken().getKey().getServiceIdAuthServers();
            if (configured == null || configured.isEmpty()) return State.UNKNOWN;
            // A conservative superset of every service/path-selected key authority.
            // Do not infer that credentials exclude a provider from JWT key lookup.
            providers.addAll(configured.values());
            if (providers.isEmpty()) return State.UNKNOWN;
        } else {
            providers.add(null); // TokenKeyRequest's single-server configuration.
        }
        KeySnapshot cached = keySnapshot;
        if (cached == null || cached.config != config || !cached.providers.equals(providers)
                || System.nanoTime() >= cached.expiresAt) {
            Set<String> kids = new HashSet<>();
            boolean complete = true;
            for (AuthServerConfig provider : providers) {
                try {
                    // Fetch the whole set once, independently of the untrusted key ID.
                    JsonWebKeySet keys = new JsonWebKeySet(OauthHelper.getKey(new TokenKeyRequest(null, true, provider)));
                    for (var key : keys.getJsonWebKeys()) if (key.getKeyId() != null) kids.add(key.getKeyId());
                } catch (Exception lookupFailure) {
                    complete = false; // Absence at one provider proves nothing about an unavailable one.
                }
            }
            cached = new KeySnapshot(config, Collections.unmodifiableList(new ArrayList<>(providers)),
                    Set.copyOf(kids), complete, System.nanoTime() + KEY_SNAPSHOT_TTL);
            keySnapshot = cached; // Cache failed/partial confirmations too, to bound retries.
        }
        return cached.complete && !cached.kids.contains(kid) ? State.UNUSABLE : State.UNKNOWN;
    }

    private record KeySnapshot(ClientConfig config, List<AuthServerConfig> providers,
                               Set<String> kids, boolean complete, long expiresAt) { }

    static State classify(JwtVerifier verifier, String token, String cookieCsrf) {
        if (token == null || token.isBlank() || cookieCsrf == null || cookieCsrf.isBlank()) return State.UNUSABLE;
        try {
            // Expiry relaxation authorizes cleanup only, not API access.
            String claim = verifier.verifyJwt(token, true, true).getStringClaimValue(Constants.CSRF);
            return Csrf.equal(claim, cookieCsrf) ? State.USABLE : State.UNUSABLE;
        } catch (InvalidJwtException e) {
            // A key lookup failure is not proof of invalidity and must not erase a session.
            for (Throwable cause = e; cause != null; cause = cause.getCause())
                if (cause instanceof UnresolvableKeyException) return State.UNKNOWN;
            return State.UNUSABLE;
        } catch (MalformedClaimException e) {
            return State.UNUSABLE;
        } catch (VerificationException e) {
            // JwtVerifier also emits this message after swallowed network/parse errors.
            // Only a successful, parseable JWKS response can establish a retired key.
            if (e.getMessage() != null && e.getMessage().startsWith("no JWK for kid:")) {
                try {
                    JsonWebSignature signature = new JsonWebSignature();
                    signature.setCompactSerialization(token);
                    String kid = signature.getKeyIdHeaderValue();
                    if (kid != null && !kid.isBlank()) {
                        return confirmMissingKey(kid);
                    }
                } catch (Exception lookupFailure) {
                    // Lookup uncertainty must preserve cookies.
                }
            }
            return State.UNKNOWN;
        } catch (Exception e) {
            return State.UNKNOWN;
        }
    }
}
