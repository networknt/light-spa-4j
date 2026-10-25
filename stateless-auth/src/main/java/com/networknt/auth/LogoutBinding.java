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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeoutException;
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
    private static KeyLookup keyLookup;
    private static final long KEY_WAIT_MILLIS = 5000;

    private LogoutBinding() { }

    static synchronized void clearKeySnapshot() { keySnapshot = null; }

    private static State confirmMissingKey(String kid) throws Exception {
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
        providers = Collections.unmodifiableList(new ArrayList<>(providers));
        KeyLookup lookup;
        boolean owner = false;
        synchronized (LogoutBinding.class) {
            KeySnapshot cached = keySnapshot;
            if (cached != null && cached.config == config && cached.providers.equals(providers)
                    && System.nanoTime() < cached.expiresAt) return cached.state(kid);
            if (keyLookup == null) {
                keyLookup = new KeyLookup(config, providers, new CompletableFuture<>());
                owner = true;
            } else if (keyLookup.config != config || !keyLookup.providers.equals(providers)) {
                // Never queue a second configuration's network work behind the current lookup.
                return State.UNKNOWN;
            }
            lookup = keyLookup;
        }
        if (owner) {
            try {
                KeySnapshot snapshot = fetchKeys(config, providers);
                synchronized (LogoutBinding.class) { keySnapshot = snapshot; }
                lookup.future.complete(snapshot);
            } catch (Exception e) {
                lookup.future.completeExceptionally(e);
                throw e;
            } finally {
                // No HTTP request or future wait runs under the class monitor.
                synchronized (LogoutBinding.class) { if (keyLookup == lookup) keyLookup = null; }
                if (!lookup.future.isDone()) lookup.future.completeExceptionally(new IllegalStateException("Key lookup aborted"));
            }
        }
        try {
            return lookup.future.get(KEY_WAIT_MILLIS, TimeUnit.MILLISECONDS).state(kid);
        } catch (TimeoutException e) {
            return State.UNKNOWN; // A late waiter must not cancel or replace the owner.
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return State.UNKNOWN;
        }
    }

    private static KeySnapshot fetchKeys(ClientConfig config, List<AuthServerConfig> providers) {
        Set<String> kids = new HashSet<>();
        boolean complete = true;
        for (AuthServerConfig provider : providers) {
            try {
                JsonWebKeySet keys = new JsonWebKeySet(OauthHelper.getKey(new TokenKeyRequest(null, true, provider)));
                for (var key : keys.getJsonWebKeys()) if (key.getKeyId() != null) kids.add(key.getKeyId());
            } catch (Exception lookupFailure) {
                complete = false; // Absence at one provider proves nothing about an unavailable one.
            }
        }
        return new KeySnapshot(config, providers, Set.copyOf(kids), complete, System.nanoTime() + KEY_SNAPSHOT_TTL);
    }

    private record KeyLookup(ClientConfig config, List<AuthServerConfig> providers,
                             CompletableFuture<KeySnapshot> future) { }

    private record KeySnapshot(ClientConfig config, List<AuthServerConfig> providers,
                               Set<String> kids, boolean complete, long expiresAt) {
        State state(String kid) { return complete && !kids.contains(kid) ? State.UNUSABLE : State.UNKNOWN; }
    }

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
