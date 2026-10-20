package com.networknt.auth;

import com.networknt.auth.csrf.Csrf;
import com.networknt.security.JwtVerifier;
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

    private LogoutBinding() { }

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
                        JsonWebKeySet keys = new JsonWebKeySet(OauthHelper.getKey(new TokenKeyRequest(kid, true, null)));
                        if (keys.findJsonWebKey(kid, null, null, null) == null) return State.UNUSABLE;
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
