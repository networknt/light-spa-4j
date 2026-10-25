package com.networknt.auth;

import com.networknt.auth.csrf.Csrf;
import com.networknt.auth.trust.JwtTrust;
import com.networknt.utility.Constants;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;

/** Cleanup uses exactly the same isolated signing authority and application policy as authentication. */
final class LogoutBinding {
    enum State { USABLE, UNUSABLE, UNKNOWN }
    private LogoutBinding() { }

    static State classify(JwtTrust trust, String token, String cookieCsrf) {
        if (token == null || token.isBlank() || cookieCsrf == null || cookieCsrf.isBlank()) return State.UNUSABLE;
        try {
            String csrf = trust.verify(token, true).getStringClaimValue(Constants.CSRF);
            return Csrf.equal(csrf, cookieCsrf) ? State.USABLE : State.UNUSABLE;
        } catch (InvalidJwtException e) {
            return JwtTrust.unavailable(e) ? State.UNKNOWN : State.UNUSABLE;
        } catch (MalformedClaimException e) {
            return State.UNUSABLE;
        } catch (Exception e) {
            return State.UNKNOWN;
        }
    }
}
