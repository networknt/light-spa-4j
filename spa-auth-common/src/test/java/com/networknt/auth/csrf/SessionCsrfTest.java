package com.networknt.auth.csrf;

import org.junit.jupiter.api.Test;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class SessionCsrfTest {
    private static final String FIRST = "old=" + Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]);
    private static final String SECOND = "new=" + Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[48]);

    @Test void bindsToExactSessionAndRejectsUnsignedMatchingValues() {
        SessionCsrf signer = new SessionCsrf("old", FIRST);
        String issued = signer.issue("access-token-A");
        assertTrue(signer.verify(issued, "access-token-A"));
        assertFalse(signer.verify(issued, "access-token-B"));
        assertFalse(signer.verify("attacker-chosen", "access-token-A"));
        assertFalse(signer.verify(issued, null));
    }

    @Test void replicasAndRotationHaveExplicitVerificationWindow() {
        SessionCsrf old = new SessionCsrf("old", FIRST);
        String before = old.issue("session");
        SessionCsrf rolling = new SessionCsrf("new", FIRST + "," + SECOND);
        assertTrue(rolling.verify(before, "session"));
        assertTrue(new SessionCsrf("new", FIRST + "," + SECOND).verify(rolling.issue("session"), "session"));
        assertFalse(new SessionCsrf("new", SECOND).verify(before, "session"));
        assertFalse(old.verify(rolling.issue("session"), "session"));
    }

    @Test void malformedTamperedAndOversizedValuesFailClosed() {
        SessionCsrf signer = new SessionCsrf("old", FIRST);
        String issued = signer.issue("session");
        for (String value : List.of("", "v2" + issued.substring(2), issued + ".extra", issued + "=",
                issued.substring(0, 10), "x".repeat(10000), issued.replace(".old.", ".new.")))
            assertFalse(signer.verify(value, "session"));
        String[] parts = issued.split("\\.");
        parts[2] = Csrf.nonce();
        assertFalse(signer.verify(String.join(".", parts), "session"));
        parts = issued.split("\\.");
        parts[3] = Csrf.nonce();
        assertFalse(signer.verify(String.join(".", parts), "session"));
        assertFalse(signer.verify(null, "session"));
    }

    @Test void invalidKeyConfigurationNeverEchoesSecrets() {
        for (String setting : List.of("secret-value", "old=short", FIRST + "," + FIRST, "bad.id=secret-value", "old=%%%")) {
            var error = assertThrows(IllegalArgumentException.class, () -> new SessionCsrf("old", setting));
            assertFalse(error.getMessage().contains("secret-value"));
            assertNull(error.getCause());
        }
        assertThrows(IllegalArgumentException.class, () -> new SessionCsrf("missing", FIRST));
        assertThrows(IllegalArgumentException.class, () -> new SessionCsrf(null, null));
    }

    @Test void randomNoncesAreFullLengthAndSubprotocolSafe() {
        var values = new HashSet<String>();
        for (int i = 0; i < 100; i++) {
            String nonce = Csrf.nonce();
            assertTrue(nonce.matches("[A-Za-z0-9_-]{43}"));
            assertEquals(32, Base64.getUrlDecoder().decode(nonce).length);
            assertTrue(values.add(nonce));
        }
    }

    @Test void comparisonIsBoundedAndSupportsLegacyAuthenticatedClaims() {
        assertTrue(Csrf.equal("legacy-claim", "legacy-claim"));
        assertFalse(Csrf.equal("one", "two"));
        assertFalse(Csrf.equal(null, null));
        assertFalse(Csrf.equal("", ""));
        assertFalse(Csrf.equal("x".repeat(513), "x".repeat(513)));
    }

    @Test void signingTemplatesAreSafeAcrossConcurrentRequests() {
        SessionCsrf signer = new SessionCsrf("old", FIRST);
        assertTrue(java.util.stream.IntStream.range(0, 100).parallel().allMatch(i -> {
            String token = "session-" + i;
            String value = signer.issue(token);
            return signer.verify(value, token) && !signer.verify(value, "foreign-session");
        }));
    }
}
