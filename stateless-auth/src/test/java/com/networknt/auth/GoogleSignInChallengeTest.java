package com.networknt.auth;

import org.junit.jupiter.api.Test;
import java.util.concurrent.atomic.AtomicLong;
import static org.junit.jupiter.api.Assertions.*;

class GoogleSignInChallengeTest {
    @Test void bindsToAccountExpiresAndIsSingleUse() {
        AtomicLong clock = new AtomicLong(1);
        GoogleSignInChallenge store = new GoogleSignInChallenge(clock::get);
        var challenge = store.issue("existing-uuid", "source");
        assertEquals("existing-uuid", store.consume(challenge.id(), challenge.nonce()).userId());
        assertNull(store.consume(challenge.id(), challenge.nonce()));
        var expired = store.issue(null, "source");
        clock.addAndGet(300000);
        assertNull(store.consume(expired.id(), expired.nonce()));
    }
    @Test void oneSourceCannotExhaustTheGlobalCapacity() {
        AtomicLong clock = new AtomicLong(1);
        GoogleSignInChallenge store = new GoogleSignInChallenge(clock::get);
        for (int i = 0; i < 32; i++) store.issue(null, "attacker");
        assertThrows(GoogleSignInChallenge.RateLimited.class, () -> store.issue(null, "attacker"));
        assertNotNull(store.issue(null, "other-user"));
        clock.addAndGet(300000);
        assertNotNull(store.issue(null, "attacker"));
    }
    @Test void wrongCookieConsumesOnlyThatAttempt() {
        GoogleSignInChallenge store = new GoogleSignInChallenge(() -> 1L);
        var first = store.issue(null, "source"); var second = store.issue(null, "source");
        assertNull(store.consume(first.id(), second.nonce()));
        assertNull(store.consume(first.id(), first.nonce()));
        assertNotNull(store.consume(second.id(), second.nonce()));
    }
    @Test void requiresExactHttpsOriginsAndPreservesPortalState() {
        assertTrue(GoogleAuthHandler.validOrigin("https://signin.example"));
        for (String origin : new String[]{"", "*", "http://signin.example", "https://signin.example/path",
                "https://user@signin.example", "https://signin.example?query", "https://signin.example#fragment"}) {
            assertFalse(GoogleAuthHandler.validOrigin(origin));
        }
        assertEquals("https://portal/#/app/dashboard?state=a%26b",
                GoogleAuthHandler.redirect("https://portal/#/app/dashboard", "a&b"));
        assertEquals("https://portal/#/app/dashboard?x=1&state=s",
                GoogleAuthHandler.redirect("https://portal/#/app/dashboard?x=1", "s"));
    }
}
