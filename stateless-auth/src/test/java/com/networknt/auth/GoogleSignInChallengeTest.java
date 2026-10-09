package com.networknt.auth;

import org.junit.jupiter.api.Test;
import java.util.concurrent.atomic.AtomicLong;
import static org.junit.jupiter.api.Assertions.*;

class GoogleSignInChallengeTest {
    @Test void bindsToAccountExpiresAndIsSingleUse() {
        AtomicLong clock = new AtomicLong(1);
        GoogleSignInChallenge store = new GoogleSignInChallenge(clock::get);
        var challenge = store.issue("existing-uuid");
        assertEquals("existing-uuid", store.consume(challenge.nonce()).userId());
        assertNull(store.consume(challenge.nonce()));
        var expired = store.issue(null);
        clock.addAndGet(300000);
        assertNull(store.consume(expired.nonce()));
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
