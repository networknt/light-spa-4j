package com.networknt.auth;

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class GoogleChallengeSourceTest {
    @Test void directConnectionsIgnoreSpoofedForwarding() {
        assertEquals("198.51.100.1", GoogleChallengeSource.address("198.51.100.1", "203.0.113.99", ""));
        assertEquals("198.51.100.1", GoogleChallengeSource.address("198.51.100.1", "invalid", "10.0.0.1"));
    }
    @Test void clientsBehindOneProxyHaveIndependentBudgets() {
        GoogleSignInChallenge store = new GoogleSignInChallenge(() -> 1L);
        String first = GoogleChallengeSource.address("10.0.0.1", "198.51.100.1", "10.0.0.1");
        String second = GoogleChallengeSource.address("10.0.0.1", "198.51.100.2", "10.0.0.1");
        for (int i = 0; i < 32; i++) store.issue(null, first);
        assertThrows(GoogleSignInChallenge.RateLimited.class, () -> store.issue(null, first));
        assertNotNull(store.issue(null, second));
    }
    @Test void walksTrustedHopsAndIgnoresClientInjectedPrefix() {
        assertEquals("198.51.100.1", GoogleChallengeSource.address("10.0.0.2", "spoofed, 198.51.100.1, 10.0.0.1", List.of("10.0.0.1", "10.0.0.2")));
        assertEquals("10.0.0.3", GoogleChallengeSource.address("10.0.0.2", "198.51.100.1, 10.0.0.3", "10.0.0.2"));
        assertEquals("198.51.100.1", GoogleChallengeSource.address("::1", "198.51.100.1", "0:0:0:0:0:0:0:1"));
    }
    @Test void malformedTrustedForwardingDoesNotUseProxyBudget() {
        for (String value : new String[]{"", "host.example", "198.51.100.1:1234", "999.1.1.1", "10.0.0.1", "198.51.100.1,"})
            assertThrows(IllegalArgumentException.class, () -> GoogleChallengeSource.address("10.0.0.1", value, "10.0.0.1"));
        assertThrows(IllegalArgumentException.class, () -> GoogleChallengeSource.address("10.0.0.1", null, "10.0.0.1"));
        assertThrows(IllegalArgumentException.class, () -> GoogleChallengeSource.address("10.0.0.1", "1.1.1.1,".repeat(33), "10.0.0.1"));
        assertThrows(IllegalStateException.class, () -> GoogleChallengeSource.address("10.0.0.1", "198.51.100.1", "proxy.example"));
    }
}
