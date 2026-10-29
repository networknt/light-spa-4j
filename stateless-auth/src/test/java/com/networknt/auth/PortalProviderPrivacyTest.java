package com.networknt.auth;

import com.networknt.cluster.Cluster;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;
import java.lang.reflect.Proxy;
import java.sql.SQLException;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

@Isolated
class PortalProviderPrivacyTest {
    @Test void commandAndNestedProviderFailuresKeepSafeCallSitesButNoPayloads() {
        final String canary = "portal-provider-secret-canary";
        Cluster previousCluster = PortalClient.cluster;
        var previousCommand = PortalClient.commandConnection;
        var previousQuery = PortalClient.queryConnection;
        try (PrivacyLogs logs = new PrivacyLogs(canary)) {
            PortalClient.commandConnection = null; PortalClient.queryConnection = null;
            PortalClient.cluster = (Cluster) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[]{Cluster.class}, (proxy, method, args) -> {
                        var cause = new SQLException(canary, "08001", 42);
                        // Anonymous types have an empty simple name; fully qualified names do not.
                        var failure = new IllegalStateException(canary + "\r\nforged=1", cause) { };
                        cause.initCause(failure); // A cyclic provider chain must remain bounded.
                        failure.addSuppressed(new IllegalArgumentException(canary));
                        throw failure;
                    });
            var command = PortalClient.createSocialUser(Map.of("password", canary), canary);
            var query = PortalClient.callQueryWithToken(canary, canary);
            assertTrue(command.isFailure()); assertTrue(query.isFailure());
            logs.text(command.getError().toString()); logs.text(query.getError().toString());
            var diagnostic = logs.events.list.stream().filter(event -> event.getFormattedMessage().equals("Portal provider request failed"))
                    .findFirst().orElseThrow().getThrowableProxy();
            assertNotNull(diagnostic);
            assertTrue(diagnostic.getMessage().contains("PortalProviderPrivacyTest$"));
            assertTrue(diagnostic.getStackTraceElementProxyArray().length > 0);
            assertTrue(diagnostic.getCause().getMessage().contains("java.sql.SQLException SQLState=08001 vendorCode=42"));
            assertNotNull(diagnostic.getSuppressed());
            assertEquals("Cause chain truncated", diagnostic.getCause().getCause().getMessage());
        } finally {
            PortalClient.cluster = previousCluster;
            PortalClient.commandConnection = previousCommand; PortalClient.queryConnection = previousQuery;
        }
    }
    @Test void connectionInitializationKeepsSafeFailureCallSites() {
        final String canary = "portal-init-secret-canary";
        Cluster previous = PortalClient.cluster;
        var command = PortalClient.commandConnection; var query = PortalClient.queryConnection;
        try (PrivacyLogs logs = new PrivacyLogs(canary)) {
            PortalClient.cluster = (Cluster) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[]{Cluster.class}, (proxy, method, args) -> "https://" + canary + " invalid-host");
            assertNotNull(new PortalClient());
            assertEquals(2, logs.events.list.stream().filter(event -> event.getFormattedMessage().equals("Portal provider request failed")
                    && event.getThrowableProxy() != null
                    && event.getThrowableProxy().getMessage().equals("java.net.URISyntaxException")
                    && event.getThrowableProxy().getStackTraceElementProxyArray().length > 0).count());
        } finally { PortalClient.cluster = previous; PortalClient.commandConnection = command; PortalClient.queryConnection = query; }
    }

}
