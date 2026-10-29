package com.networknt.auth;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.core.read.ListAppender;
import ch.qos.logback.classic.spi.ILoggingEvent;
import com.networknt.cluster.Cluster;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;
import org.slf4j.LoggerFactory;
import java.lang.reflect.Proxy;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

@Isolated
class PortalProviderPrivacyTest {
    @Test void commandAndProviderExceptionNeverReachLogsOrReturnedStatus() {
        final String canary = "portal-provider-secret-canary";
        Cluster previousCluster = PortalClient.cluster;
        var previousCommand = PortalClient.commandConnection;
        var previousQuery = PortalClient.queryConnection;
        Logger logger = (Logger) LoggerFactory.getLogger(PortalClient.class);
        Level level = logger.getLevel();
        ListAppender<ILoggingEvent> logs = new ListAppender<>(); logs.start();
        logger.addAppender(logs); logger.setLevel(Level.TRACE);
        try {
            PortalClient.commandConnection = null; PortalClient.queryConnection = null;
            PortalClient.cluster = (Cluster) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[]{Cluster.class}, (proxy, method, args) -> {
                        throw new IllegalStateException(canary + "\r\nforged=1");
                    });
            var command = PortalClient.createSocialUser(Map.of("password", canary), canary);
            var query = PortalClient.callQueryWithToken(canary, canary);
            assertTrue(command.isFailure()); assertTrue(query.isFailure());
            assertFalse(command.getError().toString().contains(canary));
            assertFalse(query.getError().toString().contains(canary));
            assertTrue(logs.list.stream().anyMatch(e -> e.getFormattedMessage().contains("IllegalStateException")));
            for (var event : logs.list) {
                assertFalse(event.getFormattedMessage().contains(canary));
                assertNull(event.getThrowableProxy(), "provider throwable must not be retained by the log event");
                if (event.getArgumentArray() != null) for (Object value : event.getArgumentArray())
                    assertFalse(String.valueOf(value).contains(canary));
            }
        } finally {
            PortalClient.cluster = previousCluster;
            PortalClient.commandConnection = previousCommand; PortalClient.queryConnection = previousQuery;
            logger.detachAppender(logs); logger.setLevel(level); logs.stop();
        }
    }
}
