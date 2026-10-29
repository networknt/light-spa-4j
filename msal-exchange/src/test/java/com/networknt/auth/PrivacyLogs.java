package com.networknt.auth;

import ch.qos.logback.classic.*;
import ch.qos.logback.classic.spi.*;
import ch.qos.logback.core.read.ListAppender;
import org.slf4j.LoggerFactory;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import static org.junit.jupiter.api.Assertions.*;

/** Root capture: full TRACE for Portal failures, auth TRACE for legacy URL callbacks. */
final class PrivacyLogs implements AutoCloseable {
    final ListAppender<ILoggingEvent> events = new ListAppender<>() {
        @Override protected void append(ILoggingEvent event) { event.prepareForDeferredProcessing(); super.append(event); }
    };
    private final Map<Logger, Level> levels = new IdentityHashMap<>();
    private final Logger root = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    private final String[] canaries;
    PrivacyLogs(String... canaries) { this(true, canaries); }
    PrivacyLogs(boolean allTrace, String... canaries) {
        this.canaries = canaries;
        LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
        for (Logger logger : context.getLoggerList()) {
            levels.put(logger, logger.getLevel());
            logger.setLevel(allTrace || logger.getName().startsWith("com.networknt.auth") ? Level.TRACE : Level.WARN);
        }
        // Callback protocols carry secrets in URLs; raw transport TRACE is a separate boundary.
        if (!allTrace) {
            Logger auth = context.getLogger("com.networknt.auth");
            if (!levels.containsKey(auth)) levels.put(auth, auth.getLevel());
            auth.setLevel(Level.TRACE);
        }
        events.list = new CopyOnWriteArrayList<>(); events.start(); root.addAppender(events);
    }
    void text(String value) { for (String marker : canaries) assertFalse(value.contains(marker), "Sensitive canary in logs/response"); }
    private void value(Object value) {
        if (value == null) return;
        if (value instanceof char[] chars) text(new String(chars));
        else if (value instanceof byte[] bytes) text(new String(bytes, java.nio.charset.StandardCharsets.UTF_8));
        else if (value instanceof Object[] array) for (Object item : array) value(item);
        else if (value instanceof Map<?, ?> map) map.forEach((key, item) -> { value(key); value(item); });
        else text(String.valueOf(value));
    }
    private void throwable(IThrowableProxy failure) {
        if (failure == null) return;
        text(String.valueOf(failure.getMessage()));
        for (var frame : failure.getStackTraceElementProxyArray()) text(frame.toString());
        throwable(failure.getCause());
        if (failure.getSuppressed() != null) for (var item : failure.getSuppressed()) throwable(item);
    }
    void awaitMessage(String text) throws Exception {
        long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(3);
        while (events.list.stream().noneMatch(event -> event.getFormattedMessage().contains(text))) {
            assertTrue(System.nanoTime() < deadline, "Expected diagnostic was not emitted"); Thread.sleep(5);
        }
    }
    @Override public void close() {
        try {
            for (var event : events.list) {
                text(event.getFormattedMessage()); value(event.getArgumentArray()); value(event.getMDCPropertyMap()); throwable(event.getThrowableProxy());
            }
        } finally { root.detachAppender(events); levels.forEach(Logger::setLevel); events.stop(); }
    }
}
