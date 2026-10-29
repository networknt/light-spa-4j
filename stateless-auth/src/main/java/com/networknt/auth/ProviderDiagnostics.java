package com.networknt.auth;

import com.networknt.status.Status;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.Headers;
import org.slf4j.Logger;
import java.sql.SQLException;
import java.util.*;

/** Allowlisted diagnostics: retain call sites and cause types, never provider messages. */
final class ProviderDiagnostics {
    private ProviderDiagnostics() { }
    static Status rejected(Status provider) {
        Status safe = new Status("ERR10014", "OAuth provider request failed");
        safe.setStatusCode(provider.getStatusCode());
        return safe;
    }
    static void reject(HttpServerExchange exchange, Status provider, Logger logger) {
        Status safe = rejected(provider);
        exchange.setStatusCode(safe.getStatusCode());
        exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "application/json");
        exchange.getResponseSender().send(safe.toString());
        logger.error("OAuth provider request failed; HTTP status {}", safe.getStatusCode());
    }
    static void log(Logger logger, Throwable failure) {
        logger.error("Portal provider request failed", sanitized(failure,
                Collections.newSetFromMap(new IdentityHashMap<>()), 0));
    }
    private static Throwable sanitized(Throwable failure, Set<Throwable> seen, int depth) {
        if (failure == null) return null;
        if (depth >= 8 || seen.size() >= 64 || !seen.add(failure)) return new SafeFailure("Cause chain truncated");
        String metadata = failure.getClass().getName();
        if (failure instanceof SQLException sql) {
            String state = sql.getSQLState();
            if (state != null && state.matches("[A-Z0-9]{5}")) metadata += " SQLState=" + state;
            metadata += " vendorCode=" + sql.getErrorCode();
        }
        SafeFailure copy = new SafeFailure(metadata);
        StackTraceElement[] frames = failure.getStackTrace();
        copy.setStackTrace(Arrays.copyOf(frames, Math.min(frames.length, 32)));
        Throwable cause = sanitized(failure.getCause(), seen, depth + 1);
        if (cause != null) copy.initCause(cause);
        Throwable[] suppressed = failure.getSuppressed();
        for (int i = 0; i < Math.min(suppressed.length, 4); i++) {
            Throwable safe = sanitized(suppressed[i], seen, depth + 1);
            if (safe != null) copy.addSuppressed(safe);
        }
        return copy;
    }
    private static final class SafeFailure extends RuntimeException {
        private static final long serialVersionUID = 1L;
        SafeFailure(String metadata) { super(metadata); }
    }
}
