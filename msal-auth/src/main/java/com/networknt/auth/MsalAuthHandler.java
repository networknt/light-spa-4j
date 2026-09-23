package com.networknt.auth;

import com.networknt.config.JsonMapper;
import com.networknt.handler.Handler;
import com.networknt.handler.MiddlewareHandler;
import com.networknt.httpstring.HttpStringConstants;
import com.networknt.security.JwtVerifier;
import com.networknt.security.SecurityConfig;
import com.networknt.security.VerificationException;
import com.networknt.status.Status;
import com.networknt.utility.Constants;
import com.networknt.utility.UuidUtil;
import io.undertow.Handlers;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.Cookie;
import io.undertow.server.handlers.CookieImpl;
import io.undertow.server.handlers.CookieSameSiteMode;
import io.undertow.util.Headers;
import io.undertow.util.Methods;
import io.undertow.util.StatusCodes;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Deque;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/** Direct Entra ID authentication for a browser-facing gateway. */
public class MsalAuthHandler implements MiddlewareHandler {
    private static final Logger logger = LoggerFactory.getLogger(MsalAuthHandler.class);
    private static final String ACCESS_TOKEN = "accessToken";
    private static final String CSRF_PROTOCOL_PREFIX = "csrf.";
    private static final String INVALID_AUTH_TOKEN = "ERR10000";
    private static final String CSRF_MISSING = "ERR10036";
    private static final String CSRF_MISMATCH = "ERR10039";
    private static final String LOGOUT_CSRF_INVALID = "ERR11649";
    private static final String METHOD_NOT_ALLOWED = "ERR10008";
    private static final AtomicLong LEGACY_LOGOUT_GET_COUNT = new AtomicLong();
    private static final AtomicLong LOGOUT_CSRF_WOULD_REJECT_COUNT = new AtomicLong();

    private static volatile VerifierState verifierState;

    private volatile HttpHandler next;

    public MsalAuthHandler() {
        MsalAuthConfig config = MsalAuthConfig.load();
        if (config.isEnabled()) ensureVerifierState();
    }

    @Override
    public void handleRequest(HttpServerExchange exchange) throws Exception {
        MsalAuthConfig config = MsalAuthConfig.load();
        if (!config.isEnabled()) {
            Handler.next(exchange, next);
            return;
        }
        ensureVerifierState();
        String path = exchange.getRelativePath();
        boolean login = path.equals(config.getLoginPath());
        boolean logout = path.equals(config.getLogoutPath());

        if (login || logout) {
            if (Methods.OPTIONS.equals(exchange.getRequestMethod())) {
                Handler.next(exchange, next);
                return;
            }
            exchange.getResponseHeaders().put(Headers.CACHE_CONTROL, "no-store");
            if (!Methods.POST.equals(exchange.getRequestMethod())) {
                if (logout && Methods.GET.equals(exchange.getRequestMethod())) recordLegacyLogoutGet();
                exchange.getResponseHeaders().put(Headers.ALLOW, Methods.POST_STRING);
                setExchangeStatus(exchange, METHOD_NOT_ALLOWED,
                        exchange.getRequestMethod().toString(), path);
                return;
            }
        }

        if (login) {
            handleLogin(exchange, config);
            return;
        }
        if (logout) {
            if (!validateLogoutCsrf(exchange, config)) return;
            clearCookie(exchange, ACCESS_TOKEN, true, config);
            clearCookie(exchange, Constants.CSRF, false, config);
            exchange.setStatusCode(StatusCodes.NO_CONTENT);
            exchange.endExchange();
            return;
        }

        Cookie accessToken = exchange.getRequestCookie(ACCESS_TOKEN);
        if (accessToken != null && accessToken.getValue() != null && !accessToken.getValue().isBlank()) {
            String token = accessToken.getValue();
            if (verifyMicrosoftToken(exchange, token) == null) return;
            String cookieCsrf = cookieValue(exchange, Constants.CSRF);
            String requestCsrf = requestCsrf(exchange);
            if (cookieCsrf == null || requestCsrf == null) {
                rejectUnauthorized(exchange, CSRF_MISSING, "CSRF_HEADER_MISSING",
                        "Missing CSRF cookie or request value");
                return;
            }
            if (!cookieCsrf.equals(requestCsrf)) {
                logger.warn("MSAL double-submit CSRF validation failed");
                rejectUnauthorized(exchange, CSRF_MISMATCH, "CSRF_VALIDATION_FAILED",
                        "CSRF request value does not match cookie");
                return;
            }
            exchange.getRequestHeaders().put(Headers.AUTHORIZATION, "Bearer " + token);
        }
        Handler.next(exchange, next);
    }

    private void handleLogin(HttpServerExchange exchange, MsalAuthConfig config) throws Exception {
        String token = bearerToken(exchange);
        if (token == null) {
            rejectUnauthorized(exchange, "ERR11000", "MSAL_BEARER_TOKEN_MISSING",
                    "Microsoft bearer token is missing");
            return;
        }
        JwtClaims claims = verifyMicrosoftToken(exchange, token);
        if (claims == null) return;
        String csrf = UuidUtil.uuidToBase64(UuidUtil.getUUID());
        int maxAge = cookieMaxAge(claims, config.getSessionTimeout());
        setCookie(exchange, ACCESS_TOKEN, token, maxAge, true, config);
        setCookie(exchange, Constants.CSRF, csrf, maxAge, false, config);
        exchange.setStatusCode(StatusCodes.OK);
        exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "application/json");
        exchange.getResponseSender().send(JsonMapper.toJson(Map.of("message", "success")));
    }

    private JwtClaims verifyMicrosoftToken(HttpServerExchange exchange, String token) throws Exception {
        VerifierState state = ensureVerifierState();
        try {
            // Expiry is always enforced for this handler, independently of security-msal.ignoreJwtExpiry.
            return state.verifier.verifyJwt(token, false, true, null,
                    exchange.getRequestPath(), null);
        } catch (InvalidJwtException | VerificationException e) {
            logger.warn("Microsoft token validation failed: {}", e.getMessage());
            setExchangeStatus(exchange, INVALID_AUTH_TOKEN, e.getMessage());
            return null;
        }
    }

    private boolean validateLogoutCsrf(HttpServerExchange exchange, MsalAuthConfig config) {
        if (exchange.getRequestCookie(ACCESS_TOKEN) == null && exchange.getRequestCookie(Constants.CSRF) == null) return true;
        String requestCsrf = requestCsrf(exchange);
        String cookieCsrf = cookieValue(exchange, Constants.CSRF);
        boolean missing = requestCsrf == null;
        if (!missing && requestCsrf.equals(cookieCsrf)) return true;
        long count = LOGOUT_CSRF_WOULD_REJECT_COUNT.incrementAndGet();
        logger.info("event=spa_auth_logout_csrf_would_reject runtime=msal-auth endpoint=logout " +
                        "failure={} enforced={} count={} counterScope=process reset=process_restart",
                missing ? "header_missing" : "cookie_invalid", config.isLogoutCsrfEnforced(), count);
        if (!config.isLogoutCsrfEnforced()) return true;
        rejectUnauthorized(exchange, missing ? CSRF_MISSING : LOGOUT_CSRF_INVALID,
                missing ? "CSRF_HEADER_MISSING" : "LOGOUT_CSRF_VALIDATION_FAILED",
                missing ? "Missing CSRF request value" : "CSRF cookie/header validation failed for logout");
        return false;
    }

    private void rejectUnauthorized(HttpServerExchange exchange, String code, String message, String description) {
        setExchangeStatus(exchange, new Status(StatusCodes.UNAUTHORIZED, code, message, description));
    }

    static String bearerToken(HttpServerExchange exchange) {
        String header = exchange.getRequestHeaders().getFirst(Headers.AUTHORIZATION);
        if (header == null) return null;
        int space = header.indexOf(' ');
        if (space <= 0 || !"Bearer".equalsIgnoreCase(header.substring(0, space))) return null;
        String token = header.substring(space + 1).trim();
        return token.isEmpty() ? null : token;
    }

    static String requestCsrf(HttpServerExchange exchange) {
        String value = exchange.getRequestHeaders().getFirst(HttpStringConstants.CSRF_TOKEN);
        if (value != null && !value.isBlank()) return value;
        if (exchange.getRequestHeaders().getFirst("Sec-WebSocket-Key") != null &&
                exchange.getRequestHeaders().getFirst("Sec-WebSocket-Version") != null) {
            String protocols = exchange.getRequestHeaders().getFirst("Sec-WebSocket-Protocol");
            if (protocols != null) {
                for (String protocol : protocols.split(",")) {
                    String candidate = protocol.trim();
                    if (candidate.startsWith(CSRF_PROTOCOL_PREFIX))
                        return candidate.substring(CSRF_PROTOCOL_PREFIX.length());
                }
            }
        }
        Deque<String> query = exchange.getQueryParameters().get(Constants.CSRF);
        return query == null || query.isEmpty() ? null : query.getFirst();
    }

    static int cookieMaxAge(JwtClaims claims, int sessionTimeout) {
        try {
            if (claims.getExpirationTime() == null) return 0;
            long seconds = (claims.getExpirationTime().getValueInMillis() - System.currentTimeMillis()) / 1000;
            return (int) Math.max(0, Math.min(seconds, sessionTimeout));
        } catch (Exception e) {
            return 0;
        }
    }

    private static VerifierState ensureVerifierState() {
        VerifierState state = verifierState;
        if (state != null) return state;
        synchronized (MsalAuthHandler.class) {
            state = verifierState;
            if (state == null) {
                SecurityConfig config = SecurityConfig.load("security-msal");
                state = new VerifierState(new JwtVerifier(config));
                verifierState = state;
            }
            return state;
        }
    }

    static void installVerifierForTest(JwtVerifier verifier) {
        verifierState = new VerifierState(verifier);
    }

    private static final class VerifierState {
        private final JwtVerifier verifier;

        private VerifierState(JwtVerifier verifier) {
            this.verifier = verifier;
        }
    }

    private static String cookieValue(HttpServerExchange exchange, String name) {
        Cookie cookie = exchange.getRequestCookie(name);
        return cookie == null || cookie.getValue() == null || cookie.getValue().isBlank() ? null : cookie.getValue();
    }

    private static CookieSameSiteMode sameSite(String value) {
        if (value == null) return CookieSameSiteMode.NONE;
        for (CookieSameSiteMode mode : CookieSameSiteMode.values())
            if (mode.toString().equalsIgnoreCase(value)) return mode;
        throw new IllegalArgumentException("msal-auth.cookieSameSite must be Strict, Lax, or None");
    }

    private static void setCookie(HttpServerExchange exchange, String name, String value, int maxAge,
                                  boolean httpOnly, MsalAuthConfig config) {
        exchange.setResponseCookie(new CookieImpl(name, value).setDomain(config.getCookieDomain())
                .setPath(config.getCookiePath()).setMaxAge(maxAge).setHttpOnly(httpOnly)
                .setSameSiteMode(sameSite(config.getCookieSameSite()).toString()).setSecure(config.isCookieSecure()));
    }

    private static void clearCookie(HttpServerExchange exchange, String name, boolean httpOnly, MsalAuthConfig config) {
        setCookie(exchange, name, "", 0, httpOnly, config);
    }

    private static void recordLegacyLogoutGet() {
        long count = LEGACY_LOGOUT_GET_COUNT.incrementAndGet();
        logger.info("event=spa_auth_legacy_method runtime=msal-auth endpoint=logout method=GET " +
                "count={} counterScope=process reset=process_restart", count);
    }

    static long legacyLogoutGetCount() { return LEGACY_LOGOUT_GET_COUNT.get(); }
    static long logoutCsrfWouldRejectCount() { return LOGOUT_CSRF_WOULD_REJECT_COUNT.get(); }

    @Override public HttpHandler getNext() { return next; }
    @Override public MiddlewareHandler setNext(HttpHandler next) {
        Handlers.handlerNotNull(next); this.next = next; return this;
    }
    @Override public boolean isEnabled() { return MsalAuthConfig.load().isEnabled(); }
}
