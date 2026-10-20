package com.networknt.auth;

import com.networknt.config.JsonMapper;
import com.networknt.handler.Handler;
import com.networknt.handler.MiddlewareHandler;
import com.networknt.config.Config;
import com.networknt.security.SecurityConfig;
import com.networknt.status.Status;
import com.networknt.utility.Constants;
import com.networknt.auth.csrf.Csrf;
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
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.UnresolvableKeyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/** Direct Entra ID authentication for a browser-facing gateway. */
public class MsalAuthHandler implements MiddlewareHandler {
    private static final Logger logger = LoggerFactory.getLogger(MsalAuthHandler.class);
    private static final String ACCESS_TOKEN = "accessToken";
    private static final String INVALID_AUTH_TOKEN = "ERR10000";
    private static final String AUTH_TOKEN_EXPIRED = "ERR10001";
    private static final String INVALID_TOKEN_DESCRIPTION = "Invalid Microsoft access token";
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
        if (config.isEnabled()) ensureVerifierState(config);
    }

    @Override
    public void handleRequest(HttpServerExchange exchange) throws Exception {
        MsalAuthConfig config = MsalAuthConfig.load();
        if (Methods.OPTIONS.equals(exchange.getRequestMethod())) {
            Handler.next(exchange, next);
            return;
        }
        if (!config.isEnabled()) {
            Handler.next(exchange, next);
            return;
        }
        ensureVerifierState(config);
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
            if (verifyMicrosoftToken(exchange, token, config) == null) return;
            String requestCsrf;
            try { requestCsrf = Csrf.request(exchange, config.getWebsocketAllowedOrigins(), cookieValue(exchange, Constants.CSRF)); }
            catch (IllegalArgumentException e) {
                rejectUnauthorized(exchange, Csrf.code(e), "CSRF_VALIDATION_FAILED", "Missing or invalid CSRF transport");
                return;
            }
            if (!Csrf.equal(cookieValue(exchange, Constants.CSRF), requestCsrf)
                    || !config.getSessionCsrf().verify(requestCsrf, token)) {
                rejectUnauthorized(exchange, CSRF_MISMATCH, "CSRF_VALIDATION_FAILED", "Invalid session-bound CSRF value");
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
        JwtClaims claims = verifyMicrosoftToken(exchange, token, config);
        if (claims == null) return;
        String csrf = config.getSessionCsrf().issue(token);
        int maxAge = cookieMaxAge(claims, config.getSessionTimeout());
        setCookie(exchange, ACCESS_TOKEN, token, maxAge, true, config);
        setCookie(exchange, Constants.CSRF, csrf, maxAge, false, config);
        exchange.setStatusCode(StatusCodes.OK);
        exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "application/json");
        exchange.getResponseSender().send(JsonMapper.toJson(Map.of("message", "success")));
    }

    private JwtClaims verifyMicrosoftToken(HttpServerExchange exchange, String token, MsalAuthConfig config) throws Exception {
        VerifierState state = ensureVerifierState(config);
        try {
            // Expiry is always enforced for this handler, independently of security-msal.ignoreJwtExpiry.
            JwtClaims claims = state.verifier.verify(token);
            config.getTokenPolicy().validate(claims, state.clockSkewSeconds);
            return claims;
        } catch (MsalTokenPolicy.RejectedTokenException e) {
            rejectInvalidToken(exchange, config, e.category());
            return null;
        } catch (InvalidJwtException e) {
            if (keyResolutionFailure(e)) {
                rejectKeyLookup(exchange);
            } else if (e.hasExpired()) {
                rejectToken(exchange, config, "expired", AUTH_TOKEN_EXPIRED, "AUTH_TOKEN_EXPIRED", "Microsoft access token has expired");
            } else {
                rejectInvalidToken(exchange, config, "signature_or_claims");
            }
            return null;
        } catch (MalformedClaimException e) {
            rejectInvalidToken(exchange, config, "signature_or_claims");
            return null;

        }
    }

    private static boolean keyResolutionFailure(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause())
            if (cause instanceof UnresolvableKeyException) return true;
        return false;
    }

    private void rejectKeyLookup(HttpServerExchange exchange) {
        logger.warn("Microsoft token validation failed category=key_lookup");
        rejectUnauthorized(exchange, INVALID_AUTH_TOKEN, "INVALID_AUTH_TOKEN", INVALID_TOKEN_DESCRIPTION);
    }

    private void rejectInvalidToken(HttpServerExchange exchange, MsalAuthConfig config, String category) {
        rejectToken(exchange, config, category, INVALID_AUTH_TOKEN, "INVALID_AUTH_TOKEN", INVALID_TOKEN_DESCRIPTION);
    }

    private void rejectToken(HttpServerExchange exchange, MsalAuthConfig config, String category,
                             String code, String message, String description) {
        logger.warn("Microsoft token validation failed category={}", category);
        // Cookie mutations must precede setExchangeStatus, which can commit the response.
        if (exchange.getRequestCookie(ACCESS_TOKEN) != null) {
            clearCookie(exchange, ACCESS_TOKEN, true, config);
            clearCookie(exchange, Constants.CSRF, false, config);
            exchange.getResponseHeaders().put(Headers.CACHE_CONTROL, "no-store");
        }
        rejectUnauthorized(exchange, code, message, description);
    }

    private boolean validateLogoutCsrf(HttpServerExchange exchange, MsalAuthConfig config) {
        if (exchange.getRequestCookie(ACCESS_TOKEN) == null && exchange.getRequestCookie(Constants.CSRF) == null) return true;
        String requestCsrf = null;
        try { requestCsrf = Csrf.request(exchange, config.getWebsocketAllowedOrigins()); }
        catch (IllegalArgumentException ignored) { }
        boolean missing = requestCsrf == null;
        if (!missing && Csrf.equal(requestCsrf, cookieValue(exchange, Constants.CSRF))
                && config.getSessionCsrf().verify(requestCsrf, cookieValue(exchange, ACCESS_TOKEN))) return true;
        if (Csrf.recoveryAllowed(exchange, config.getWebsocketAllowedOrigins())) return true;
        long count = LOGOUT_CSRF_WOULD_REJECT_COUNT.incrementAndGet();
        logger.info("event=spa_auth_logout_csrf_would_reject runtime=msal-auth endpoint=logout " +
                        "failure={} enforced={} count={} counterScope=process reset=process_restart",
                missing ? "header_missing" : "cookie_invalid", config.isLogoutCsrfEnforced(), count);
        // Cleanup alone can use browser provenance when old/partial sessions cannot prove a binding.
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

    static int cookieMaxAge(JwtClaims claims, int sessionTimeout) {
        try {
            if (claims.getExpirationTime() == null) return 0;
            long seconds = (claims.getExpirationTime().getValueInMillis() - System.currentTimeMillis()) / 1000;
            return (int) Math.max(0, Math.min(seconds, sessionTimeout));
        } catch (Exception e) {
            return 0;
        }
    }

    private static VerifierState ensureVerifierState(MsalAuthConfig msalConfig) {
        VerifierState state = verifierState;
        Map<String, Object> securitySource = Config.getInstance().getJsonMapConfig("security-msal");
        if (state != null && (state.testOverride || (state.config == msalConfig && state.securitySource == securitySource))) return state;
        synchronized (MsalAuthHandler.class) {
            state = verifierState;
            if (state == null || (!state.testOverride && (state.config != msalConfig || state.securitySource != securitySource))) {
                SecurityConfig config = SecurityConfig.load("security-msal");
                requireUncachedVerifier(config);
                state = new VerifierState(new MsalJwtVerifier(msalConfig.getJwksUri(), config.getClockSkewInSeconds()),
                        config.getClockSkewInSeconds(), msalConfig, securitySource, false);
                verifierState = state;
            }
            return state;
        }
    }

    static void installVerifierForTest(MsalTokenVerifier verifier) {
        verifierState = verifier == null ? null : new VerifierState(verifier,
                SecurityConfig.load("security-msal").getClockSkewInSeconds(), null, null, true);
    }

    static void requireUncachedVerifier(SecurityConfig config) {
        if (config.isEnableJwtCache())
            throw new IllegalArgumentException("msal-auth requires security-msal.enableJwtCache: false");
    }

    private static final class VerifierState {
        private final MsalTokenVerifier verifier;
        private final int clockSkewSeconds;
        private final MsalAuthConfig config;
        private final Map<String, Object> securitySource;
        private final boolean testOverride;

        private VerifierState(MsalTokenVerifier verifier, int clockSkewSeconds, MsalAuthConfig config,
                              Map<String, Object> securitySource, boolean testOverride) {
            this.verifier = verifier;
            this.clockSkewSeconds = clockSkewSeconds;
            this.config = config;
            this.securitySource = securitySource;
            this.testOverride = testOverride;
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
