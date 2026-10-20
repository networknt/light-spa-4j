package com.networknt.auth;

import com.networknt.client.oauth.*;
import com.networknt.config.Config;
import com.networknt.config.ConfigException;
import com.networknt.config.JsonMapper;
import com.networknt.handler.Handler;
import com.networknt.handler.MiddlewareHandler;
import com.networknt.httpstring.HttpStringConstants;
import com.networknt.monad.Result;
import com.networknt.security.JwtVerifier;
import com.networknt.security.SecurityConfig;
import com.networknt.security.VerificationException;
import com.networknt.utility.Constants;
import com.networknt.status.Status;
import com.networknt.auth.csrf.Csrf;
import io.undertow.Handlers;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.Cookie;
import io.undertow.server.handlers.CookieImpl;
import io.undertow.server.handlers.CookieSameSiteMode;
import io.undertow.util.Headers;
import io.undertow.util.HttpString;
import io.undertow.util.Methods;
import io.undertow.util.StatusCodes;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Handler for MSAL token exchange.
 * This handler exchanges a Microsoft token for an internal token and manages session cookies.
 *
 * @author Steve Hu
 */
public class MsalTokenExchangeHandler implements MiddlewareHandler {
    private static final Logger logger = LoggerFactory.getLogger(MsalTokenExchangeHandler.class);
    private static final String JWT_BEARER_TOKEN_MISSING = "ERR11647"; // New error code
    private static final String TOKEN_EXCHANGE_FAILED = "ERR11648"; // New error code
    private static final String INVALID_AUTH_TOKEN = "ERR10000";
    private static final String CSRF_HEADER_MISSING = "ERR10036";
    private static final String CSRF_TOKEN_MISSING_IN_JWT = "ERR10038";
    private static final String HEADER_CSRF_JWT_CSRF_NOT_MATCH = "ERR10039";
    private static final String LOGOUT_CSRF_INVALID = "ERR11649";
    private static final String METHOD_NOT_ALLOWED = "ERR10008";
    private static final String CACHE_CONTROL_NO_STORE = "no-store";
    private static final String POST_ONLY_ALLOW = Methods.POST_STRING;

    private static final AtomicLong LEGACY_EXCHANGE_GET_COUNT = new AtomicLong();
    private static final AtomicLong LEGACY_LOGOUT_GET_COUNT = new AtomicLong();
    private static final AtomicLong LOGOUT_CSRF_WOULD_REJECT_COUNT = new AtomicLong();

    private static final String ACCESS_TOKEN = "accessToken";
    private static final String REFRESH_TOKEN = "refreshToken";
    private static final String USER_TYPE = "userType";
    private static final String USER_ID = "userId";
    /**
     * The key for scopes in the response body.
     */
    protected static final String SCOPES = "scopes";
    private static final String SCOPE = "scope";
    private static final String SCP = "scp";
    private static final String ROLE = "role";


    // Two separate JwtVerifier instances ---
    static SecurityConfig securityConfig;
    static SecurityConfig msalSecurityConfig;
    static JwtVerifier internalJwtVerifier; // For tokens from your second provider (in cookies)
    static JwtVerifier msalJwtVerifier;     // For tokens from Microsoft for token exchange

    static {
        // Verifier for your internal tokens (from cookies)
        securityConfig = SecurityConfig.load();
        internalJwtVerifier = new JwtVerifier(securityConfig);

        // Verifier for incoming Microsoft tokens. Assumes a "msalJwt" section in security.yml
        try {
            msalSecurityConfig = SecurityConfig.load("security-msal");
            msalJwtVerifier = new JwtVerifier(msalSecurityConfig);
        } catch(ConfigException e) {
            logger.error("Failed to load msalJwt configuration from security.yml. Microsoft token validation will fail.", e);
            msalJwtVerifier = null;
        }
    }

    private volatile HttpHandler next;

    /**
     * Default constructor for MsalTokenExchangeHandler.
     */
    public MsalTokenExchangeHandler() {
        MsalExchangeConfig.load();
        logger.info("MsalTokenExchangeHandler is constructed.");
    }

    @Override
    public void handleRequest(final HttpServerExchange exchange) throws Exception {
        MsalExchangeConfig config = MsalExchangeConfig.load();
        if (Methods.OPTIONS.equals(exchange.getRequestMethod())) {
            Handler.next(exchange, next);
            return;
        }

        String reqPath = exchange.getRequestPath();
        MsalEndpoint endpoint = classifyEndpoint(exchange.getRelativePath(), config);
        if(endpoint != MsalEndpoint.OTHER) {
            if(Methods.OPTIONS.equals(exchange.getRequestMethod())) {
                Handler.next(exchange, next);
                return;
            }
            markNoStore(exchange);
            if(!Methods.POST.equals(exchange.getRequestMethod())) {
                if(Methods.GET.equals(exchange.getRequestMethod())) recordLegacyGet(endpoint);
                rejectMethod(exchange);
                return;
            }
        }
        if (endpoint == MsalEndpoint.EXCHANGE) {
            // token exchange request handling.
            if(logger.isTraceEnabled()) logger.trace("MsalTokenExchangeHandler exchange is called.");

            String microsoftToken = bearerToken(exchange);
            if (microsoftToken == null) {
                setExchangeStatus(exchange, JWT_BEARER_TOKEN_MISSING);
                return;
            }

            // --- Validate the incoming Microsoft ID token ---
            if(verifyMicrosoftToken(exchange, microsoftToken, reqPath) == null) return;

            String msalAccessToken = null;
            int msalAccessTokenMaxAge = config.getSessionTimeout();
            if(config.isAzureMsalAuthorization()) {
                msalAccessToken = bearerToken(exchange, config.getMsalAccessTokenHeader());
                if (msalAccessToken == null) {
                    setExchangeStatus(exchange, JWT_BEARER_TOKEN_MISSING);
                    return;
                }
                JwtClaims msalAccessTokenClaims = verifyMicrosoftToken(exchange, msalAccessToken, reqPath);
                if(msalAccessTokenClaims == null) return;
                msalAccessTokenMaxAge = accessTokenCookieMaxAge(msalAccessTokenClaims, config);
            }

            // --- Perform Token Exchange ---
            String csrf = Csrf.nonce();
            TokenExchangeRequest request = new TokenExchangeRequest();
            request.setSubjectToken(microsoftToken);
            request.setSubjectTokenType("urn:ietf:params:oauth:token-type:jwt");
            request.setCsrf(csrf); // The CSRF for the *new* token we are getting

            Result<TokenResponse> result = OauthHelper.getTokenFromTokenExchangeResult(request);
            if (result.isFailure()) {
                logger.error("Token exchange failed with status: {}", result.getError());
                setExchangeStatus(exchange, TOKEN_EXCHANGE_FAILED, result.getError().getDescription());
                return;
            }

            // --- The setCookies logic is identical ---
            List<String> scopes = setCookies(exchange, result.getResult(), csrf, config);
            if(msalAccessToken != null) {
                setMsalAccessTokenCookie(exchange, msalAccessToken, msalAccessTokenMaxAge, config);
            }
            if(logger.isTraceEnabled()) logger.trace("scopes = {}", scopes);

            exchange.setStatusCode(StatusCodes.OK);
            exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "application/json");
            // Return the scopes in the response body
            Map<String, Object> rs = new HashMap<>();
            rs.put(SCOPES, scopes);
            exchange.getResponseSender().send(JsonMapper.toJson(rs));
        } else if (endpoint == MsalEndpoint.LOGOUT) {
            // logout request handling, this is the same as StatelessAuthHandler to remove the cookies.
            if(logger.isTraceEnabled()) logger.trace("MsalTokenExchangeHandler logout is called.");
            if(!validateLogoutCsrf(exchange, config)) return;
            removeCookies(exchange, config);
            exchange.setStatusCode(StatusCodes.NO_CONTENT);
            exchange.endExchange();
        } else {
            Cookie sessionAccess = exchange.getRequestCookie(ACCESS_TOKEN);
            if ((sessionAccess == null || sessionAccess.getValue() == null || sessionAccess.getValue().isBlank())
                    && exchange.getRequestCookie(REFRESH_TOKEN) != null) {
                recoverSession(exchange, config);
                return;
            }

            // This is the subsequent request handling after the token exchange. Here we verify the JWT in the cookies.
            if(logger.isTraceEnabled()) logger.trace("MsalTokenExchangeHandler is called for subsequent request.");
            boolean hasSessionCookie = exchange.getRequestCookie(ACCESS_TOKEN) != null || exchange.getRequestCookie(REFRESH_TOKEN) != null;
            String microsoftAccessToken = null;
            if(config.isAzureMsalAuthorization() && hasSessionCookie) {
                Cookie msalAccessTokenCookie = exchange.getRequestCookie(config.getMsalAccessTokenCookie());
                if (msalAccessTokenCookie == null || msalAccessTokenCookie.getValue() == null || msalAccessTokenCookie.getValue().trim().length() == 0) {
                    setExchangeStatus(exchange, JWT_BEARER_TOKEN_MISSING);
                    return;
                }
                String msalAccessToken = msalAccessTokenCookie.getValue();
                if(verifyMicrosoftToken(exchange, msalAccessToken, reqPath) == null) return;
                microsoftAccessToken = msalAccessToken;
            }
            String jwt = null;
            Cookie cookie = exchange.getRequestCookie(ACCESS_TOKEN);
            if(cookie != null) {
                jwt = cookie.getValue();
                // verify the jwt with the internal verifier, the token is from the light-oauth token exchange.
                JwtClaims claims = internalJwtVerifier.verifyJwt(jwt, securityConfig.isIgnoreJwtExpiry(), true, null, reqPath, null);
                String jwtCsrf = claims.getStringClaimValue(Constants.CSRF);
                String headerCsrf;
                try { headerCsrf = Csrf.request(exchange, config.getWebsocketAllowedOrigins(), exchange.getRequestCookie(Constants.CSRF) == null ? null : exchange.getRequestCookie(Constants.CSRF).getValue()); }
                catch (IllegalArgumentException e) { rejectCsrf(exchange, Csrf.code(e)); return; }
                // verify csrf from jwt token in httpOnly cookie
                if(jwtCsrf == null || jwtCsrf.trim().length() == 0) {
                    rejectCsrf(exchange, CSRF_TOKEN_MISSING_IN_JWT);
                    return;
                }
                if(!Csrf.equal(headerCsrf, jwtCsrf)) {
                    rejectCsrf(exchange, HEADER_CSRF_JWT_CSRF_NOT_MATCH);
                    return;
                }
                // renew the token 1.5 minute before it is expired to keep the session if the user is still using it
                // regardless the refreshToken is long term remember me or not. The private message API access repeatedly
                // per minute will make the session continue until the browser tab is closed.
                if(claims.getExpirationTime().getValueInMillis() - System.currentTimeMillis() < 90000) {
                    jwt = renewToken(exchange, exchange.getRequestCookie(REFRESH_TOKEN), config, jwtCsrf);
                }
            }
            if (exchange.isComplete()) return;
            if (microsoftAccessToken != null) injectMsalAuthorization(exchange, microsoftAccessToken);
            if(jwt != null) injectLightOauthToken(exchange, jwt, config);
            // if there is no jwt and refresh token available in the cookies, the user not logged in or
            // the session is expired. Or the endpoint that is trying to access doesn't need a token
            // for example, in the light-portal command side, createUser doesn't need a token. let it go
            // to the service and an error will be back if the service does require a token.
            // don't call the next handler if the exchange is completed in renewToken when error occurs.
            if(!exchange.isComplete()) Handler.next(exchange, next);
        }
    }

    private MsalEndpoint classifyEndpoint(String relativePath, MsalExchangeConfig config) {
        if (relativePath.equals(config.getExchangePath())) return MsalEndpoint.EXCHANGE;
        if (relativePath.equals(config.getLogoutPath())) return MsalEndpoint.LOGOUT;
        return MsalEndpoint.OTHER;
    }

    private void rejectMethod(HttpServerExchange exchange) {
        exchange.getResponseHeaders().put(Headers.ALLOW, POST_ONLY_ALLOW);
        setExchangeStatus(exchange, METHOD_NOT_ALLOWED,
                exchange.getRequestMethod().toString(), exchange.getRelativePath());
    }

    private void markNoStore(HttpServerExchange exchange) {
        exchange.getResponseHeaders().put(Headers.CACHE_CONTROL, CACHE_CONTROL_NO_STORE);
    }

    private void recordLegacyGet(MsalEndpoint endpoint) {
        AtomicLong counter = endpoint == MsalEndpoint.EXCHANGE
                ? LEGACY_EXCHANGE_GET_COUNT : LEGACY_LOGOUT_GET_COUNT;
        long count = counter.incrementAndGet();
        logger.info("event=spa_auth_legacy_method runtime=msal-exchange endpoint={} " +
                        "method=GET count={} counterScope=process reset=process_restart",
                endpoint.telemetryName, count);
        if((count & (count - 1)) == 0) {
            logger.warn("Deprecated MSAL endpoint method observed: endpoint={}, method=GET, count={}",
                    endpoint.telemetryName, count);
        }
    }

    static long legacyGetCount(String endpoint) {
        return "exchange".equals(endpoint)
                ? LEGACY_EXCHANGE_GET_COUNT.get() : LEGACY_LOGOUT_GET_COUNT.get();
    }

    static long logoutCsrfWouldRejectCount() {
        return LOGOUT_CSRF_WOULD_REJECT_COUNT.get();
    }

    private boolean validateLogoutCsrf(HttpServerExchange exchange, MsalExchangeConfig config) {
        if(!hasOwnedSessionCookie(exchange, config)) return true;

        String headerCsrf = null;
        try { headerCsrf = Csrf.request(exchange, config.getWebsocketAllowedOrigins()); }
        catch (IllegalArgumentException ignored) { }
        boolean headerMissing = headerCsrf == null;
        boolean valid = false;
        if (!headerMissing) {
            try {
                Cookie access = exchange.getRequestCookie(ACCESS_TOKEN);
                Cookie csrf = exchange.getRequestCookie(Constants.CSRF);
                if (access != null && csrf != null && Csrf.equal(headerCsrf, csrf.getValue())) {
                    // Expiry relaxation is limited to cleanup of a signed, bound session.
                    JwtClaims claims = internalJwtVerifier.verifyJwt(access.getValue(), true, true);
                    valid = Csrf.equal(headerCsrf, claims.getStringClaimValue(Constants.CSRF));
                }
            } catch (Exception ignored) { /* Invalid/partial sessions fail closed without credential diagnostics. */ }
        }
        if (valid) return true;
        if (Csrf.recoveryAllowed(exchange, config.getWebsocketAllowedOrigins())) return true;
        long count = LOGOUT_CSRF_WOULD_REJECT_COUNT.incrementAndGet();
        String failure = headerMissing ? "header_missing" : "cookie_invalid";
        logger.info("event=spa_auth_logout_csrf_would_reject runtime=msal-exchange endpoint=logout " +
                        "failure={} enforced={} count={} counterScope=process reset=process_restart",
                failure, config.isLogoutCsrfEnforced(), count);
        if(!config.isLogoutCsrfEnforced()) return true;

        setExchangeStatus(exchange, headerMissing ? CSRF_HEADER_MISSING : LOGOUT_CSRF_INVALID);
        return false;
    }

    private boolean hasOwnedSessionCookie(HttpServerExchange exchange, MsalExchangeConfig config) {
        for(String name : new String[]{ACCESS_TOKEN, REFRESH_TOKEN, Constants.CSRF, USER_ID, USER_TYPE,
                Constants.ROLES, Constants.HOST, Constants.EMAIL, Constants.EID,
                config.getMsalAccessTokenCookie()}) {
            if(exchange.getRequestCookie(name) != null) return true;
        }
        return false;
    }

    private String bearerToken(final HttpServerExchange exchange) {
        return bearerToken(exchange, Headers.AUTHORIZATION.toString());
    }

    private String bearerToken(final HttpServerExchange exchange, String headerName) {
        String authHeader = exchange.getRequestHeaders().getFirst(headerName);
        if (authHeader == null) return null;
        int space = authHeader.indexOf(' ');
        if (space <= 0) return null;
        String scheme = authHeader.substring(0, space);
        String token = authHeader.substring(space + 1).trim();
        if (!"Bearer".equalsIgnoreCase(scheme) || token.length() == 0) return null;
        return token;
    }

    private JwtClaims verifyMicrosoftToken(final HttpServerExchange exchange, String microsoftToken, String reqPath) throws Exception {
        if(msalJwtVerifier == null) {
            // handle case where config failed to load
            throw new Exception("MsalJwtVerifier is not initialized.");
        }
        try {
            // We only need to verify it, we don't need the claims for much.
            // The second provider will do its own validation and claim mapping.
            // Set skipAudienceVerification to true if the 'aud' doesn't match this BFF's client ID.
            return msalJwtVerifier.verifyJwt(microsoftToken, msalSecurityConfig.isIgnoreJwtExpiry(), true, null, reqPath, null);
        } catch (InvalidJwtException | VerificationException e) {
            logger.error("Microsoft token validation failed.", e);
            setExchangeStatus(exchange, INVALID_AUTH_TOKEN, e.getMessage());
            return null;
        }
    }

    private void injectMsalAuthorization(final HttpServerExchange exchange, String microsoftToken) {
        exchange.getRequestHeaders().put(Headers.AUTHORIZATION, "Bearer " + microsoftToken);
    }

    private void injectLightOauthToken(final HttpServerExchange exchange, String jwt, MsalExchangeConfig config) {
        if(config.isAzureMsalAuthorization()) {
            exchange.getRequestHeaders().put(new HttpString(config.getLightTokenHeader()), "Bearer " + jwt);
        } else {
            exchange.getRequestHeaders().put(Headers.AUTHORIZATION, "Bearer " + jwt);
        }
    }

    // --- The following methods can be copied directly or moved to a shared utility class ---
    private void rejectCsrf(HttpServerExchange exchange, String code) {
        setExchangeStatus(exchange, new Status(StatusCodes.UNAUTHORIZED, code, "CSRF_VALIDATION_FAILED",
                "Missing or invalid session-bound CSRF value or transport"));
    }

    private void sessionRefreshed(HttpServerExchange exchange) {
        exchange.getResponseHeaders().put(Headers.CACHE_CONTROL, "no-store");
        exchange.getResponseHeaders().put(new HttpString("X-Session-Refreshed"), "true");
        setExchangeStatus(exchange, new Status(StatusCodes.UNAUTHORIZED, "ERR10000", "SESSION_REFRESHED",
                "Session cookies refreshed. Retry explicitly with the new CSRF cookie; the request was not executed."));
    }

    private void recoverSession(HttpServerExchange exchange, MsalExchangeConfig config) throws Exception {
        if (!Csrf.recoveryAllowed(exchange, config.getWebsocketAllowedOrigins())) {
            rejectCsrf(exchange, "ERR10039");
            return;
        }
        exchange.getResponseHeaders().put(Headers.CACHE_CONTROL, "no-store");
        try {
            var result = RefreshTokenSingleFlight.recover(exchange.getRequestCookie(REFRESH_TOKEN).getValue(), logger);
            if (result.isSuccess()) {
                setCookies(exchange, result.getResponse(), result.getCsrf(), config);
                if (!exchange.isComplete()) sessionRefreshed(exchange);
                return;
            }
        } catch (Exception ignored) { /* Clear failed recovery without exposing credentials. */ }
        removeCookies(exchange, config);
        setExchangeStatus(exchange, new Status(StatusCodes.UNAUTHORIZED, "ERR10000", "INVALID_AUTH_TOKEN",
                "Session recovery failed. Sign in again."));
    }

    private String renewToken(HttpServerExchange exchange, Cookie cookie, MsalExchangeConfig config, String verifiedCsrf) throws Exception {
        String jwt = null;
        if(cookie != null) {
            String refreshToken = cookie.getValue();
            if(refreshToken != null) {
                RefreshTokenSingleFlight.RefreshResult result = RefreshTokenSingleFlight.renew(refreshToken, verifiedCsrf, logger);
                if(result.isSuccess()) {
                    TokenResponse response = result.getResponse();
                    setCookies(exchange, response, result.getCsrf(), config);
                    if (!Csrf.equal(verifiedCsrf, result.getCsrf())) {
                        sessionRefreshed(exchange);
                        return null;
                    }
                    jwt = response.getAccessToken();
                } else {
                    if(logger.isDebugEnabled()) logger.debug("Failed to get the access token from refresh token with error: {}", result.getError());
                    // remove the cookies to log out the user
                    removeCookies(exchange, config);
                    exchange.endExchange();
                }
            }
        }
        return jwt;
    }

    private int accessTokenCookieMaxAge(JwtClaims claims, MsalExchangeConfig config) throws Exception {
        if(claims.getExpirationTime() == null) return config.getSessionTimeout();
        long seconds = (claims.getExpirationTime().getValueInMillis() - System.currentTimeMillis()) / 1000;
        if(seconds <= 0) return config.getSessionTimeout();
        return (int)Math.min(seconds, config.getSessionTimeout());
    }

    private void setMsalAccessTokenCookie(final HttpServerExchange exchange, String msalAccessToken, int maxAge, MsalExchangeConfig config) {
        exchange.setResponseCookie(new CookieImpl(config.getMsalAccessTokenCookie(), msalAccessToken)
                .setDomain(config.cookieDomain)
                .setPath(config.getCookiePath())
                .setMaxAge(maxAge)
                .setHttpOnly(true)
                .setSameSiteMode(CookieSameSiteMode.NONE.toString())
                .setSecure(config.cookieSecure));
    }

    private void removeCookies(final HttpServerExchange exchange, MsalExchangeConfig config) {
        clearCookie(exchange, ACCESS_TOKEN, true, config);
        clearCookie(exchange, REFRESH_TOKEN, true, config);
        clearCookie(exchange, Constants.CSRF, false, config);
        clearCookie(exchange, USER_ID, false, config);
        clearCookie(exchange, USER_TYPE, false, config);
        clearCookie(exchange, Constants.ROLES, false, config);
        clearCookie(exchange, Constants.HOST, false, config);
        clearCookie(exchange, Constants.EMAIL, false, config);
        clearCookie(exchange, Constants.EID, false, config);
        clearCookie(exchange, config.getMsalAccessTokenCookie(), true, config);
    }

    private void clearCookie(HttpServerExchange exchange, String name, boolean httpOnly,
                             MsalExchangeConfig config) {
        // Emit every owned deletion cookie even when it was absent from the request, matching Rust.
        exchange.setResponseCookie(new CookieImpl(name, "")
                .setMaxAge(0)
                .setDomain(config.cookieDomain)
                .setPath(config.cookiePath)
                .setHttpOnly(httpOnly)
                .setSameSiteMode(CookieSameSiteMode.NONE.toString())
                .setSecure(config.cookieSecure));
    }

    /**
     * Sets session cookies based on the token response.
     *
     * @param exchange the HttpServerExchange
     * @param response the TokenResponse
     * @param csrf the CSRF token
     * @param config the MsalExchangeConfig
     * @return a list of scopes from the access token
     * @throws Exception if cookie setting fails
     */
    protected List<String> setCookies(final HttpServerExchange exchange, TokenResponse response, String csrf, MsalExchangeConfig config) throws Exception {
        String accessToken = response.getAccessToken();
        String refreshToken = response.getRefreshToken();
        String remember = response.getRemember();
        int expiresIn = (int)response.getExpiresIn(); // used to set the cookie max age so that there is no chance for expired jwt.
        // parse the access token.
        JwtClaims claims = null;
        String roles = null;
        String userType = null;
        String userId = null;
        String eid = null;
        String host = null;
        String email = null;
        // The scopes list is returned and will be part of the response.
        List<String> scopes = null;
        try {
            JwtContext context = internalJwtVerifier.parseJwt(accessToken);
            claims = context.getJwtClaims();
            roles = claims.getStringClaimValue(ROLE);
            if(roles == null) {
                roles = "user"; // default role for all authenticated users.
            }
            userType = claims.getStringClaimValue(Constants.USER_TYPE);
            userId = claims.getStringClaimValue(Constants.UID);
            eid = claims.getStringClaimValue(Constants.EID);
            scopes = claims.getStringListClaimValue(SCP);
            host = claims.getStringClaimValue(Constants.HOST);
            email = claims.getStringClaimValue(Constants.EML);
        } catch (InvalidJwtException e) {
            logger.error("Exception: ", e);
            setExchangeStatus(exchange, INVALID_AUTH_TOKEN);
            return null;
        }

        // put all the info into a cookie object
        exchange.setResponseCookie(new CookieImpl(ACCESS_TOKEN, accessToken)
                .setDomain(config.cookieDomain)
                .setPath(config.getCookiePath())
                .setMaxAge(expiresIn)
                .setHttpOnly(true)
                .setSameSiteMode(CookieSameSiteMode.NONE.toString())
                .setSecure(config.cookieSecure));
        exchange.setResponseCookie(new CookieImpl(REFRESH_TOKEN, refreshToken)
                .setDomain(config.cookieDomain)
                .setPath(config.getCookiePath())
                .setMaxAge((remember == null || remember.equals("N")) ? config.getSessionTimeout() : config.getRememberMeTimeout())
                .setHttpOnly(true)
                .setSameSiteMode(CookieSameSiteMode.NONE.toString())
                .setSecure(config.cookieSecure));
        // this is user info in cookie, and it is accessible for Javascript.
        exchange.setResponseCookie(new CookieImpl(USER_ID, userId)
                .setDomain(config.cookieDomain)
                .setPath(config.cookiePath)
                .setMaxAge(expiresIn)
                .setHttpOnly(false)
                .setSameSiteMode(CookieSameSiteMode.NONE.toString())
                .setSecure(config.cookieSecure));
        if(userType != null) {
            exchange.setResponseCookie(new CookieImpl(USER_TYPE, userType)
                    .setDomain(config.cookieDomain)
                    .setPath(config.cookiePath)
                    .setMaxAge(expiresIn)
                    .setHttpOnly(false)
                    .setSameSiteMode(CookieSameSiteMode.NONE.toString())
                    .setSecure(config.cookieSecure));
        }
        if(roles != null) {
            exchange.setResponseCookie(new CookieImpl(Constants.ROLES, Base64.getEncoder().encodeToString(roles.getBytes(StandardCharsets.UTF_8)))
                    .setDomain(config.cookieDomain)
                    .setPath(config.cookiePath)
                    .setMaxAge(expiresIn)
                    .setHttpOnly(false)
                    .setSameSiteMode(CookieSameSiteMode.NONE.toString())
                    .setSecure(config.cookieSecure));
        }
        if(host != null) {
            exchange.setResponseCookie(new CookieImpl(Constants.HOST, host)
                    .setDomain(config.cookieDomain)
                    .setPath(config.cookiePath)
                    .setMaxAge(expiresIn)
                    .setHttpOnly(false)
                    .setSameSiteMode(CookieSameSiteMode.NONE.toString())
                    .setSecure(config.cookieSecure));
        }
        if(email != null) {
            exchange.setResponseCookie(new CookieImpl(Constants.EMAIL, email)
                    .setDomain(config.cookieDomain)
                    .setPath(config.cookiePath)
                    .setMaxAge(expiresIn)
                    .setHttpOnly(false)
                    .setSameSiteMode(CookieSameSiteMode.NONE.toString())
                    .setSecure(config.cookieSecure));
        }
        if(eid != null) {
            exchange.setResponseCookie(new CookieImpl(Constants.EID, eid)
                    .setDomain(config.cookieDomain)
                    .setPath(config.cookiePath)
                    .setMaxAge(expiresIn)
                    .setHttpOnly(false)
                    .setSameSiteMode(CookieSameSiteMode.NONE.toString())
                    .setSecure(config.cookieSecure));
        }

        // this is another csrf token in cookie, and it is accessible for Javascript.
        exchange.setResponseCookie(new CookieImpl(Constants.CSRF, csrf)
                .setDomain(config.cookieDomain)
                .setPath(config.cookiePath)
                .setMaxAge(expiresIn)
                .setHttpOnly(false)
                .setSameSiteMode(CookieSameSiteMode.NONE.toString())
                .setSecure(config.cookieSecure));
        return scopes;
    }

    @Override
    public HttpHandler getNext() {
        return next;
    }

    @Override
    public MiddlewareHandler setNext(HttpHandler next) {
        Handlers.handlerNotNull(next);
        this.next = next;
        return this;
    }

    @Override
    public boolean isEnabled() {
        return MsalExchangeConfig.load().isEnabled();
    }

    private enum MsalEndpoint {
        EXCHANGE("exchange"), LOGOUT("logout"), OTHER("other");

        private final String telemetryName;

        MsalEndpoint(String telemetryName) {
            this.telemetryName = telemetryName;
        }
    }

}
