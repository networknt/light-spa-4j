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
import com.networknt.utility.Constants;
import com.networknt.utility.ModuleRegistry;
import com.networknt.utility.UuidUtil;
import io.undertow.Handlers;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.Cookie;
import io.undertow.server.handlers.CookieImpl;
import io.undertow.server.handlers.CookieSameSiteMode;
import io.undertow.util.Headers;
import io.undertow.util.StatusCodes;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.ErrorCodeValidator;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MsalTokenExchangeHandler implements MiddlewareHandler {
    private static final Logger logger = LoggerFactory.getLogger(MsalTokenExchangeHandler.class);
    private static final String JWT_BEARER_TOKEN_MISSING = "ERR11000"; // New error code
    private static final String TOKEN_EXCHANGE_FAILED = "ERR11001"; // New error code
    private static final String INVALID_AUTH_TOKEN = "ERR10000";
    private static final String CSRF_HEADER_MISSING = "ERR10036";
    private static final String CSRF_TOKEN_MISSING_IN_JWT = "ERR10038";
    private static final String HEADER_CSRF_JWT_CSRF_NOT_MATCH = "ERR10039";

    private static final String ACCESS_TOKEN = "accessToken";
    private static final String REFRESH_TOKEN = "refreshToken";
    private static final String USER_TYPE = "userType";
    private static final String USER_ID = "userId";
    protected static final String SCOPES = "scopes";
    private static final String SCOPE = "scope";
    private static final String SCP = "scp";
    private static final String ROLE = "role";

    public static MsalExchangeConfig config =
            (MsalExchangeConfig)Config.getInstance().getJsonObjectConfig(MsalExchangeConfig.CONFIG_NAME, MsalExchangeConfig.class);

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

    public MsalTokenExchangeHandler() {
        logger.info("MsalTokenExchangeHandler is constructed.");
    }

    @Override
    public void handleRequest(final HttpServerExchange exchange) throws Exception {
        if (exchange.getRelativePath().equals(config.getExchangePath())) {
            // token exchange request handling.
            if(logger.isTraceEnabled()) logger.trace("MsalTokenExchangeHandler exchange is called.");

            String authHeader = exchange.getRequestHeaders().getFirst(Headers.AUTHORIZATION);
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                setExchangeStatus(exchange, JWT_BEARER_TOKEN_MISSING);
                return;
            }
            String microsoftToken = authHeader.substring(7);

            // --- Validate the incoming Microsoft Token ---
            if(msalJwtVerifier == null) {
                // handle case where config failed to load
                throw new Exception("MsalJwtVerifier is not initialized.");
            }
            try {
                // We only need to verify it, we don't need the claims for much.
                // The second provider will do its own validation and claim mapping.
                // Set skipAudienceVerification to true if the 'aud' doesn't match this BFF's client ID.
                String reqPath = exchange.getRequestPath();
                msalJwtVerifier.verifyJwt(microsoftToken, msalSecurityConfig.isIgnoreJwtExpiry(), true, null, reqPath, null);
            } catch (InvalidJwtException e) {
                logger.error("Microsoft token validation failed.", e);
                setExchangeStatus(exchange, INVALID_AUTH_TOKEN, e.getMessage());
                return;
            }

            // --- Perform Token Exchange ---
            String csrf = UuidUtil.uuidToBase64(UuidUtil.getUUID());
            TokenExchangeRequest request = new TokenExchangeRequest();
            request.setSubjectToken(microsoftToken);
            request.setSubjectTokenType("urn:ietf:params:oauth:token-type:jwt");
            request.setCsrf(csrf); // The CSRF for the *new* token we are getting

            Result<TokenResponse> result = OauthHelper.getTokenResult(request);
            if (result.isFailure()) {
                logger.error("Token exchange failed with status: {}", result.getError());
                setExchangeStatus(exchange, TOKEN_EXCHANGE_FAILED, result.getError().getDescription());
                return;
            }

            // --- The setCookies logic is identical ---
            List<String> scopes = setCookies(exchange, result.getResult(), csrf);
            if(logger.isTraceEnabled()) logger.trace("scopes = {}", scopes);

            exchange.setStatusCode(StatusCodes.OK);
            exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "application/json");
            // Return the scopes in the response body
            Map<String, Object> rs = new HashMap<>();
            rs.put(SCOPES, scopes);
            exchange.getResponseSender().send(JsonMapper.toJson(rs));
        } else if (exchange.getRelativePath().equals(config.getLogoutPath())) {
            // logout request handling, this is the same as StatelessAuthHandler to remove the cookies.
            if(logger.isTraceEnabled()) logger.trace("MsalTokenExchangeHandler logout is called.");
            removeCookies(exchange);
            exchange.endExchange();
        } else {
            // This is the subsequent request handling after the token exchange. Here we verify the JWT in the cookies.
            if(logger.isTraceEnabled()) logger.trace("MsalTokenExchangeHandler is called for subsequent request.");
            String jwt = null;
            Cookie cookie = exchange.getRequestCookie(ACCESS_TOKEN);
            if(cookie != null) {
                jwt = cookie.getValue();
                // verify the jwt with the internal verifier, the token is from the light-oauth token exchange.
                JwtClaims claims = internalJwtVerifier.verifyJwt(jwt, securityConfig.isIgnoreJwtExpiry(), true);
                String jwtCsrf = claims.getStringClaimValue(Constants.CSRF);
                // get csrf token from the header. Return error is it doesn't exist.
                String headerCsrf = exchange.getRequestHeaders().getFirst(HttpStringConstants.CSRF_TOKEN);
                if(headerCsrf == null || headerCsrf.trim().length() == 0) {
                    setExchangeStatus(exchange, CSRF_HEADER_MISSING);
                    return;
                }
                // verify csrf from jwt token in httpOnly cookie
                if(jwtCsrf == null || jwtCsrf.trim().length() == 0) {
                    setExchangeStatus(exchange, CSRF_TOKEN_MISSING_IN_JWT);
                    return;
                }
                if(logger.isDebugEnabled()) logger.debug("headerCsrf = " + headerCsrf + " jwtCsrf = " + jwtCsrf);
                if(!headerCsrf.equals(jwtCsrf)) {
                    setExchangeStatus(exchange, HEADER_CSRF_JWT_CSRF_NOT_MATCH, headerCsrf, jwtCsrf);
                    return;
                }
                // renew the token 1.5 minute before it is expired to keep the session if the user is still using it
                // regardless the refreshToken is long term remember me or not. The private message API access repeatedly
                // per minute will make the session continue until the browser tab is closed.
                if(claims.getExpirationTime().getValueInMillis() - System.currentTimeMillis() < 90000) {
                    jwt = renewToken(exchange, exchange.getRequestCookie(REFRESH_TOKEN));
                }
            } else {
                // renew the token and set the cookies
                jwt = renewToken(exchange, exchange.getRequestCookie(REFRESH_TOKEN));
            }
            if(logger.isTraceEnabled()) logger.trace("jwt = " + jwt);
            if(jwt != null) exchange.getRequestHeaders().put(Headers.AUTHORIZATION, "Bearer " + jwt);
            // if there is no jwt and refresh token available in the cookies, the user not logged in or
            // the session is expired. Or the endpoint that is trying to access doesn't need a token
            // for example, in the light-portal command side, createUser doesn't need a token. let it go
            // to the service and an error will be back if the service does require a token.
            // don't call the next handler if the exchange is completed in renewToken when error occurs.
            if(!exchange.isComplete()) Handler.next(exchange, next);
        }
    }

    // --- The following methods can be copied directly or moved to a shared utility class ---
    private String renewToken(HttpServerExchange exchange, Cookie cookie) throws Exception {
        String jwt = null;
        if(cookie != null) {
            String refreshToken = cookie.getValue();
            if(refreshToken != null) {
                TokenRequest tokenRequest = new RefreshTokenRequest();
                String csrf = UuidUtil.uuidToBase64(UuidUtil.getUUID());
                tokenRequest.setCsrf(csrf);
                ((RefreshTokenRequest) tokenRequest).setRefreshToken(refreshToken);
                Result<TokenResponse> result = OauthHelper.getTokenResult(tokenRequest);
                if(result.isSuccess()) {
                    TokenResponse response = result.getResult();
                    setCookies(exchange, response, csrf);
                    jwt = response.getAccessToken();
                } else {
                    if(logger.isDebugEnabled()) logger.debug("Failed to get the access token from refresh token with error: {}", result.getError());
                    // remove the cookies to log out the user
                    removeCookies(exchange);
                    exchange.endExchange();
                }
            }
        }
        return jwt;
    }

    private void removeCookies(final HttpServerExchange exchange) {
        // first get the cookie from the request.
        Cookie accessTokenCookie = exchange.getRequestCookie(ACCESS_TOKEN);
        if(accessTokenCookie != null) {
            accessTokenCookie.setMaxAge(0)
                    .setValue("")
                    .setDomain(config.cookieDomain)
                    .setPath(config.cookiePath)
                    .setHttpOnly(true)
                    .setSecure(config.cookieSecure);
            exchange.setResponseCookie(accessTokenCookie);
        }
        Cookie refreshTokenCookie = exchange.getRequestCookie(REFRESH_TOKEN);
        if(refreshTokenCookie != null) {
            refreshTokenCookie.setMaxAge(0)
                    .setValue("")
                    .setDomain(config.cookieDomain)
                    .setPath(config.cookiePath)
                    .setHttpOnly(true)
                    .setSecure(config.cookieSecure);
            exchange.setResponseCookie(refreshTokenCookie);
        }
        Cookie csrfCookie = exchange.getRequestCookie(Constants.CSRF);
        if(csrfCookie != null) {
            csrfCookie.setMaxAge(0)
                    .setValue("")
                    .setDomain(config.cookieDomain)
                    .setPath(config.cookiePath)
                    .setHttpOnly(true)
                    .setSecure(config.cookieSecure);
            exchange.setResponseCookie(csrfCookie);
        }
        // remove userId
        Cookie userIdCookie = exchange.getRequestCookie(USER_ID);
        if(userIdCookie != null) {
            userIdCookie.setMaxAge(0)
                    .setValue("")
                    .setDomain(config.cookieDomain)
                    .setPath(config.cookiePath)
                    .setHttpOnly(false)
                    .setSecure(config.cookieSecure);

            exchange.setResponseCookie(userIdCookie);
        }
        Cookie userTypeCookie = exchange.getRequestCookie(USER_TYPE);
        if(userTypeCookie != null) {
            userTypeCookie.setMaxAge(0)
                    .setValue("")
                    .setDomain(config.cookieDomain)
                    .setPath(config.cookiePath)
                    .setHttpOnly(false)
                    .setSecure(config.cookieSecure);
            exchange.setResponseCookie(userTypeCookie);
        }
        Cookie rolesCookie = exchange.getRequestCookie(Constants.ROLES);
        if(rolesCookie != null) {
            rolesCookie.setMaxAge(0)
                    .setValue("")
                    .setDomain(config.cookieDomain)
                    .setPath(config.cookiePath)
                    .setHttpOnly(false)
                    .setSecure(config.cookieSecure);
            exchange.setResponseCookie(rolesCookie);
        }
        Cookie hostCookie = exchange.getRequestCookie(Constants.HOST);
        if(hostCookie != null) {
            hostCookie.setMaxAge(0)
                    .setValue("")
                    .setDomain(config.cookieDomain)
                    .setPath(config.cookiePath)
                    .setHttpOnly(false)
                    .setSecure(config.cookieSecure);
            exchange.setResponseCookie(hostCookie);
        }
        Cookie emailCookie = exchange.getRequestCookie(Constants.EMAIL);
        if(emailCookie != null) {
            emailCookie.setMaxAge(0)
                    .setValue("")
                    .setDomain(config.cookieDomain)
                    .setPath(config.cookiePath)
                    .setHttpOnly(false)
                    .setSecure(config.cookieSecure);
            exchange.setResponseCookie(emailCookie);
        }
        Cookie eidCookie = exchange.getRequestCookie(Constants.EID);
        if(eidCookie != null) {
            eidCookie.setMaxAge(0)
                    .setValue("")
                    .setDomain(config.cookieDomain)
                    .setPath(config.cookiePath)
                    .setHttpOnly(false)
                    .setSecure(config.cookieSecure);
            exchange.setResponseCookie(eidCookie);
        }
    }

    protected List<String> setCookies(final HttpServerExchange exchange, TokenResponse response, String csrf) throws Exception {
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
                .setMaxAge((remember == null || remember.equals("N")) ? expiresIn : 7776000)  // 90 days if remember is "Y"
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
            exchange.setResponseCookie(new CookieImpl(Constants.ROLES, roles)
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
        return config.isEnabled();
    }

    @Override
    public void register() {
        ModuleRegistry.registerModule(MsalExchangeConfig.CONFIG_NAME, MsalExchangeConfig.class.getName(), Config.getNoneDecryptedInstance().getJsonMapConfigNoCache(MsalExchangeConfig.CONFIG_NAME), null);
    }
}