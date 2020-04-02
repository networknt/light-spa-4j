/*
 * Copyright (c) 2018 Network New Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.networknt.auth;

import com.networknt.client.oauth.*;
import com.networknt.config.Config;
import com.networknt.config.JsonMapper;
import com.networknt.handler.Handler;
import com.networknt.handler.MiddlewareHandler;
import com.networknt.httpstring.AttachmentConstants;
import com.networknt.httpstring.HttpStringConstants;
import com.networknt.monad.Result;
import com.networknt.security.JwtVerifier;
import com.networknt.status.Status;
import com.networknt.exception.ExpiredTokenException;
import com.networknt.utility.Constants;
import com.networknt.utility.ModuleRegistry;
import com.networknt.utility.Util;
import io.undertow.Handlers;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.Cookie;
import io.undertow.server.handlers.CookieImpl;
import io.undertow.util.Headers;
import io.undertow.util.StatusCodes;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * This is a handler that receives authorization code from OAuth 2.0 provider with authorization grant type.
 * It will take the redirected code and get JWT token along with client_id and client_secret defined in
 * client.yml and secret.yml config files. Once the tokens are received, they will be sent to the browser
 * with cookies immediately.
 *
 * This middleware handler must be place before StatelessCsrfHandler as the request doesn't have any CSRF
 * header yet. After this action, all subsequent requests from the browser will have jwt token in cookies
 * and CSRF token in headers.
 *
 * This handler get the access token and expiresIn from cookie. If the token is about to expire, renew it.
 * Next the access token will be parsed and put into the auditInfo object so that StatelessCsrfHandler can
 * compare the csrf token from the jwt with the one from header.
 *
 * This handler must be injected after StatelessAuthHandler and before StatelessCsrfHandler.
 *
 * If token does not exist or is not matched, an error will be returned. For the stateless SPA application,
 * the jwt access token is passed in a cookie instead of normal API to API calls with jwt token in Authorization
 * header.
 *
 * If the token is expired, it will use the refersh token to renew the access token and put both new access token
 * and refresh token into the response cookies in the same request.
 *
 * This is a handler that checks if CSRF token exists in the header for services exposed to Single Page
 * Application running on browsers. Normally, this handler only needs to be injected on the services in
 * the DMZ. For example aggregators or light-router to aggregate calls to multiple services or router
 * calls to multiple services from internal network.
 *
 * It compares the token from header to the token inside the JWT to ensure that it matches. If token does
 * not exist or is not matched, an error will be returned. For the stateless SPA application, the jwt
 * access token is passed in a cookie instead of normal API to API calls with jwt token in Authorization
 * header.
 *
 * This handler is a middleware handler and must be injected in service.yml if needed. When this handler
 * is used, you have to use StatelessAuthHandler to send the access token to the SPA running on the browser
 * in order to work.
 *
 * @author Steve Hu
 */
public class StatelessAuthHandler implements MiddlewareHandler {
    private static final Logger logger = LoggerFactory.getLogger(StatelessAuthHandler.class);
    private static final String CONFIG_NAME = "statelessAuth";
    private static final String CODE = "code";
    private static final String AUTHORIZATION_CODE_MISSING = "ERR10035";
    private static final String JWT_NOT_FOUND_IN_COOKIES = "ERR10040";
    private static final String INVALID_AUTH_TOKEN = "ERR10000";
    private static final String CSRF_HEADER_MISSING = "ERR10036";
    private static final String CSRF_TOKEN_MISSING_IN_JWT = "ERR10038";
    private static final String HEADER_CSRF_JWT_CSRF_NOT_MATCH = "ERR10039";
    private static final String REFRESH_TOKEN_RESPONSE_EMPTY = "ERR10037";
    private static final String OPENAPI_SECURITY_CONFIG = "openapi-security";
    private static final String SWAGGER_SECURITY_CONFIG = "swagger-security";
    private static final String GRAPHQL_SECURITY_CONFIG = "graphql-security";
    private static final String HYBRID_SECURITY_CONFIG = "hybrid-security";
    private static final String ACCESS_TOKEN = "accessToken";
    private static final String REFRESH_TOKEN = "refreshToken";
    private static final String USER_TYPE = "userType";
    private static final String USER_ID = "userId";
    private static final String SCOPES = "scopes";
    private static final String SCOPE = "scope";

    public static StatelessAuthConfig config =
            (StatelessAuthConfig)Config.getInstance().getJsonObjectConfig(CONFIG_NAME, StatelessAuthConfig.class);
    static Map<String, Object> securityConfig;
    static JwtVerifier jwtVerifier;
    static {
        // The SPA server can be based on OpenAPI, GraphQL or Hybrid, check if openapi-security.yml exists first
        securityConfig = Config.getInstance().getJsonMapConfig(OPENAPI_SECURITY_CONFIG);
        if(securityConfig == null) securityConfig = Config.getInstance().getJsonMapConfig(SWAGGER_SECURITY_CONFIG);
        if(securityConfig == null) securityConfig = Config.getInstance().getJsonMapConfig(GRAPHQL_SECURITY_CONFIG);
        if(securityConfig == null) securityConfig = Config.getInstance().getJsonMapConfig(HYBRID_SECURITY_CONFIG);
        // fallback to generic security.yml
        if(securityConfig == null) securityConfig = Config.getInstance().getJsonMapConfig(JwtVerifier.SECURITY_CONFIG);
        jwtVerifier = new JwtVerifier(securityConfig);
    }

    private volatile HttpHandler next;

    public StatelessAuthHandler() {
        logger.info("StatelessAuthHandler is constructed.");
    }

    @Override
    public void handleRequest(final HttpServerExchange exchange) throws Exception {
        // This handler only cares about /authorization path. Pass to the next handler if path is not matched.
        if(logger.isDebugEnabled()) logger.debug("exchange path = " + exchange.getRelativePath() + " config path = " + config.getAuthPath());

        if(exchange.getRelativePath().equals(config.getAuthPath())) {
            // first time authentication and return both access and refresh tokens in cookies
            Deque<String> deque = exchange.getQueryParameters().get(CODE);
            String code = deque == null ? null : deque.getFirst();
            if (logger.isDebugEnabled()) logger.debug("code = " + code);
            // check if code is in the query parameter
            if (code == null || code.trim().length() == 0) {
                setExchangeStatus(exchange, AUTHORIZATION_CODE_MISSING);
                return;
            }
            // use the code and client_id, client_secret to get an access token in jwt format
            String csrf = Util.getUUID();
            TokenRequest request = new AuthorizationCodeRequest();
            ((AuthorizationCodeRequest) request).setAuthCode(code);
            request.setCsrf(csrf);
            Result<TokenResponse> result = OauthHelper.getTokenResult(request);
            if (result.isFailure()) {
                Status status = result.getError();
                // we don't have access token in the response. Must be a status object.
                exchange.setStatusCode(status.getStatusCode());
                exchange.getResponseSender().send(status.toString());
                logger.error(status.toString());
                return;
            }
            List scopes = setCookies(exchange, result.getResult(), csrf);
            if (config.getRedirectUri() != null && config.getRedirectUri().length() > 0) {
                exchange.setStatusCode(StatusCodes.OK);
                Map<String, Object> rs = new HashMap<>();
                rs.put(SCOPES, scopes);
                // add redirectUri and denyUri to the returned json.
                rs.put("redirectUri", config.redirectUri);
                rs.put("denyUri", config.denyUri != null ? config.denyUri : config.redirectUri);
                exchange.getResponseSender().send(JsonMapper.toJson(rs));
            } else {
                exchange.setStatusCode(StatusCodes.OK);
                exchange.endExchange();
            }
            return;
        } else if (exchange.getRelativePath().equals(config.getLogoutPath())) {
            removeCookies(exchange);
            exchange.endExchange();
            return;
        } else {
            // first get the jwt token from httpOnly cookie sent by first step authentication
            String jwt = null;
            Map<String, Cookie> cookies = exchange.getRequestCookies();
            if(cookies != null) {
                Cookie cookie = cookies.get(ACCESS_TOKEN);
                if(cookie != null) {
                    jwt = cookie.getValue();
                }
            }
            if(logger.isDebugEnabled()) logger.debug("jwt = " + jwt);
            // if jwt is null, return error.
            if(jwt == null || jwt.trim().length() == 0) {
                // this is session expired. Or the endpoint that is trying to access doesn't need a token
                // for example, in the light-portal command side, createUser doesn't need a token. let it go
                // to the service and an error will be back if the service does require a token.
                Handler.next(exchange, next);
                return;
            }

            // parse the access token.
            JwtClaims claims = null;
            boolean jwtExpired = false;
            try {
                // verify jwt format, signature and expiration
                claims = jwtVerifier.verifyJwt(jwt, false, true);
                // save some jwt payload into the exchange attachment for AuditHandler if it enabled.
                Map<String, Object> auditInfo = exchange.getAttachment(AttachmentConstants.AUDIT_INFO);
                // In normal case, the auditInfo shouldn't be null as it is created by OpenApiHandler with
                // endpoint and swaggerOperation available. This handler will enrich the auditInfo.
                if(auditInfo == null) {
                    auditInfo = new HashMap<>();
                    exchange.putAttachment(AttachmentConstants.AUDIT_INFO, auditInfo);
                }
                auditInfo.put(Constants.CLIENT_ID_STRING, claims.getStringClaimValue(Constants.CLIENT_ID_STRING));
                auditInfo.put(Constants.USER_ID_STRING, claims.getStringClaimValue(Constants.USER_ID_STRING));
                auditInfo.put(Constants.SUBJECT_CLAIMS, claims);
            } catch (InvalidJwtException e) {
                logger.error("Exception: ", e);
                setExchangeStatus(exchange, INVALID_AUTH_TOKEN);
                return;
            } catch (ExpiredTokenException e) {
                jwtExpired = true;
            }
            String jwtCsrf = null;
            if(jwtExpired) {
                // renew the access token with refresh token first in this case.
                // first we need to double check the csrf token in header and csrf token in jwt are matched.
                try {
                    claims = jwtVerifier.verifyJwt(jwt, true, true);
                    jwtCsrf = claims.getStringClaimValue(Constants.CSRF_STRING);
                } catch (InvalidJwtException e) {
                    logger.error("Exception: ", e);
                    setExchangeStatus(exchange, INVALID_AUTH_TOKEN);
                    return;
                }
            } else {
                jwtCsrf = claims.getStringClaimValue(Constants.CSRF_STRING);
            }

            // verify the csrf token
            // get CSRF token from the header. Return error is it doesn't exist.
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
            // complete csrf token verification

            if(jwtExpired) {
                // renew token here. First need to get refersh token from cookie
                String csrf = Util.getUUID();
                TokenRequest tokenRequest = new RefreshTokenRequest();
                tokenRequest.setCsrf(csrf);
                Cookie cookie = cookies.get(REFRESH_TOKEN);
                if(cookie != null) {
                    String refreshToken = cookie.getValue();
                    if(logger.isDebugEnabled()) logger.debug("refreshToken = " + refreshToken + " csrf = " + csrf);
                    ((RefreshTokenRequest)tokenRequest).setRefreshToken(refreshToken);
                }
                Result<TokenResponse> result = OauthHelper.getTokenResult(tokenRequest);
                if(result.isFailure()) {
                    Status status = result.getError();
                    // we don't have access token in the response. Must be a status object.
                    exchange.setStatusCode(status.getStatusCode());
                    exchange.getResponseSender().send(status.toString());
                    logger.error(status.toString());
                    return;
                }
                TokenResponse response = result.getResult();
                setCookies(exchange, response, csrf);
                jwt = response.getAccessToken();
                // now let's go to the next handler. The cookies are set for this response already.
            }
            exchange.getRequestHeaders().put(Headers.AUTHORIZATION, "Bearer " + jwt);
            Handler.next(exchange, next);
        }
    }

    private void removeCookies(final HttpServerExchange exchange) {
        // first get the cookie from the request.
        Map<String, Cookie> cookies = exchange.getRequestCookies();
        if(cookies != null) {
            Cookie accessTokenCookie = cookies.get(ACCESS_TOKEN);
            if(accessTokenCookie != null) {
                accessTokenCookie.setMaxAge(0)
                        .setValue("")
                        .setDomain(config.cookieDomain)
                        .setPath(config.cookiePath)
                        .setHttpOnly(true)
                        .setSecure(config.cookieSecure);
                exchange.setResponseCookie(accessTokenCookie);
            }
            Cookie refreshTokenCookie = cookies.get(REFRESH_TOKEN);
            if(refreshTokenCookie != null) {
                refreshTokenCookie.setMaxAge(0)
                        .setValue("")
                        .setDomain(config.cookieDomain)
                        .setPath(config.cookiePath)
                        .setHttpOnly(true)
                        .setSecure(config.cookieSecure);
                exchange.setResponseCookie(refreshTokenCookie);
            }
            Cookie csrfCookie = cookies.get(Constants.CSRF_STRING);
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
            Cookie userIdCookie = cookies.get(USER_ID);
            if(userIdCookie != null) {
                userIdCookie.setMaxAge(0)
                        .setValue("")
                        .setDomain(config.cookieDomain)
                        .setPath(config.cookiePath)
                        .setHttpOnly(false)
                        .setSecure(config.cookieSecure);

                exchange.setResponseCookie(userIdCookie);
            }
            Cookie userTypeCookie = cookies.get(USER_TYPE);
            if(userTypeCookie != null) {
                userTypeCookie.setMaxAge(0)
                        .setValue("")
                        .setDomain(config.cookieDomain)
                        .setPath(config.cookiePath)
                        .setHttpOnly(false)
                        .setSecure(config.cookieSecure);
                exchange.setResponseCookie(userTypeCookie);
            }
            Cookie rolesCookie = cookies.get(Constants.ROLES_STRING);
            if(rolesCookie != null) {
                rolesCookie.setMaxAge(0)
                        .setValue("")
                        .setDomain(config.cookieDomain)
                        .setPath(config.cookiePath)
                        .setHttpOnly(false)
                        .setSecure(config.cookieSecure);
                exchange.setResponseCookie(rolesCookie);
            }
        }
    }

    private List<String> setCookies(final HttpServerExchange exchange, TokenResponse response, String csrf) throws Exception {
        String accessToken = response.getAccessToken();
        String refreshToken = response.getRefreshToken();
        // parse the access token.
        JwtClaims claims = null;
        String roles = null;
        String userType = null;
        String userId = null;
        // The scopes list is returned and will be part of the response.
        List<String> scopes = null;
        try {
            claims = jwtVerifier.verifyJwt(accessToken, true, true);
            roles = claims.getStringClaimValue(Constants.ROLES_STRING);
            userType = claims.getStringClaimValue(Constants.USER_TYPE_STRING);
            userId = claims.getStringClaimValue(Constants.USER_ID_STRING);
            scopes = claims.getStringListClaimValue(SCOPE);
        } catch (InvalidJwtException e) {
            logger.error("Exception: ", e);
            setExchangeStatus(exchange, INVALID_AUTH_TOKEN);
            return null;
        }

        // put all the info into a cookie object
        exchange.setResponseCookie(new CookieImpl(ACCESS_TOKEN, accessToken)
                .setDomain(config.cookieDomain)
                .setPath(config.getCookiePath())
                .setMaxAge(config.cookieMaxAge)
                .setHttpOnly(true)
                .setSecure(config.cookieSecure));
        exchange.setResponseCookie(new CookieImpl(REFRESH_TOKEN, refreshToken)
                .setDomain(config.cookieDomain)
                .setPath(config.getCookiePath())
                .setMaxAge(config.cookieMaxAge)
                .setHttpOnly(true)
                .setSecure(config.cookieSecure));
        // this is user info in cookie and it is accessible for Javascript.
        exchange.setResponseCookie(new CookieImpl(USER_ID, userId)
                .setDomain(config.cookieDomain)
                .setPath(config.cookiePath)
                .setMaxAge(config.cookieMaxAge)
                .setHttpOnly(false)
                .setSecure(config.cookieSecure));
        if(userType != null) {
            exchange.setResponseCookie(new CookieImpl(USER_TYPE, userType)
                    .setDomain(config.cookieDomain)
                    .setPath(config.cookiePath)
                    .setMaxAge(config.cookieMaxAge)
                    .setHttpOnly(false)
                    .setSecure(config.cookieSecure));
        }
        if(roles != null) {
            exchange.setResponseCookie(new CookieImpl(Constants.ROLES_STRING, roles)
                    .setDomain(config.cookieDomain)
                    .setPath(config.cookiePath)
                    .setMaxAge(config.cookieMaxAge)
                    .setHttpOnly(false)
                    .setSecure(config.cookieSecure));
        }
        // this is another csrf token in cookie and it is accessible for Javascript.
        exchange.setResponseCookie(new CookieImpl(Constants.CSRF_STRING, csrf)
                .setDomain(config.cookieDomain)
                .setPath(config.cookiePath)
                .setMaxAge(config.cookieMaxAge)
                .setHttpOnly(false)
                .setSecure(config.cookieSecure));
        return scopes;
    }

    @Override
    public HttpHandler getNext() {
        return next;
    }

    @Override
    public MiddlewareHandler setNext(final HttpHandler next) {
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
        ModuleRegistry.registerModule(StatelessAuthHandler.class.getName(), Config.getInstance().getJsonMapConfigNoCache(CONFIG_NAME), null);
    }

}
