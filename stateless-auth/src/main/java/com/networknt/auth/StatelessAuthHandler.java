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

import com.networknt.audit.AuditHandler;
import com.networknt.client.oauth.*;
import com.networknt.config.Config;
import com.networknt.exception.ExpiredTokenException;
import com.networknt.handler.MiddlewareHandler;
import com.networknt.security.JwtHelper;
import com.networknt.status.Status;
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

import java.util.Deque;
import java.util.HashMap;
import java.util.Map;

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

    public static StatelessAuthConfig config =
            (StatelessAuthConfig)Config.getInstance().getJsonObjectConfig(CONFIG_NAME, StatelessAuthConfig.class);

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
            if(logger.isDebugEnabled()) logger.debug("code = " + code);
            // check if code is in the query parameter
            if(code == null || code.trim().length() == 0) {
                setExchangeStatus(exchange, AUTHORIZATION_CODE_MISSING);
                return;
            }
            // use the code and client_id, client_secret to get an access token in jwt format
            String csrf = Util.getUUID();
            TokenRequest request = new AuthorizationCodeRequest();
            ((AuthorizationCodeRequest) request).setAuthCode(code);
            request.setCsrf(csrf);
            TokenResponse response = OauthHelper.getToken(request);
            if(response != null && response.getAccessToken() == null) {
                // we don't have access token in the response. Must be a status object.
                exchange.setStatusCode(response.getStatusCode());
                exchange.getResponseSender().send(response.superString());
                logger.error(response.superString());
                return;
            }
            setCookies(exchange, response, csrf);
            if (config.getRedirectUri() != null && config.getRedirectUri().length() > 0) {
                exchange.setStatusCode(StatusCodes.FOUND);
                exchange.getResponseHeaders().put(Headers.LOCATION, config.getRedirectUri());
            } else {
                exchange.setStatusCode(StatusCodes.OK);
            }
            exchange.endExchange();
            return;
        } else {
            // first get the jwt token from httpOnly cookie sent by first step authentication
            String jwt = null;
            Map<String, Cookie> cookies = exchange.getRequestCookies();
            if(cookies != null) {
                Cookie cookie = cookies.get("accessToken");
                if(cookie != null) {
                    jwt = cookie.getValue();
                }
            }
            if(logger.isDebugEnabled()) logger.debug("jwt = " + jwt);
            // if jwt is null, return error.
            if(jwt == null || jwt.trim().length() == 0) {
                // this is session expired. Need to redirect to login page.
                exchange.setStatusCode(StatusCodes.FOUND);
                exchange.getResponseHeaders().put(Headers.LOCATION, config.getCookieTimeoutUri());
                exchange.endExchange();
                return;
            }

            // parse the access token.
            JwtClaims claims = null;
            boolean jwtExpired = false;
            try {
                // verify jwt format, signature and expiration
                claims = JwtHelper.verifyJwt(jwt, false);
                // save some jwt payload into the exchange attachment for AuditHandler if it enabled.
                Map<String, Object> auditInfo = exchange.getAttachment(AuditHandler.AUDIT_INFO);
                // In normal case, the auditInfo shouldn't be null as it is created by OpenApiHandler with
                // endpoint and swaggerOperation available. This handler will enrich the auditInfo.
                if(auditInfo == null) {
                    auditInfo = new HashMap<>();
                    exchange.putAttachment(AuditHandler.AUDIT_INFO, auditInfo);
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
                    claims = JwtHelper.verifyJwt(jwt, true);
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
            String headerCsrf = exchange.getRequestHeaders().getFirst(Constants.CSRF_TOKEN);
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
                Cookie cookie = cookies.get("refreshToken");
                if(cookie != null) {
                    String refreshToken = cookie.getValue();
                    if(logger.isDebugEnabled()) logger.debug("refreshToken = " + refreshToken + " csrf = " + csrf);
                    ((RefreshTokenRequest)tokenRequest).setRefreshToken(refreshToken);
                }
                TokenResponse response = OauthHelper.getToken(tokenRequest);
                if(response != null && response.getAccessToken() == null) {
                    // we don't have access token in the response. Must be a status object.
                    exchange.setStatusCode(response.getStatusCode());
                    exchange.getResponseSender().send(response.superString());
                    logger.error(response.superString());
                    return;
                }
                setCookies(exchange, response, csrf);
                // now let's go to the next handler. The cookies are set for this response already.
            }
            exchange.getRequestHeaders().put(Headers.AUTHORIZATION, "Bearer " + jwt);
            next.handleRequest(exchange);
        }
    }

    private void setCookies(final HttpServerExchange exchange, TokenResponse response, String csrf) throws Exception {
        String accessToken = response.getAccessToken();
        String refreshToken = response.getRefreshToken();
        long expiresIn = response.getExpiresIn();
        // parse the access token.
        JwtClaims claims = null;
        String jwtUserId, jwtUserType, jwtRoles;
        jwtUserId = jwtUserType = jwtRoles = null;
        try {
            claims = JwtHelper.verifyJwt(accessToken, true);
            jwtUserId = claims.getStringClaimValue(Constants.USER_ID_STRING);
            jwtUserType = claims.getStringClaimValue("user_type");
//            jwtRoles = claims.getStringClaimValue("roles");
            jwtRoles = String.join(",", claims.getStringListClaimValue("roles"));
        } catch (InvalidJwtException e) {
            logger.error("Exception: ", e);
            setExchangeStatus(exchange, INVALID_AUTH_TOKEN);
            return;
        }
        if(logger.isDebugEnabled()) logger.debug("accessToken = " + accessToken + " refreshToken = " + refreshToken + " expiresIn = " + expiresIn);
        // put all the info into a cookie object
        exchange.setResponseCookie(new CookieImpl("accessToken", accessToken)
                .setDomain(config.cookieDomain)
                .setPath(config.getCookiePath())
                .setMaxAge(config.cookieMaxAge)
                .setHttpOnly(true)
                .setSecure(config.cookieSecure));
        exchange.setResponseCookie(new CookieImpl("refreshToken", refreshToken)
                .setDomain(config.cookieDomain)
                .setPath(config.getCookiePath())
                .setMaxAge(config.cookieMaxAge)
                .setHttpOnly(true)
                .setSecure(config.cookieSecure));
        // this is user info in cookie and it is accessible for Javascript.
        exchange.setResponseCookie(new CookieImpl("userInfo", "userId:" + jwtUserId + ";userType:" + jwtUserType + ";roles:" + jwtRoles)
                .setDomain(config.cookieDomain)
                .setPath(config.cookiePath)
                .setMaxAge(config.cookieMaxAge)
                .setHttpOnly(false)
                .setSecure(config.cookieSecure));
        // this is another csrf token in cookie and it is accessible for Javascript.
        exchange.setResponseCookie(new CookieImpl(Constants.CSRF_STRING, csrf)
                .setDomain(config.cookieDomain)
                .setPath(config.cookiePath)
                .setMaxAge(config.cookieMaxAge)
                .setHttpOnly(false)
                .setSecure(config.cookieSecure));
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
