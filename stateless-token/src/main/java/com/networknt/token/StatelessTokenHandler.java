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

package com.networknt.token;

import com.networknt.audit.AuditHandler;
import com.networknt.config.Config;
import com.networknt.exception.ExpiredTokenException;
import com.networknt.handler.MiddlewareHandler;
import com.networknt.security.JwtHelper;
import com.networknt.status.Status;
import com.networknt.utility.Constants;
import com.networknt.utility.ModuleRegistry;
import io.undertow.Handlers;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.Cookie;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

/**
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
 * @author Steve Hu
 */
public class StatelessTokenHandler implements MiddlewareHandler {
    private static final Logger logger = LoggerFactory.getLogger(StatelessTokenHandler.class);
    private static final String CONFIG_NAME = "statelessToken";
    private static final String JWT_NOT_FOUND_IN_COOKIES = "ERR10040";
    private static final String INVALID_AUTH_TOKEN = "ERR10000";
    private static final String AUTH_TOKEN_EXPIRED = "ERR10001";


    public static StatelessTokenConfig config = (StatelessTokenConfig)Config.getInstance().getJsonObjectConfig(CONFIG_NAME, StatelessTokenConfig.class);

    private volatile HttpHandler next;

    public StatelessTokenHandler() {
        logger.info("StatelessTokenHandler is constructed");
    }

    @Override
    public void handleRequest(final HttpServerExchange exchange) throws Exception {
        if(logger.isDebugEnabled()) logger.debug("StatelessTokenHandler.handleRequest is called.");
        // first get the jwt token from httpOnly cookie sent by StatelessAuthHandler
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
            Status status = new Status(JWT_NOT_FOUND_IN_COOKIES);
            exchange.setStatusCode(status.getStatusCode());
            exchange.getResponseSender().send(status.toString());
            logger.error("ValidationError:" + status.toString());
            return;
        }
        // parse the access token.
        try {
            JwtClaims claims = JwtHelper.verifyJwt(jwt);
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
            // only log it and unauthorized is returned.
            logger.error("Exception: ", e);
            Status status = new Status(INVALID_AUTH_TOKEN);
            exchange.setStatusCode(status.getStatusCode());
            logger.error("Error in JwtVerifyHandler: " + status.toString());
            exchange.getResponseSender().send(status.toString());
            return;
        } catch (ExpiredTokenException e) {
            Status status = new Status(AUTH_TOKEN_EXPIRED);
            exchange.setStatusCode(status.getStatusCode());
            logger.error("Error in JwtVerifyHandler: " + status.toString());
            exchange.getResponseSender().send(status.toString());
            return;
        }
        next.handleRequest(exchange);
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
        ModuleRegistry.registerModule(StatelessTokenHandler.class.getName(), Config.getInstance().getJsonMapConfigNoCache(CONFIG_NAME), null);
    }
}
