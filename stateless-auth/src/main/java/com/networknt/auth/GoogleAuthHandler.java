package com.networknt.auth;

import com.google.api.client.googleapis.auth.oauth2.*;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.networknt.client.oauth.*;
import com.networknt.config.Config;
import com.networknt.config.JsonMapper;
import com.networknt.handler.MiddlewareHandler;
import com.networknt.monad.Result;
import com.networknt.status.Status;
import com.networknt.utility.StringUtils;
import com.networknt.utility.Util;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.StatusCodes;
import net.lightapi.portal.HybridCommandClient;
import net.lightapi.portal.HybridQueryClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.*;

public class GoogleAuthHandler extends StatelessAuthHandler implements MiddlewareHandler {
    private static final Logger logger = LoggerFactory.getLogger(GoogleAuthHandler.class);
    private static final String CODE = "code";
    private static final String AUTHORIZATION_CODE_MISSING = "ERR10035";
    public static StatelessAuthConfig config =
            (StatelessAuthConfig) Config.getInstance().getJsonObjectConfig(StatelessAuthConfig.CONFIG_NAME, StatelessAuthConfig.class);


    @Override
    public void handleRequest(final HttpServerExchange exchange) throws Exception {
        // This handler only cares about /google path. Pass to the next handler if path is not matched.
        if (logger.isDebugEnabled())
            logger.debug("exchange path = " + exchange.getRelativePath() + " config path = " + config.getGooglePath());
        if(exchange.getRelativePath().equals(config.getGooglePath())) {
            Deque<String> deque = exchange.getQueryParameters().get(CODE);
            String code = deque == null ? null : deque.getFirst();
            if (logger.isDebugEnabled()) logger.debug("auth code = " + code);
            // check if code is in the query parameter
            if (code == null || code.trim().length() == 0) {
                setExchangeStatus(exchange, AUTHORIZATION_CODE_MISSING);
                return;
            }

            GoogleTokenResponse tokenResponse =
                    new GoogleAuthorizationCodeTokenRequest(
                            new NetHttpTransport(),
                            JacksonFactory.getDefaultInstance(),
                            "https://oauth2.googleapis.com/token",
                            config.getGoogleClientId(),
                            config.getGoogleClientSecret(),
                            code,
                            config.getGoogleRedirectUri())
                            .execute();
            GoogleIdToken idToken = tokenResponse.parseIdToken();
            GoogleIdToken.Payload payload = idToken.getPayload();
            String email = payload.getEmail();
            boolean emailVerified = Boolean.valueOf(payload.getEmailVerified());
            String name = (String) payload.get("name");
            String userId = name.replaceAll("\\s+","") + "@go";
            String familyName = (String) payload.get("family_name");
            String givenName = (String) payload.get("given_name");
            Result<String> resultUser = HybridQueryClient.getUserByEmail(email, config.getBootstrapToken());
            if(resultUser.isFailure()) {
                // create a social user
                Map<String, Object> map = new HashMap<>();
                map.put("host", "lightapi.net");
                map.put("email", email);
                map.put("userId", userId);
                map.put("language", "en");
                map.put("firstName", givenName);
                map.put("lastName", familyName);
                Result<String> result = HybridCommandClient.createSocialUser(map, config.getBootstrapToken());
            }
            String csrf = Util.getUUID();
            TokenRequest request = new ClientAuthenticatedUserRequest("social", userId, "user");
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
        }
    }
}
