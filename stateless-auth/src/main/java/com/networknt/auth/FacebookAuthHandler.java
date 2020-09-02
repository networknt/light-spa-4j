package com.networknt.auth;

import com.networknt.client.oauth.ClientAuthenticatedUserRequest;
import com.networknt.client.oauth.OauthHelper;
import com.networknt.client.oauth.TokenRequest;
import com.networknt.client.oauth.TokenResponse;
import com.networknt.config.Config;
import com.networknt.config.JsonMapper;
import com.networknt.handler.MiddlewareHandler;
import com.networknt.monad.Result;
import com.networknt.status.Status;
import com.networknt.utility.Util;
import com.restfb.DefaultFacebookClient;
import com.restfb.FacebookClient;
import com.restfb.Parameter;
import com.restfb.Version;
import com.restfb.types.User;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.StatusCodes;
import net.lightapi.portal.HybridCommandClient;
import net.lightapi.portal.HybridQueryClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FacebookAuthHandler extends StatelessAuthHandler implements MiddlewareHandler {
    private static final Logger logger = LoggerFactory.getLogger(FacebookAuthHandler.class);
    private static final String ACCESS_TOKEN = "accessToken";
    private static final String AUTHORIZATION_CODE_MISSING = "ERR10035";
    private static final String EMAIL_REGISTERED = "ERR11350";

    public static StatelessAuthConfig config =
            (StatelessAuthConfig) Config.getInstance().getJsonObjectConfig(StatelessAuthConfig.CONFIG_NAME, StatelessAuthConfig.class);

    @Override
    public void handleRequest(final HttpServerExchange exchange) throws Exception {
        // This handler only cares about /google path. Pass to the next handler if path is not matched.
        if(exchange.getRelativePath().equals(config.getFacebookPath())) {
            Deque<String> deque = exchange.getQueryParameters().get(ACCESS_TOKEN);
            String accessToken = deque == null ? null : deque.getFirst();
            if (logger.isDebugEnabled()) logger.debug("access_token = " + accessToken);
            // check if code is in the query parameter
            if (accessToken == null || accessToken.trim().length() == 0) {
                setExchangeStatus(exchange, AUTHORIZATION_CODE_MISSING);
                return;
            }
            FacebookClient fbClient = new DefaultFacebookClient(accessToken, Version.VERSION_3_1);
            User me = fbClient.fetchObject("me", User.class, Parameter.with("fields", "id,name,email,first_name,last_name,verified"));
            if (me != null) {
                String email = me.getEmail();
                String firstName = me.getFirstName();
                String lastName = me.getLastName();
                String name = me.getName();
                String userId = name.replaceAll("\\s+","") + "@fb";
                Result<String> resultUser = HybridQueryClient.getUserByEmail(email, config.getBootstrapToken());
                if(resultUser.isSuccess()) {
                    Map<String, Object> map = JsonMapper.string2Map(resultUser.getResult());
                    String id = (String)map.get("userId");
                    if(!userId.equals(id)) {
                        setExchangeStatus(exchange, EMAIL_REGISTERED, email, id);
                        return;
                    }
                } else {
                    // create a social user
                    Map<String, Object> map = new HashMap<>();
                    map.put("host", "lightapi.net");
                    map.put("email", email);
                    map.put("userId", userId);
                    map.put("language", "en");
                    map.put("firstName", firstName);
                    map.put("lastName", lastName);
                    Result<String> result = HybridCommandClient.createSocialUser(map, config.getBootstrapToken());
                }
                String csrf = Util.getUUID();
                TokenRequest request = new ClientAuthenticatedUserRequest("social", email, "user");
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
            } else {
                setExchangeStatus(exchange, AUTHORIZATION_CODE_MISSING);
                return;
            }
        }
    }

}
