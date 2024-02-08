package com.networknt.auth;

import com.networknt.config.Config;
import com.networknt.handler.MiddlewareHandler;
import io.undertow.server.HttpServerExchange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Deque;
import java.util.HashMap;
import java.util.Map;

public class GithubAuthHandler extends StatelessAuthHandler implements MiddlewareHandler {
    private static final Logger logger = LoggerFactory.getLogger(GithubAuthHandler.class);
    private static final String CODE = "code";
    private static final String AUTHORIZATION_CODE_MISSING = "ERR10035";
    public static StatelessAuthConfig config =
            (StatelessAuthConfig) Config.getInstance().getJsonObjectConfig(StatelessAuthConfig.CONFIG_NAME, StatelessAuthConfig.class);

    @Override
    public void handleRequest(final HttpServerExchange exchange) throws Exception {
        // This handler only cares about /google path. Pass to the next handler if path is not matched.
        if (exchange.getRelativePath().equals(config.getGithubPath())) {
            Deque<String> deque = exchange.getQueryParameters().get(CODE);
            String code = deque == null ? null : deque.getFirst();
            if (logger.isDebugEnabled()) logger.debug("code = " + code);
            // check if code is in the query parameter
            if (code == null || code.trim().length() == 0) {
                setExchangeStatus(exchange, AUTHORIZATION_CODE_MISSING);
                return;
            }
            // use the code, clientId and clientSecret to get an access token
            Map<String, String> map = new HashMap<>();
            map.put("client_id", config.getGithubClientId());
            map.put("client_secret", config.getGithubClientSecret());
            map.put("code", code);
            map.put("redirect_uri", "https://localhost:3000/");

            // use the access token to query the user info
            /*
            fetch(`https://github.com/login/oauth/access_token`, {
                    method: "POST",
                    body: data
  })
    .then(response => response.text())
    .then(paramsString => {
                    let params = new URLSearchParams(paramsString);
      const access_token = params.get("access_token");
      const scope = params.get("scope");
      const token_type = params.get("token_type");

            // Request to return data of a user that has been authenticated
            return fetch(
                    `https://api.github.com/user?access_token=${access_token}&scope=${scope}&token_type=${token_type}`
            );
    })
    .then(response => response.json())
    .then(response => {
            return res.status(200).json(response);
    })
    .catch(error => {
            return res.status(400).json(error);
    });

            // create a new portal user with the user info if it doesn't exist.

        }
    }
    */


        }
    }
}
