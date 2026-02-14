package com.networknt.auth;

import com.networknt.client.Http2Client;
import com.networknt.client.simplepool.SimpleConnectionState;
import com.networknt.cluster.Cluster;
import com.networknt.config.Config;
import com.networknt.config.JsonMapper;
import com.networknt.monad.Failure;
import com.networknt.monad.Result;
import com.networknt.monad.Success;
import com.networknt.server.Server;
import com.networknt.server.ServerConfig;
import com.networknt.service.SingletonServiceFactory;
import com.networknt.status.Status;
import io.undertow.UndertowOptions;
import io.undertow.client.ClientConnection;
import io.undertow.client.ClientRequest;
import io.undertow.client.ClientResponse;
import io.undertow.util.Headers;
import io.undertow.util.Methods;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xnio.OptionMap;

import java.net.URI;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;


public class PortalClient {
    static final Logger logger = LoggerFactory.getLogger(PortalClient.class);
    static final String commandServiceId = "com.networknt.portal.hybrid.command-1.0.0";
    static final String queryServiceId = "com.networknt.portal.hybrid.query-1.0.0";

    static String tag = ServerConfig.getInstance().getEnvironment();
    // Get the singleton Cluster instance
    static Cluster cluster = SingletonServiceFactory.getBean(Cluster.class);
    // Get the singleton Http2Client instance
    static Http2Client client = Http2Client.getInstance();
    static ClientConnection commandConnection;
    {
        String host = cluster.serviceToUrl("https", commandServiceId, tag, null);
        try {
            SimpleConnectionState.ConnectionToken tokenCommandConnection = client.borrow(new URI(host), Http2Client.WORKER, Http2Client.SSL, Http2Client.BUFFER_POOL, OptionMap.create(UndertowOptions.ENABLE_HTTP2, true));

            commandConnection = (ClientConnection) tokenCommandConnection.getRawConnection();
        } catch (Exception e) {
            logger.error("Exception:", e);
        }
    }

    static ClientConnection queryConnection;
    {
        String host = cluster.serviceToUrl("https", queryServiceId, tag, null);
        try {
            SimpleConnectionState.ConnectionToken tokenQueryConnection = client.borrow(new URI(host), Http2Client.WORKER, Http2Client.SSL, Http2Client.BUFFER_POOL, OptionMap.create(UndertowOptions.ENABLE_HTTP2, true));

            queryConnection = (ClientConnection) tokenQueryConnection.getRawConnection();
        } catch (Exception e) {
            logger.error("Exception:", e);
        }
    }

    static final String GENERIC_EXCEPTION = "ERR10014";

    public static Result<String> callCommandWithToken(String command, String token) {
        Result<String> result = null;
        try {
            if(commandConnection == null || !commandConnection.isOpen()) {
                // The connection is close or not created.
                String host = cluster.serviceToUrl("https", commandServiceId, tag, null);
                SimpleConnectionState.ConnectionToken tokenCommandConnection = client.borrow(new URI(host), Http2Client.WORKER, Http2Client.SSL, Http2Client.BUFFER_POOL, OptionMap.create(UndertowOptions.ENABLE_HTTP2, true));

                commandConnection = (ClientConnection) tokenCommandConnection.getRawConnection();
            }
            // Create one CountDownLatch that will be reset in the callback function
            final CountDownLatch latch = new CountDownLatch(1);
            // Create an AtomicReference object to receive ClientResponse from callback function
            final AtomicReference<ClientResponse> reference = new AtomicReference<>();
            String message = "/portal/command?cmd=" + URLEncoder.encode(command, "UTF-8");
            final ClientRequest request = new ClientRequest().setMethod(Methods.GET).setPath(message);
            request.getRequestHeaders().put(Headers.AUTHORIZATION, "Bearer " + token);
            request.getRequestHeaders().put(Headers.HOST, "localhost");
            commandConnection.sendRequest(request, client.createClientCallback(reference, latch));
            latch.await();
            int statusCode = reference.get().getResponseCode();
            String body = reference.get().getAttachment(Http2Client.RESPONSE_BODY);
            if(statusCode != 200) {
                Status status = Config.getInstance().getMapper().readValue(body, Status.class);
                result = Failure.of(status);
            } else result = Success.of(body);
        } catch (Exception e) {
            logger.error("Exception:", e);
            Status status = new Status(GENERIC_EXCEPTION, e.getMessage());
            result = Failure.of(status);
        }
        return result;
    }

    public static Result<String> callQueryWithToken(String command, String token) {
        Result<String> result = null;
        try {
            if(queryConnection == null || !queryConnection.isOpen()) {
                // The connection is close or not created.
                String host = cluster.serviceToUrl("https", queryServiceId, tag, null);
                SimpleConnectionState.ConnectionToken tokenQueryConnection = client.borrow(new URI(host), Http2Client.WORKER, Http2Client.SSL, Http2Client.BUFFER_POOL, OptionMap.create(UndertowOptions.ENABLE_HTTP2, true));

                queryConnection = (ClientConnection) tokenQueryConnection.getRawConnection();
            }
            // Create one CountDownLatch that will be reset in the callback function
            final CountDownLatch latch = new CountDownLatch(1);
            // Create an AtomicReference object to receive ClientResponse from callback function
            final AtomicReference<ClientResponse> reference = new AtomicReference<>();
            String message = "/portal/query?cmd=" + URLEncoder.encode(command, "UTF-8");
            final ClientRequest request = new ClientRequest().setMethod(Methods.GET).setPath(message);
            request.getRequestHeaders().put(Headers.AUTHORIZATION, "Bearer " + token);
            request.getRequestHeaders().put(Headers.HOST, "localhost");
            queryConnection.sendRequest(request, client.createClientCallback(reference, latch));
            latch.await();
            int statusCode = reference.get().getResponseCode();
            String body = reference.get().getAttachment(Http2Client.RESPONSE_BODY);
            if(statusCode != 200) {
                Status status = Config.getInstance().getMapper().readValue(body, Status.class);
                result = Failure.of(status);
            } else result = Success.of(body);
        } catch (Exception e) {
            logger.error("Exception:", e);
            Status status = new Status(GENERIC_EXCEPTION, e.getMessage());
            result = Failure.of(status);
        }
        return result;
    }

    /**
     * Create a sociate user with bootstrap token from light-spa-4j statelessAuthHandler.
     *
     * @param userMap map contains all the properties for the social user
     * @param token a client credential JWT token
     * @return Result of refreshToken
     */
    public static Result<String> createSocialUser(Map<String, Object> userMap, String token) {
        Map<String, Object> commandMap = new HashMap<>();
        commandMap.put("host", "lightapi.net");
        commandMap.put("service", "user");
        commandMap.put("action", "createSocialUser");
        commandMap.put("version", "0.1.0");
        commandMap.put("data", userMap);
        String command = JsonMapper.toJson(commandMap);
        if(logger.isTraceEnabled()) logger.trace("command = " + command);
        return callCommandWithToken(command, token);
    }

    /**
     * Get User by email between service to service invocation. It is mainly called from light-spa-4j social login handlers.
     * The token will be a bootstrap client credential token so that there is no user_id in the JWT to bypass the match
     * verification. This is an internal method that is called between portal services and a client credential token must
     * be provided.
     *
     * @param email email
     * @param token a client credential JWT token
     * @return Result of user
     */
    public static Result<String> getUserByEmail(String email, String token) {
        final String command = String.format("{\"host\":\"lightapi.net\",\"service\":\"user\",\"action\":\"queryUserByEmail\",\"version\":\"0.1.0\",\"data\":{\"email\":\"%s\"}}", email);
        return callQueryWithToken(command, token);
    }

}
