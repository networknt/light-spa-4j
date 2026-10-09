package com.networknt.auth;

import com.networknt.client.Http2Client;
import com.networknt.client.simplepool.SimpleConnectionState;
import com.networknt.cluster.Cluster;
import com.networknt.config.Config;
import com.networknt.config.JsonMapper;
import com.networknt.monad.Failure;
import com.networknt.monad.Result;
import com.networknt.monad.Success;
import com.networknt.server.ServerConfig;
import com.networknt.service.SingletonServiceFactory;
import com.networknt.status.Status;
import io.undertow.client.*;
import io.undertow.util.*;
import org.xnio.OptionMap;
import java.net.URI;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** The identity command is sent in a POST body, never in a URL. */
final class GooglePortalClient {
    static Result<String> resolve(Map<String, Object> identity, String bootstrapToken) {
        Http2Client client = Http2Client.getInstance();
        SimpleConnectionState.ConnectionToken borrowed = null;
        try {
            Map<String, Object> config = Config.getInstance().getJsonMapConfig("google-sign-in");
            String endpoint = (String) config.get("portalCommandUrl");
            if (endpoint == null || endpoint.isBlank()) {
                Cluster cluster = SingletonServiceFactory.getBean(Cluster.class);
                endpoint = cluster.serviceToUrl("https", "com.networknt.portal.hybrid.command-1.0.0",
                        ServerConfig.getInstance().getEnvironment(), null) + "/portal/command";
            }
            URI uri = URI.create(endpoint);
            if (!"https".equals(uri.getScheme()) || uri.getRawQuery() != null || uri.getUserInfo() != null || uri.getRawFragment() != null || uri.getHost() == null)
                throw new IllegalArgumentException("Invalid Portal command endpoint");
            URI origin = URI.create(uri.getScheme() + "://" + uri.getRawAuthority());
            borrowed = client.borrow(origin, Http2Client.WORKER, Http2Client.SSL,
                    Http2Client.BUFFER_POOL, OptionMap.EMPTY);
            ClientRequest request = new ClientRequest().setMethod(Methods.POST).setPath(uri.getRawPath());
            request.getRequestHeaders().put(Headers.HOST, uri.getRawAuthority());
            request.getRequestHeaders().put(Headers.CONTENT_TYPE, "application/json");
            request.getRequestHeaders().put(Headers.AUTHORIZATION, "Bearer " + bootstrapToken);
            String body = JsonMapper.toJson(Map.of("host", "lightapi.net", "service", "user",
                    "action", "googleIdentity", "version", "0.1.0", "data", identity));
            request.getRequestHeaders().put(Headers.TRANSFER_ENCODING, "chunked");
            AtomicReference<ClientResponse> response = new AtomicReference<>();
            CountDownLatch done = new CountDownLatch(1);
            ((ClientConnection) borrowed.getRawConnection()).sendRequest(request,
                    client.createClientCallback(response, done, body));
            if (!done.await(10, TimeUnit.SECONDS) || response.get() == null) {
                ((ClientConnection) borrowed.getRawConnection()).close();
                return Failure.of(new Status(503, "GOOGLE_IDENTITY_UNAVAILABLE", "Identity service unavailable", "Try again"));
            }
            ClientResponse reply = response.get();
            String result = reply.getAttachment(Http2Client.RESPONSE_BODY);
            if (reply.getResponseCode() != 200) return Failure.of(new Status(reply.getResponseCode(),
                    "GOOGLE_IDENTITY_REJECTED", "Google account could not be signed in or linked",
                    "Sign in to the existing account to link it, or contact an administrator"));
            return Success.of(result);
        } catch (Exception exception) {
            if (exception instanceof InterruptedException) Thread.currentThread().interrupt();
            return Failure.of(new Status(503, "GOOGLE_IDENTITY_UNAVAILABLE", "Identity service unavailable", "Try again"));
        } finally { if (borrowed != null) client.restore(borrowed); }
    }
}
