package com.networknt.auth;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.client.oauth.*;
import com.networknt.config.Config;
import com.networknt.config.JsonMapper;
import com.networknt.handler.Handler;
import com.networknt.handler.MiddlewareHandler;
import com.networknt.monad.Result;
import com.networknt.utility.UuidUtil;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.Cookie;
import io.undertow.server.handlers.CookieImpl;
import io.undertow.util.*;
import org.jose4j.jwt.JwtClaims;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** GIS ID-token callback, with explicit linking to the current authenticated Portal account. */
public class GoogleAuthHandler extends StatelessAuthHandler implements MiddlewareHandler {
    private static final String NONCE_COOKIE = "__Host-google_signin_nonce";
    private static final GoogleSignInChallenge CHALLENGES = new GoogleSignInChallenge();
    private static final ObjectMapper JSON = Config.getInstance().getMapper().copy()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    @FunctionalInterface interface Verify { JwtClaims verify(String token, String audience, String nonce) throws Exception; }
    @FunctionalInterface interface Resolve { Result<String> resolve(Map<String, Object> identity, String token); }
    private final Verify verifier;
    private final Resolve portal;
    public GoogleAuthHandler() { this(new GoogleIdTokenVerifier()::verify, GooglePortalClient::resolve); }
    GoogleAuthHandler(Verify verifier, Resolve portal) { this.verifier = verifier; this.portal = portal; }

    @Override
    public void handleRequest(HttpServerExchange exchange) throws Exception {
        StatelessAuthConfig config = StatelessAuthConfig.load();
        String path = exchange.getRelativePath();
        boolean link = path.equals(config.getGooglePath() + "/link");
        if (!path.equals(config.getGooglePath()) && !link) { Handler.next(exchange, getNext()); return; }
        if (Methods.OPTIONS.equals(exchange.getRequestMethod())) { Handler.next(exchange, getNext()); return; }
        exchange.getResponseHeaders().put(Headers.CACHE_CONTROL, "no-store");
        if (exchange.isInIoThread()) { exchange.dispatch(this); return; }
        if (!Methods.POST.equals(exchange.getRequestMethod()) && !Methods.GET.equals(exchange.getRequestMethod())) {
            exchange.getResponseHeaders().put(Headers.ALLOW, "GET, POST");
            reject(exchange, 405, "METHOD_NOT_ALLOWED"); return;
        }
        Map<String, Object> gis = Config.getInstance().getJsonMapConfig("google-sign-in");
        String origin = (String) gis.get("allowedOrigin");
        if (!validOrigin(origin)) { reject(exchange, 503, "GOOGLE_SIGN_IN_NOT_CONFIGURED"); return; }
        HeaderValues origins = exchange.getRequestHeaders().get(Headers.ORIGIN);
        if (origins == null || origins.size() != 1 || !origin.equals(origins.getFirst())) {
            reject(exchange, 403, "GOOGLE_ORIGIN_REJECTED"); return;
        }
        String currentUser = null;
        if (link) {
            try { currentUser = currentUser(exchange); }
            catch (Exception exception) { reject(exchange, 401, "PORTAL_LOGIN_REQUIRED"); return; }
        }
        boolean challengeRequest = "1".equals(exchange.getQueryParameters().getOrDefault("challenge", new ArrayDeque<>()).peekFirst());
        if (Methods.GET.equals(exchange.getRequestMethod()) || challengeRequest) {
            if (!challengeRequest || exchange.getQueryParameters().size() != 1) {
                exchange.getResponseHeaders().put(Headers.ALLOW, "POST"); reject(exchange, 405, "METHOD_NOT_ALLOWED"); return;
            }
            try {
                GoogleSignInChallenge.Challenge challenge = CHALLENGES.issue(currentUser);
                nonceCookie(exchange, challenge.nonce(), 300);
                json(exchange, Map.of("nonce", challenge.nonce()));
            } catch (IllegalStateException exception) { reject(exchange, 503, "GOOGLE_CHALLENGE_UNAVAILABLE"); }
            return;
        }
        String contentType = exchange.getRequestHeaders().getFirst(Headers.CONTENT_TYPE);
        if (contentType == null || !contentType.split(";", 2)[0].trim().equalsIgnoreCase("application/json")) {
            reject(exchange, 415, "JSON_REQUIRED"); return;
        }
        if (!exchange.getQueryParameters().isEmpty()) { reject(exchange, 400, "QUERY_PARAMETERS_REJECTED"); return; }
        Map<String, Object> body;
        try {
            exchange.setMaxEntitySize(16384); exchange.startBlocking();
            byte[] bytes = exchange.getInputStream().readNBytes(16385);
            if (bytes.length > 16384) { reject(exchange, 413, "REQUEST_TOO_LARGE"); return; }
            body = JSON.readValue(bytes, JSON.getTypeFactory().constructMapType(Map.class, String.class, Object.class));
            if (body == null || !Set.of("credential", "state").containsAll(body.keySet())) throw new IllegalArgumentException();
        } catch (Exception exception) { reject(exchange, 400, "INVALID_REQUEST"); return; }
        String credential = body.get("credential") instanceof String s ? s : null;
        String state = body.get("state") instanceof String s ? s : "";
        if (credential == null || credential.isBlank() || credential.length() > 8192 || state.length() > 128 || (body.containsKey("state") && !(body.get("state") instanceof String))) {
            reject(exchange, 400, "INVALID_REQUEST"); return;
        }
        Cookie cookie = exchange.getRequestCookie(NONCE_COOKIE);
        GoogleSignInChallenge.Challenge challenge = cookie == null ? null : CHALLENGES.consume(cookie.getValue());
        nonceCookie(exchange, "", 0);
        if (challenge == null || !Objects.equals(currentUser, challenge.userId())) {
            reject(exchange, 403, "GOOGLE_CHALLENGE_REJECTED"); return;
        }
        JwtClaims claims;
        try { claims = verifier.verify(credential, config.getGoogleClientId(), challenge.nonce()); }
        catch (Exception exception) { reject(exchange, 401, "INVALID_GOOGLE_CREDENTIAL"); return; }
        String email = claims.getStringClaimValue("email");
        Map<String, Object> identity = new HashMap<>();
        identity.put("subject", claims.getSubject());
        identity.put("email", email.toLowerCase(Locale.ROOT));
        identity.put("authoritativeEmail", email.toLowerCase(Locale.ROOT).endsWith("@gmail.com")
                || claims.getStringClaimValue("hd") != null);
        identity.put("firstName", Objects.toString(claims.getClaimValue("given_name"), ""));
        identity.put("lastName", Objects.toString(claims.getClaimValue("family_name"), ""));
        identity.put("operation", link ? "link" : "login");
        if (link) identity.put("targetUserId", currentUser);
        Result<String> resolved = portal.resolve(identity, config.getBootstrapToken());
        if (resolved.isFailure()) { reject(exchange, resolved.getError().getStatusCode(), resolved.getError().getCode()); return; }
        Map<String, Object> account;
        try {
            account = JsonMapper.string2Map(resolved.getResult());
            UUID.fromString((String) account.get("userId"));
            if (!(account.get("email") instanceof String address) || address.isBlank() || address.length() > 255)
                throw new IllegalArgumentException();
        } catch (Exception exception) { reject(exchange, 503, "GOOGLE_IDENTITY_UNAVAILABLE"); return; }
        if (link) {
            String redirect = redirect(config.getRedirectUri(), state);
            json(exchange, Map.of("linked", true, "scopes", List.of(), "redirectUri", redirect,
                    "denyUri", config.getDenyUri() == null ? redirect : config.getDenyUri()));
        } else {
            issueSession(exchange, account, state, config);
        }
    }

    static boolean validOrigin(String origin) {
        try {
            URI uri = URI.create(origin);
            return "https".equals(uri.getScheme()) && uri.getHost() != null && uri.getUserInfo() == null
                    && uri.getRawQuery() == null && uri.getRawFragment() == null && uri.getRawPath().isEmpty();
        } catch (Exception exception) { return false; }
    }

    protected String currentUser(HttpServerExchange exchange) throws Exception {
        Cookie cookie = exchange.getRequestCookie("accessToken");
        if (cookie == null) throw new IllegalArgumentException("No session");
        JwtClaims claims = jwtVerifier.verifyJwt(cookie.getValue(), false, false);
        return UUID.fromString(claims.getStringClaimValue("user_id")).toString();
    }

    protected void issueSession(HttpServerExchange exchange, Map<String, Object> account, String state,
                                StatelessAuthConfig config) throws Exception {
        String csrf = UuidUtil.uuidToBase64(UuidUtil.getUUID());
        TokenRequest request = new ClientAuthenticatedUserRequest("social", (String) account.get("email"), "user");
        request.setCsrf(csrf);
        Result<TokenResponse> result = OauthHelper.getTokenResult(request);
        if (result.isFailure()) { reject(exchange, result.getError().getStatusCode(), result.getError().getCode()); return; }
        List scopes = setCookies(exchange, result.getResult(), csrf, config);
        String redirect = redirect(config.getRedirectUri(), state);
        json(exchange, Map.of("scopes", scopes, "redirectUri", redirect,
                "denyUri", config.getDenyUri() == null ? redirect : config.getDenyUri()));
    }

    static String redirect(String base, String state) {
        if (state == null || state.isEmpty()) return base;
        String route = base.contains("#") ? base.substring(base.indexOf('#') + 1) : base;
        return base + (route.contains("?") ? "&" : "?") + "state=" + URLEncoder.encode(state, StandardCharsets.UTF_8);
    }
    private static void nonceCookie(HttpServerExchange exchange, String nonce, int maxAge) {
        exchange.setResponseCookie(new CookieImpl(NONCE_COOKIE, nonce).setPath("/")
                .setHttpOnly(true).setSecure(true).setSameSiteMode("None").setMaxAge(maxAge));
    }
    private static void json(HttpServerExchange exchange, Object body) {
        exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "application/json");
        exchange.getResponseSender().send(JsonMapper.toJson(body));
    }
    private static void reject(HttpServerExchange exchange, int status, String code) {
        exchange.setStatusCode(status); json(exchange, Map.of("code", code));
    }
}
