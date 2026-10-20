package com.networknt.auth;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;

import java.net.URI;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/** Application trust checks applied after signature verification on every request. */
final class MsalTokenPolicy {
    private static final Pattern SPACE = Pattern.compile(" +");
    static final class RejectedTokenException extends Exception {
        private final String category;
        RejectedTokenException(String category) { super("Microsoft token rejected: " + category); this.category = category; }
        String category() { return category; }
    }
    private final String tenantId;
    private final String issuer;
    private final List<String> audiences;
    private final String version;
    private final Set<String> requiredScopes;
    private final Set<String> allowedClientIds;

    MsalTokenPolicy(String tenantId, String issuer, String audience,
                    List<String> requiredScopes, List<String> allowedClientIds) {
        requireUuid(tenantId, "tenantId");
        requireText(issuer, "issuer");
        requireText(audience, "audience");
        URI uri;
        try {
            uri = URI.create(issuer);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("msal-auth.issuer must be a tenant-specific HTTPS URI");
        }
        String path = uri.getRawPath();
        if (!"https".equals(uri.getScheme()) || uri.getHost() == null || uri.getRawUserInfo() != null
                || uri.getRawQuery() != null || uri.getRawFragment() != null
                || !(("/" + tenantId + "/v2.0").equals(path) || ("/" + tenantId + "/").equals(path))) {
            throw new IllegalArgumentException("msal-auth.issuer must be a tenant-specific HTTPS issuer matching tenantId");
        }
        this.version = path.endsWith("/v2.0") ? "2.0" : "1.0";
        this.tenantId = tenantId;
        this.issuer = issuer;
        this.audiences = List.of(audience);
        if (requiredScopes == null || requiredScopes.isEmpty())
            throw new IllegalArgumentException("msal-auth.requiredScopes must not be empty");
        for (String scope : requiredScopes) {
            requireText(scope, "requiredScopes");
            if (scope.chars().anyMatch(Character::isWhitespace))
                throw new IllegalArgumentException("msal-auth.requiredScopes entries must be individual scopes");
        }
        if (allowedClientIds == null || allowedClientIds.isEmpty())
            throw new IllegalArgumentException("msal-auth.allowedClientIds must not be empty");
        for (String clientId : allowedClientIds) requireUuid(clientId, "allowedClientIds");
        this.requiredScopes = Set.copyOf(requiredScopes);
        this.allowedClientIds = Set.copyOf(allowedClientIds);
    }

    void validate(JwtClaims claims, int clockSkewSeconds) throws MalformedClaimException, RejectedTokenException {
        if (!issuer.equals(claims.getIssuer())) throw new RejectedTokenException("issuer");
        if (!tenantId.equals(claims.getStringClaimValue("tid"))) throw new RejectedTokenException("tenant");
        if (!version.equals(claims.getStringClaimValue("ver"))) throw new RejectedTokenException("version");
        if (!audiences.equals(claims.getAudience())) throw new RejectedTokenException("audience");
        String client = claims.getStringClaimValue("2.0".equals(version) ? "azp" : "appid");
        String scopes = claims.getStringClaimValue("scp");
        if (!allowedClientIds.contains(client == null ? "" : client)) throw new RejectedTokenException("client");
        if (scopes == null || scopes.isBlank()
                || !new HashSet<>(Arrays.asList(SPACE.split(scopes))).containsAll(requiredScopes))
            throw new RejectedTokenException("scopes");
        if ("app".equals(claims.getStringClaimValue("idtyp"))
                || claims.getSubject() == null || claims.getSubject().isBlank())
            throw new RejectedTokenException("token_purpose");
        // Expiration is enforced by JwtVerifier. Its large internal time allowance
        // does not enforce nbf adequately, so apply the configured allowance here.
        validateNotBefore(claims, NumericDate.now().getValue(), clockSkewSeconds);
    }

    static void validateNotBefore(JwtClaims claims, long now, int clockSkewSeconds)
            throws MalformedClaimException, RejectedTokenException {
        if (claims.getNotBefore() != null && claims.getNotBefore().getValue() > now + Math.max(0, clockSkewSeconds))
            throw new RejectedTokenException("not_before");
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank() || !value.equals(value.trim()))
            throw new IllegalArgumentException("msal-auth." + field + " must be configured");
    }

    private static void requireUuid(String value, String field) {
        requireText(value, field);
        try {
            if (!UUID.fromString(value).toString().equals(value))
                throw new IllegalArgumentException();
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("msal-auth." + field + " must contain canonical tenant/client UUIDs");
        }
    }
}
