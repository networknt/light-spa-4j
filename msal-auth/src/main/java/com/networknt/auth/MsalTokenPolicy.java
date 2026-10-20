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

/** Application trust checks applied after signature verification on every request. */
final class MsalTokenPolicy {
    private final String tenantId;
    private final String issuer;
    private final String audience;
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
        this.audience = audience;
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

    void validate(JwtClaims claims, int clockSkewSeconds) throws MalformedClaimException {
        if (!issuer.equals(claims.getIssuer())
                || !tenantId.equals(claims.getStringClaimValue("tid"))
                || !version.equals(claims.getStringClaimValue("ver"))
                || !List.of(audience).equals(claims.getAudience())) {
            throw new IllegalArgumentException("Invalid Microsoft token trust claims");
        }
        String client = claims.getStringClaimValue("2.0".equals(version) ? "azp" : "appid");
        String scopes = claims.getStringClaimValue("scp");
        if (!allowedClientIds.contains(client == null ? "" : client)
                || scopes == null || scopes.isBlank()
                || !new HashSet<>(Arrays.asList(scopes.split(" +"))).containsAll(requiredScopes)
                || "app".equals(claims.getStringClaimValue("idtyp"))
                || claims.getSubject() == null || claims.getSubject().isBlank()) {
            throw new IllegalArgumentException("Invalid Microsoft delegated access token");
        }
        // The shared verifier uses a large time allowance internally; enforce nbf here as well.
        long now = NumericDate.now().getValue();
        long skew = Math.max(0, clockSkewSeconds);
        if (claims.getExpirationTime() == null || claims.getExpirationTime().getValue() <= now - skew
                || (claims.getNotBefore() != null && claims.getNotBefore().getValue() > now + skew)) {
            throw new IllegalArgumentException("Invalid Microsoft token lifetime");
        }
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
