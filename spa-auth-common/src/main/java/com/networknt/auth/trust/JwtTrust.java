package com.networknt.auth.trust;

import com.networknt.config.JsonMapper;
import org.jose4j.http.Get;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.ErrorCodeValidator;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.VerificationKeyResolver;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** An immutable application policy with its own signing authority and JWKS cache.
 * Never reads light-4j's global verifier, client routing, certificate or JWT caches. */
public final class JwtTrust {
    public enum Kind { INTERNAL_ACCESS, MICROSOFT_ID, MICROSOFT_ACCESS }
    private final Kind kind;
    private final String issuer;
    private final String audience;
    private final String tenant;
    private final String version;
    private final Set<String> clients;
    private final Set<String> scopes;
    private final int skew;
    private final JwtConsumer consumer;
    private final VerificationKeyResolver signingSource;
    VerificationKeyResolver signingSource() { return signingSource; }

    /** A configuration snapshot owns its pool. Only identical administrator-selected endpoints/TLS roots share keys. */
    public static final class Factory {
        private final java.util.concurrent.ConcurrentHashMap<SourceKey, VerificationKeyResolver> sources = new java.util.concurrent.ConcurrentHashMap<>();
        public JwtTrust load(Object source, Kind kind) {
            Map<String, Object> settings = configuration(source);
            String uri = text(settings, "jwksUri");
            https(uri);
            List<String> caFiles = caFiles(settings.get("additionalCaFiles"));
            SourceKey key = new SourceKey(uri, caFiles);
            return new JwtTrust(settings, kind, sources.computeIfAbsent(key, ignored -> source(uri, caFiles)));
        }
    }
    private record SourceKey(String uri, List<String> caFiles) { }
    public static JwtTrust load(Object source, Kind kind) { return new Factory().load(source, kind); }

    private static VerificationKeyResolver source(String uri, List<String> caFiles) {
        Get transport = new Get();
        transport.setConnectTimeout(5000);
        transport.setReadTimeout(5000);
        transport.setRetries(0);
        transport.setResponseBodySizeLimit(1024 * 1024);
        if (!caFiles.isEmpty()) {
            try {
                javax.net.ssl.TrustManagerFactory trust = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
                trust.init((java.security.KeyStore) null);
                java.util.Collection<java.security.cert.X509Certificate> roots = new java.util.ArrayList<>();
                for (var manager : trust.getTrustManagers()) if (manager instanceof javax.net.ssl.X509TrustManager x509)
                    roots.addAll(Arrays.asList(x509.getAcceptedIssuers()));
                var certificates = java.security.cert.CertificateFactory.getInstance("X.509");
                for (String file : caFiles) try (var input = java.nio.file.Files.newInputStream(java.nio.file.Path.of(file))) {
                    for (var certificate : certificates.generateCertificates(input)) roots.add((java.security.cert.X509Certificate) certificate);
                }
                transport.setTrustedCertificates(roots); // Add endpoint-specific roots without replacing JVM/public trust.
            } catch (Exception e) { throw new IllegalArgumentException("Cannot load endpoint-specific additional CA certificates", e); }
        }
        return new JwksSource(uri, transport);
    }
    private static List<String> caFiles(Object value) {
        if (value == null) return List.of();
        if (value instanceof String s) value = s.isBlank() ? List.of() : JsonMapper.fromJson(s, List.class);
        if (!(value instanceof List<?> values) || values.stream().anyMatch(v -> !(v instanceof String s) || s.isBlank()))
            throw new IllegalArgumentException("additionalCaFiles must be an array of PEM certificate paths");
        return values.stream().map(String.class::cast).map(p -> java.nio.file.Path.of(p).toAbsolutePath().normalize().toString()).sorted().distinct().toList();
    }

    JwtTrust(Map<String, Object> settings, Kind kind, VerificationKeyResolver resolver) {
        this.kind = kind;
        this.signingSource = resolver;
        issuer = text(settings, "issuer");
        audience = text(settings, "audience");
        Object clock = settings.getOrDefault("clockSkewSeconds", 0);
        try { skew = Integer.parseInt(clock.toString()); }
        catch (RuntimeException e) { throw new IllegalArgumentException("token trust clockSkewSeconds must be an integer"); }
        if (skew < 0 || skew > 300) throw new IllegalArgumentException("token trust clockSkewSeconds must be 0..300");
        tenant = kind == Kind.INTERNAL_ACCESS ? null : text(settings, "tenantId");
        if (tenant != null) {
            uuid(tenant);
            URI authority = https(issuer);
            String path = authority.getRawPath();
            if (authority.getRawQuery() != null || !(path.equals("/" + tenant + "/v2.0") || path.equals("/" + tenant + "/")))
                throw new IllegalArgumentException("Microsoft issuer must identify the configured tenant and v1/v2 version");
            version = path.endsWith("/v2.0") ? "2.0" : "1.0";
        } else version = null;
        scopes = list(settings.get("requiredScopes"));
        clients = list(settings.get("allowedClientIds"));
        if (kind == Kind.MICROSOFT_ACCESS) {
            if (scopes.isEmpty() || clients.isEmpty()) throw new IllegalArgumentException("Microsoft API trust requires delegated scopes and allowed clients");
            clients.forEach(JwtTrust::uuid);
            if ("2.0".equals(version)) uuid(audience);
        }
        if (kind == Kind.MICROSOFT_ID) uuid(audience);
        // Lifetime and application claims are checked below on EVERY verification, including cleanup.
        consumer = new JwtConsumerBuilder().setVerificationKeyResolver(resolver)
                .setJwsAlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, AlgorithmIdentifiers.RSA_USING_SHA256)
                .setSkipAllDefaultValidators().build();
    }

    public JwtClaims verify(String token, boolean allowExpired) throws InvalidJwtException {
        JwtClaims claims = consumer.processToClaims(token);
        try {
            if (!issuer.equals(claims.getIssuer()) || !List.of(audience).equals(claims.getAudience())) throw rejected("issuer_or_audience");
            long now = NumericDate.now().getValue();
            if (claims.getExpirationTime() == null) throw rejected("expiration_missing");
            if (!allowExpired && claims.getExpirationTime().getValue() <= now - skew)
                throw new InvalidJwtException("Token expired", List.of(new ErrorCodeValidator.Error(ErrorCodes.EXPIRED, "Token expired")), null);
            if (claims.getNotBefore() != null && claims.getNotBefore().getValue() > now + skew) throw rejected("not_before");
            if (kind != Kind.INTERNAL_ACCESS) {
                if (!tenant.equals(claims.getStringClaimValue("tid")) || !version.equals(claims.getStringClaimValue("ver"))) throw rejected("tenant_or_version");
                if (claims.getSubject() == null || claims.getSubject().isBlank() || "app".equals(claims.getStringClaimValue("idtyp"))) throw rejected("token_purpose");
                String delegated = claims.getStringClaimValue("scp");
                if (kind == Kind.MICROSOFT_ID) {
                    // The subject is intentionally a SPA ID token, not an API bearer token.
                    String nonce = claims.getStringClaimValue("nonce");
                    if (nonce == null || nonce.isBlank() || delegated != null) throw rejected("id_token_purpose");
                } else {
                    String client = claims.getStringClaimValue("2.0".equals(version) ? "azp" : "appid");
                    if (!clients.contains(client == null ? "" : client) || delegated == null
                            || !Set.copyOf(Arrays.asList(delegated.trim().split(" +"))).containsAll(scopes)) throw rejected("client_or_scopes");
                }
            }
            return claims;
        } catch (MalformedClaimException e) { throw rejected("malformed_claim"); }
    }

    /** Only transport/parse uncertainty is retryable. Confirmed missing keys are invalid. */
    public static boolean unavailable(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause())
            if (cause instanceof JwksSource.UnavailableKey) return true;
        return false;
    }

    /** An OAuth refresh may already be rotated even when publication of its new signing key lags. */
    public static boolean verificationPending(Throwable failure) {
        if (unavailable(failure)) return true;
        for (Throwable cause = failure; cause != null; cause = cause.getCause())
            if (cause instanceof JwksSource.MissingKey) return true;
        return false;
    }

    private static InvalidJwtException rejected(String category) {
        return new InvalidJwtException("Token rejected", List.of(new ErrorCodeValidator.Error(0, category)), null);
    }
    private static String text(Map<String, Object> settings, String name) {
        Object value = settings.get(name);
        if (!(value instanceof String s) || s.isBlank() || !s.equals(s.trim())) throw new IllegalArgumentException("token trust requires " + name);
        return s;
    }
    private static URI https(String value) {
        URI uri = URI.create(value);
        if (!"https".equals(uri.getScheme()) || uri.getHost() == null || uri.getRawUserInfo() != null || uri.getRawFragment() != null)
            throw new IllegalArgumentException("token trust requires an administrator-configured HTTPS endpoint");
        return uri;
    }
    private static void uuid(String value) {
        if (!UUID.fromString(value).toString().equals(value)) throw new IllegalArgumentException("Microsoft tenant/client must be a canonical UUID");
    }
    private static Set<String> list(Object value) {
        if (value == null) return Set.of();
        if (value instanceof String s) {
            s = s.trim();
            value = s.startsWith("[") ? JsonMapper.fromJson(s, List.class) : s.isEmpty() ? List.of() : Arrays.stream(s.split(",", -1)).map(String::trim).toList();
        }
        if (!(value instanceof List<?> values) || values.stream().anyMatch(v -> !(v instanceof String s) || s.isBlank() || s.chars().anyMatch(Character::isWhitespace)))
            throw new IllegalArgumentException("token trust lists must contain nonempty individual strings");
        return Set.copyOf(values.stream().map(String.class::cast).toList());
    }
    @SuppressWarnings("unchecked")
    public static Map<String, Object> configuration(Object source) {
        if (source instanceof String s && !s.isBlank()) source = JsonMapper.fromJson(s, Map.class);
        if (!(source instanceof Map<?, ?> map)) throw new IllegalArgumentException("enabled handler requires token trust settings");
        return (Map<String, Object>) map;
    }
}
