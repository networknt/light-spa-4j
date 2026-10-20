package com.networknt.auth.trust;

import com.networknt.config.JsonMapper;
import org.jose4j.http.Get;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
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
import org.jose4j.lang.UnresolvableKeyException;

import java.net.URI;
import java.security.Key;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

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

    public static JwtTrust load(Object source, Kind kind) {
        Map<String, Object> settings = configuration(source);
        String uri = text(settings, "jwksUri");
        https(uri);
        HttpsJwks keys = new HttpsJwks(uri);
        Get transport = new Get();
        transport.setConnectTimeout(5000);
        transport.setReadTimeout(5000);
        transport.setRetries(0);
        transport.setResponseBodySizeLimit(1024 * 1024);
        keys.setSimpleHttpGet(transport);
        keys.setDefaultCacheDuration(300);
        keys.setRefreshReprieveThreshold(30000);
        return new JwtTrust(settings, kind, resolver(keys));
    }

    JwtTrust(Map<String, Object> settings, Kind kind, HttpsJwks source) {
        this(settings, kind, resolver(source));
    }

    JwtTrust(Map<String, Object> settings, Kind kind, VerificationKeyResolver resolver) {
        this.kind = kind;
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
            if (cause instanceof KeyUnavailable) return true;
        return false;
    }

    private static VerificationKeyResolver resolver(HttpsJwks source) {
        AtomicReference<CompletableFuture<List<JsonWebKey>>> flight = new AtomicReference<>();
        return new VerificationKeyResolver() {
            private volatile LookupFailure lastFailure;

            @Override
            public Key resolveKey(org.jose4j.jws.JsonWebSignature jws, List<org.jose4j.jwx.JsonWebStructure> nesting)
                    throws UnresolvableKeyException {
                String kid = jws.getKeyIdHeaderValue();
                if (kid == null || kid.isBlank() || kid.length() > 256) throw new MissingKey();
                LookupFailure failed = lastFailure;
                if (failed != null && System.nanoTime() - failed.expiresAt < 0) throw failed.error;
                CompletableFuture<List<JsonWebKey>> owner = new CompletableFuture<>();
                CompletableFuture<List<JsonWebKey>> current = flight.compareAndExchange(null, owner);
                if (current == null) {
                    current = owner;
                    try {
                        List<JsonWebKey> keys = source.getJsonWebKeys();
                        if (select(keys, kid) == null) {
                            source.refresh(); // Endpoint-owned cache and 30s unknown-kid refresh reprieve.
                            keys = source.getJsonWebKeys();
                        }
                        owner.complete(keys);
                    } catch (Exception e) {
                        KeyUnavailable unavailable = new KeyUnavailable(e);
                        lastFailure = new LookupFailure(unavailable, System.nanoTime() + TimeUnit.SECONDS.toNanos(5));
                        owner.completeExceptionally(unavailable);
                    } finally {
                        flight.compareAndSet(owner, null);
                        if (!owner.isDone()) owner.completeExceptionally(new IllegalStateException("Key lookup aborted"));
                    }
                }
                try {
                    Key key = select(current.get(5, TimeUnit.SECONDS), kid);
                    if (key == null) throw new MissingKey();
                    return key;
                } catch (MissingKey e) { throw e; }
                catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new KeyUnavailable(e); }
                catch (Exception e) { throw new KeyUnavailable(e); }
            }
        };
    }

    private static Key select(List<JsonWebKey> keys, String kid) throws UnresolvableKeyException {
        Key selected = null;
        for (JsonWebKey key : keys) {
            if (key instanceof RsaJsonWebKey && kid.equals(key.getKeyId())
                    && (key.getUse() == null || "sig".equals(key.getUse()))
                    && (key.getKeyOps() == null || key.getKeyOps().contains("verify"))
                    && (key.getAlgorithm() == null || AlgorithmIdentifiers.RSA_USING_SHA256.equals(key.getAlgorithm()))) {
                if (selected != null) throw new UnresolvableKeyException("Ambiguous signing key");
                selected = key.getKey();
            }
        }
        return selected;
    }

    private record LookupFailure(KeyUnavailable error, long expiresAt) { }

    private static final class KeyUnavailable extends UnresolvableKeyException {
        KeyUnavailable(Throwable cause) { super("Signing keys temporarily unavailable", cause); }
    }
    private static final class MissingKey extends UnresolvableKeyException {
        MissingKey() { super("No matching signing key in trusted JWKS"); }
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
