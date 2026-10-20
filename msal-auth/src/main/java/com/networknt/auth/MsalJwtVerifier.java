package com.networknt.auth;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.jose4j.http.Get;

/** Instance-owned signing trust. Never constructs or consults light-4j's global JwtVerifier. */
final class MsalJwtVerifier implements MsalTokenVerifier {
    private final JwtConsumer consumer;

    MsalJwtVerifier(String jwksUri, int skew) {
        this(jwks(jwksUri), skew);
    }

    MsalJwtVerifier(HttpsJwks jwks, int skew) {
        this(new HttpsJwksVerificationKeyResolver(jwks), skew);
    }

    MsalJwtVerifier(VerificationKeyResolver resolver, int skew) {
        if (skew < 0) throw new IllegalArgumentException("security-msal clock skew must not be negative");
        consumer = new JwtConsumerBuilder()
                .setVerificationKeyResolver(resolver)
                .setJwsAlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, AlgorithmIdentifiers.RSA_USING_SHA256)
                .setRequireExpirationTime()
                .setAllowedClockSkewInSeconds(skew)
                .setSkipDefaultAudienceValidation() // MsalTokenPolicy applies the exact application policy.
                .build();
    }

    private static HttpsJwks jwks(String uri) {
        HttpsJwks jwks = new HttpsJwks(uri);
        Get transport = new Get();
        transport.setConnectTimeout(5000);
        transport.setReadTimeout(5000);
        transport.setRetries(0);
        transport.setResponseBodySizeLimit(1024 * 1024);
        jwks.setSimpleHttpGet(transport);
        // Bound unknown-kid refreshes; caches and refresh state belong to this endpoint instance.
        jwks.setRefreshReprieveThreshold(30000);
        return jwks;
    }

    @Override public JwtClaims verify(String token) throws InvalidJwtException {
        return consumer.processToClaims(token);
    }
}

@FunctionalInterface
interface MsalTokenVerifier {
    JwtClaims verify(String token) throws InvalidJwtException;
}
