package com.networknt.auth;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.jose4j.http.Get;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/** Google keys are fetched only from this fixed HTTPS endpoint, never from token headers. */
public final class GoogleIdTokenVerifier {
    private static final VerificationKeyResolver GOOGLE_KEYS;
    static {
        HttpsJwks keys = new HttpsJwks("https://www.googleapis.com/oauth2/v3/certs");
        Get http = new Get();
        http.setConnectTimeout(3000);
        http.setReadTimeout(3000);
        keys.setSimpleHttpGet(http);
        keys.setDefaultCacheDuration(3600);
        GOOGLE_KEYS = new HttpsJwksVerificationKeyResolver(keys);
    }
    private final VerificationKeyResolver keys;
    public GoogleIdTokenVerifier() { this(GOOGLE_KEYS); }
    GoogleIdTokenVerifier(VerificationKeyResolver keys) { this.keys = keys; }

    public JwtClaims verify(String credential, String clientId, String nonce) throws Exception {
        if (credential == null || credential.length() > 8192 || clientId == null || clientId.isBlank()
                || nonce == null || nonce.isBlank()) throw new IllegalArgumentException("Invalid credential");
        JwtClaims claims = new JwtConsumerBuilder()
                .setRequireExpirationTime().setRequireIssuedAt().setRequireSubject()
                .setExpectedIssuers(true, "accounts.google.com", "https://accounts.google.com")
                .setExpectedAudience(clientId).setAllowedClockSkewInSeconds(30)
                .setJwsAlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT,
                        AlgorithmIdentifiers.RSA_USING_SHA256)
                .setVerificationKeyResolver(keys).build().processToClaims(credential);
        String subject = claims.getSubject();
        String email = claims.getStringClaimValue("email");
        String azp = claims.getStringClaimValue("azp");
        if (subject == null || !subject.matches("[0-9]{1,255}") || email == null || email.length() > 320
                || !Boolean.TRUE.equals(claims.getClaimValue("email_verified"))
                || (azp != null && !clientId.equals(azp))
                || (claims.getAudience().size() != 1 && azp == null)
                || claims.getIssuedAt().getValue() > System.currentTimeMillis() / 1000 + 30
                || !same(nonce, claims.getStringClaimValue("nonce"))) {
            throw new IllegalArgumentException("Invalid Google identity");
        }
        return claims;
    }

    static boolean same(String expected, String actual) {
        return expected != null && actual != null && MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8), actual.getBytes(StandardCharsets.UTF_8));
    }
}
