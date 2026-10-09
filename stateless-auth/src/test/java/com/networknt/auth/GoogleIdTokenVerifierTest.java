package com.networknt.auth;

import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.*;
import org.jose4j.jwt.*;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class GoogleIdTokenVerifierTest {
    private static final String CLIENT = "portal.apps.googleusercontent.com";
    private static final String NONCE = "server-nonce";
    private final RsaJsonWebKey key;
    private final GoogleIdTokenVerifier verifier;
    GoogleIdTokenVerifierTest() throws Exception {
        key = RsaJwkGenerator.generateJwk(2048);
        verifier = new GoogleIdTokenVerifier((jws, nesting) -> key.getPublicKey());
    }
    private JwtClaims claims() {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("https://accounts.google.com"); claims.setAudience(CLIENT);
        claims.setSubject("123456789"); claims.setIssuedAtToNow(); claims.setExpirationTimeMinutesInTheFuture(5);
        claims.setClaim("email", "person@gmail.com"); claims.setClaim("email_verified", true);
        claims.setClaim("nonce", NONCE);
        return claims;
    }
    private String sign(JwtClaims claims, RsaJsonWebKey signingKey, String algorithm) throws Exception {
        JsonWebSignature signature = new JsonWebSignature(); signature.setPayload(claims.toJson());
        signature.setKey(signingKey.getPrivateKey()); signature.setAlgorithmHeaderValue(algorithm);
        signature.setKeyIdHeaderValue("fixture"); return signature.getCompactSerialization();
    }
    private String sign(JwtClaims claims) throws Exception { return sign(claims, key, AlgorithmIdentifiers.RSA_USING_SHA256); }
    @Test void acceptsBothGoogleIssuerSpellings() throws Exception {
        for (String issuer : List.of("https://accounts.google.com", "accounts.google.com")) {
            JwtClaims claims = claims(); claims.setIssuer(issuer);
            assertEquals("123456789", verifier.verify(sign(claims), CLIENT, NONCE).getSubject());
        }
    }
    @Test void rejectsWrongSignatureAudienceIssuerExpiryAndNonce() throws Exception {
        assertThrows(Exception.class, () -> verifier.verify(sign(claims(), RsaJwkGenerator.generateJwk(2048),
                AlgorithmIdentifiers.RSA_USING_SHA256), CLIENT, NONCE));
        assertThrows(Exception.class, () -> verifier.verify(sign(claims()), "another-client", NONCE));
        assertThrows(Exception.class, () -> verifier.verify(sign(claims()), CLIENT, "another-nonce"));
        JwtClaims issuer = claims(); issuer.setIssuer("https://attacker.example");
        assertThrows(Exception.class, () -> verifier.verify(sign(issuer), CLIENT, NONCE));
        JwtClaims expired = claims(); expired.setExpirationTime(NumericDate.fromSeconds(1));
        assertThrows(Exception.class, () -> verifier.verify(sign(expired), CLIENT, NONCE));
    }
    @Test void rejectsUnverifiedEmailMissingClaimsAndWrongAlgorithm() throws Exception {
        for (String field : List.of("exp", "iat", "sub", "nonce", "email", "email_verified")) {
            JwtClaims missing = claims(); missing.unsetClaim(field);
            assertThrows(Exception.class, () -> verifier.verify(sign(missing), CLIENT, NONCE), field);
        }
        JwtClaims unverified = claims(); unverified.setClaim("email_verified", false);
        assertThrows(Exception.class, () -> verifier.verify(sign(unverified), CLIENT, NONCE));
        assertThrows(Exception.class, () -> verifier.verify(sign(claims(), key, AlgorithmIdentifiers.RSA_USING_SHA512), CLIENT, NONCE));
    }
    @Test void rejectsWrongAuthorizedPartyAndAmbiguousAudience() throws Exception {
        JwtClaims wrong = claims(); wrong.setClaim("azp", "attacker");
        assertThrows(Exception.class, () -> verifier.verify(sign(wrong), CLIENT, NONCE));
        JwtClaims multiple = claims(); multiple.setAudience(CLIENT, "attacker");
        assertThrows(Exception.class, () -> verifier.verify(sign(multiple), CLIENT, NONCE));
    }
}
