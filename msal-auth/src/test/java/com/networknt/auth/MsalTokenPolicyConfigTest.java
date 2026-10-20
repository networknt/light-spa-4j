package com.networknt.auth;

import com.networknt.security.SecurityConfig;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.networknt.auth.MsalTokenValidationTest.*;
import static org.junit.jupiter.api.Assertions.*;

class MsalTokenPolicyConfigTest {
    @Test
    void requiresExplicitTrustConfiguration() {
        assertThrows(IllegalArgumentException.class, () ->
                new MsalTokenPolicy(null, ISSUER, AUDIENCE, List.of("access_as_user"), List.of(CLIENT)));
        assertThrows(IllegalArgumentException.class, () ->
                new MsalTokenPolicy(TENANT, null, AUDIENCE, List.of("access_as_user"), List.of(CLIENT)));
        assertThrows(IllegalArgumentException.class, () ->
                new MsalTokenPolicy(TENANT, ISSUER, "", List.of("access_as_user"), List.of(CLIENT)));
        assertThrows(IllegalArgumentException.class, () ->
                new MsalTokenPolicy(TENANT, ISSUER, AUDIENCE, List.of(), List.of(CLIENT)));
        assertThrows(IllegalArgumentException.class, () ->
                new MsalTokenPolicy(TENANT, ISSUER, AUDIENCE, List.of("access_as_user"), List.of()));
    }

    @Test
    void rejectsAmbiguousOrMalformedPolicy() {
        for (String issuer : List.of("https://login.microsoftonline.com/common/v2.0",
                "http://login.microsoftonline.com/" + TENANT + "/v2.0",
                ISSUER + "?tenant=other", ISSUER + "#fragment",
                "https://user@login.microsoftonline.com/" + TENANT + "/v2.0",
                "https://login.microsoftonline.com/44444444-4444-4444-4444-444444444444/v2.0")) {
            assertThrows(IllegalArgumentException.class, () ->
                    new MsalTokenPolicy(TENANT, issuer, AUDIENCE, List.of("access_as_user"), List.of(CLIENT)));
        }
        assertThrows(IllegalArgumentException.class, () ->
                new MsalTokenPolicy(TENANT, ISSUER, AUDIENCE, List.of("scope1 scope2"), List.of(CLIENT)));
        assertThrows(IllegalArgumentException.class, () ->
                new MsalTokenPolicy(TENANT, ISSUER, AUDIENCE, List.of("access_as_user"), List.of("*")));
    }

    @Test
    void disabledHandlerDoesNotRequireTrustConfiguration() {
        assertFalse(MsalAuthConfig.load("msal-disabled").isEnabled());
    }

    @Test
    void enabledHandlerFailsClosedWithoutTrustConfiguration() {
        assertThrows(IllegalArgumentException.class, () -> MsalAuthConfig.load("msal-missing-policy"));
    }

    @Test
    void rejectsSharedJwtCacheAndAllowsExplicitlyDisabledCache() {
        assertDoesNotThrow(() -> MsalAuthHandler.requireUncachedVerifier(SecurityConfig.load("security-msal")));
        assertThrows(IllegalArgumentException.class, () ->
                MsalAuthHandler.requireUncachedVerifier(SecurityConfig.load("security-msal-cached")));
    }
}
