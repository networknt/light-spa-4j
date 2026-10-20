package com.networknt.auth;

import com.networknt.config.JsonMapper;
import org.jose4j.jwt.NumericDate;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static com.networknt.auth.MsalTokenValidationTest.*;
import static org.junit.jupiter.api.Assertions.*;

class MsalProductionConfigTest {
    @TempDir Path directory;

    public static void main(String[] args) throws Exception {
        MsalAuthConfig config = MsalAuthConfig.load("msal-deployed");
        config.getTokenPolicy().validate(validClaims(), 60);
        System.out.println("PRODUCTION_POLICY_LOADED");
    }

    @Test
    void shippedTemplateUsesRealValuesInjectionForNativeJsonAndCsvLists() throws Exception {
        // Use the checked-in production template, not the test resource of the same name.
        Files.copy(Path.of("src/main/resources/config/msal-auth.yml"), directory.resolve("msal-deployed.yml"));
        for (Object scopes : List.of(List.of("access_as_user"), "[\"access_as_user\"]", "access_as_user,extra_scope", "ENV")) {
            Map<String, Object> values = new HashMap<>(Map.of("msal-auth.tenantId", TENANT,
                    "msal-auth.jwksUri", "https://login.microsoftonline.com/keys", "msal-auth.issuer", ISSUER, "msal-auth.audience", AUDIENCE,
                    "msal-auth.requiredScopes", scopes, "msal-auth.allowedClientIds", CLIENT, "msal-auth.csrfSigningKeyId", "test", "msal-auth.csrfSigningKeys", "test=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
            boolean environment = "ENV".equals(scopes);
            if (environment) {
                values.remove("msal-auth.requiredScopes");
                values.remove("msal-auth.allowedClientIds");
            }
            Files.writeString(directory.resolve("values.yml"), JsonMapper.toJson(values));
            Path output = directory.resolve("probe.log");
            ProcessBuilder builder = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                    "-Dlight-4j-config-dir=" + directory, "-cp", System.getProperty("java.class.path"),
                    MsalProductionConfigTest.class.getName()).redirectErrorStream(true).redirectOutput(output.toFile());
            if (environment) {
                builder.environment().put("MSAL_AUTH_REQUIREDSCOPES", "access_as_user,extra_scope");
                builder.environment().put("MSAL_AUTH_ALLOWEDCLIENTIDS", "[\"" + CLIENT + "\"]");
            }
            Process process = builder.start();
            boolean finished = process.waitFor(30, TimeUnit.SECONDS);
            if (!finished) process.destroyForcibly();
            assertTrue(finished, "configuration probe timed out");
            String result = Files.readString(output);
            assertEquals(0, process.exitValue(), result);
            assertTrue(result.contains("PRODUCTION_POLICY_LOADED"), result);
        }
    }

    @Test
    void invalidReloadIsCachedAndCorrectedSnapshotRecovers() {
        class CountedMap extends HashMap<String, Object> {
            int reads;
            @Override public Object get(Object key) { reads++; return super.get(key); }
        }
        CountedMap invalid = new CountedMap();
        invalid.put("enabled", true);
        RuntimeException first = assertThrows(IllegalArgumentException.class, () -> MsalAuthConfig.loadSnapshot(invalid));
        int reads = invalid.reads;
        for (int request = 0; request < 10; request++)
            assertSame(first, assertThrows(IllegalArgumentException.class, () -> MsalAuthConfig.loadSnapshot(invalid)));
        assertEquals(reads, invalid.reads, "invalid snapshot must not be reparsed per request");
        assertNotNull(MsalAuthConfig.loadSnapshot(validMap()).getTokenPolicy());
    }

    private static Map<String, Object> validMap() {
        return new HashMap<>(Map.of("enabled", true, "tenantId", TENANT, "issuer", ISSUER,
                "audience", AUDIENCE, "jwksUri", "https://login.microsoftonline.com/keys", "requiredScopes", List.of("access_as_user"), "allowedClientIds", List.of(CLIENT), "csrfSigningKeyId", "test", "csrfSigningKeys", "test=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    }

    @Test
    void malformedAndEmptyListSettingsFailClosed() {
        for (Object scopes : List.of("", "[]", "[42]", "[broken", "access_as_user,", List.of(42))) {
            Map<String, Object> map = validMap();
            map.put("requiredScopes", scopes);
            assertThrows(IllegalArgumentException.class, () -> new MsalAuthConfig(map));
        }
    }

    @Test
    void disabledHandlerIgnoresPolicySettings() {
        Map<String, Object> map = new HashMap<>(Map.of("enabled", false, "requiredScopes", 42, "tenantId", 7,
                "websocketAllowedOrigins", 42, "browserAllowedOrigins", 42, "csrfSigningKeys", 42));
        MsalAuthConfig config = assertDoesNotThrow(() -> new MsalAuthConfig(map));
        assertFalse(config.isEnabled());
        assertNull(config.getTokenPolicy());
    }

    @Test
    void notBeforeBoundaryUsesConfiguredSkewAndCategory() throws Exception {
        var claims = validClaims();
        claims.setNotBefore(NumericDate.fromSeconds(1060));
        assertDoesNotThrow(() -> MsalTokenPolicy.validateNotBefore(claims, 1000, 60));
        claims.setNotBefore(NumericDate.fromSeconds(1061));
        var error = assertThrows(MsalTokenPolicy.RejectedTokenException.class,
                () -> MsalTokenPolicy.validateNotBefore(claims, 1000, 60));
        assertEquals("not_before", error.category());
    }

    @Test
    void signingEndpointMustBeExplicitTrustedHttps() {
        for (String uri : List.of("", "http://localhost/keys", "https://user:password@example.com/keys", "https://example.com/keys#fragment"))
            assertThrows(IllegalArgumentException.class, () -> MsalAuthConfig.validateJwksUri(uri));
        assertThrows(IllegalArgumentException.class, () -> MsalAuthConfig.validateJwksUri(null));
        assertDoesNotThrow(() -> MsalAuthConfig.validateJwksUri("https://login.microsoftonline.com/keys?appid=application"));
    }

    @Test
    void enabledHandlerRequiresSigningKeysAndInvalidReloadFailsClosed() {
        Map<String, Object> invalid = validMap();
        invalid.remove("csrfSigningKeys");
        RuntimeException error = assertThrows(IllegalArgumentException.class, () -> MsalAuthConfig.loadSnapshot(invalid));
        assertTrue(error.getMessage().contains("csrfSigningKeys"));
        assertSame(error, assertThrows(IllegalArgumentException.class, () -> MsalAuthConfig.loadSnapshot(invalid)));
        MsalAuthConfig recovered = MsalAuthConfig.loadSnapshot(validMap());
        String value = recovered.getSessionCsrf().issue("session");
        assertTrue(recovered.getSessionCsrf().verify(value, "session"));

        Map<String, Object> rotated = validMap();
        rotated.put("csrfSigningKeyId", "next");
        rotated.put("csrfSigningKeys", validMap().get("csrfSigningKeys") + ",next=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        MsalAuthConfig overlap = MsalAuthConfig.loadSnapshot(rotated);
        assertTrue(overlap.getSessionCsrf().verify(value, "session"));
        assertTrue(overlap.getSessionCsrf().verify(overlap.getSessionCsrf().issue("session"), "session"));

        rotated = new HashMap<>(rotated);
        rotated.put("csrfSigningKeys", "next=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        MsalAuthConfig next = MsalAuthConfig.loadSnapshot(rotated);
        assertFalse(next.getSessionCsrf().verify(value, "session"));
        assertTrue(next.getSessionCsrf().verify(next.getSessionCsrf().issue("session"), "session"));
    }

    @Test
    void httpBrowserOriginsCanBeConfiguredWithoutEnablingWebsockets() {
        Map<String, Object> map = validMap();
        map.put("browserAllowedOrigins", "HTTPS://PUBLIC.example:443");
        map.put("websocketAllowedOrigins", List.of());
        MsalAuthConfig config = new MsalAuthConfig(map);
        assertEquals(java.util.Set.of("https://public.example"), config.getBrowserAllowedOrigins());
        assertTrue(config.getWebsocketAllowedOrigins().isEmpty());
    }
}
