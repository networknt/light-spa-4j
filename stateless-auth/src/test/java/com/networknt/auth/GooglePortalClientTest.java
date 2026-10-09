package com.networknt.auth;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class GooglePortalClientTest {
    @Test void distinguishesAccountProblemsFromGatewayAuthenticationFailures() {
        assertEquals("GOOGLE_ACCOUNT_LINK_REQUIRED", GooglePortalClient.rejection(409, "{}").getError().getCode());
        assertEquals("PORTAL_ACCOUNT_UNAVAILABLE", GooglePortalClient.rejection(403, "{\"code\":\"PORTAL_ACCOUNT_UNAVAILABLE\"}").getError().getCode());
        for (int status : new int[]{401, 403, 404, 500, 503}) {
            assertEquals(503, GooglePortalClient.rejection(status, "{}").getError().getStatusCode());
            assertEquals("GOOGLE_IDENTITY_UNAVAILABLE", GooglePortalClient.rejection(status, "{}").getError().getCode());
        }
    }
}
