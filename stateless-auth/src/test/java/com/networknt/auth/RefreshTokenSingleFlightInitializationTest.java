package com.networknt.auth;

import com.networknt.status.Status;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assertions;

import java.net.URLClassLoader;
import java.util.Map;

class RefreshTokenSingleFlightInitializationTest {
    @Test
    @SuppressWarnings("unchecked")
    void missingLegacyStatusDoesNotPoisonClassInitialization() throws Exception {
        var configField = Status.class.getDeclaredField("config");
        configField.setAccessible(true);
        Map<String, Object> config = (Map<String, Object>) configField.get(null);
        Object original = config.remove("ERR10052");
        String name = RefreshTokenSingleFlight.class.getName();
        // Load a fresh copy to exercise initialization even if other tests already used the class.
        try (var loader = new URLClassLoader(new java.net.URL[]{RefreshTokenSingleFlight.class.getProtectionDomain()
                .getCodeSource().getLocation()}, getClass().getClassLoader()) {
            @Override
            protected Class<?> loadClass(String requested, boolean resolve) throws ClassNotFoundException {
                if (!requested.equals(name) && !requested.startsWith(name + "$")) return super.loadClass(requested, resolve);
                synchronized (getClassLoadingLock(requested)) {
                    Class<?> loaded = findLoadedClass(requested);
                    if (loaded == null) loaded = findClass(requested);
                    if (resolve) resolveClass(loaded);
                    return loaded;
                }
            }
        }) {
            Assertions.assertNotNull(Class.forName(name, true, loader));
            Class<?> resultClass = Class.forName(name + "$RefreshResult", true, loader);
            var failure = resultClass.getDeclaredMethod("failure", Status.class);
            failure.setAccessible(true);
            var classify = resultClass.getMethod("isInvalidRefreshToken");
            Status rawError = new Status(401, "ERR10052", "GET_TOKEN_ERROR", "Cannot get valid token Refresh token not found.");
            Assertions.assertEquals(false, classify.invoke(failure.invoke(null, rawError)));
            if (original != null) config.put("ERR10052", original);
            Status restored = new Status("ERR10052", "Refresh token not found");
            Assertions.assertEquals(true, classify.invoke(failure.invoke(null, restored)), "same loaded class recovers after configuration repair");
        } finally {
            if (original != null) config.put("ERR10052", original);
            else config.remove("ERR10052");
        }
    }
}
