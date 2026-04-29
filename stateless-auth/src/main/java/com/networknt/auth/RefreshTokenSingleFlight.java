package com.networknt.auth;

import com.networknt.client.oauth.OauthHelper;
import com.networknt.client.oauth.RefreshTokenRequest;
import com.networknt.client.oauth.TokenRequest;
import com.networknt.client.oauth.TokenResponse;
import com.networknt.monad.Result;
import com.networknt.status.Status;
import com.networknt.utility.UuidUtil;
import org.slf4j.Logger;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public final class RefreshTokenSingleFlight {
    private static final long REFRESH_WAIT_TIMEOUT_MILLIS = 5000L;
    private static final long REFRESH_COMPLETED_CACHE_MILLIS = 3000L;
    private static final int MAX_REFRESH_TRACKED_ENTRIES = 10000;

    private static final ConcurrentHashMap<String, CompletableFuture<RefreshResult>> refreshInFlight = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, CachedRefreshResult> refreshCompleted = new ConcurrentHashMap<>();

    private RefreshTokenSingleFlight() {
    }

    public static RefreshResult renew(String refreshToken, Logger logger) throws Exception {
        String key = refreshTokenKey(refreshToken);
        cleanupRefreshCaches();
        CachedRefreshResult cached = refreshCompleted.get(key);
        if (cached != null) {
            if (cached.expiresAtMillis > System.currentTimeMillis()) {
                if (logger.isDebugEnabled()) logger.debug("Reusing completed refresh result for token hash {}", shortKey(key));
                return cached.result;
            }
            refreshCompleted.remove(key, cached);
        }

        CompletableFuture<RefreshResult> ownerFuture = new CompletableFuture<>();
        CompletableFuture<RefreshResult> existingFuture = refreshInFlight.putIfAbsent(key, ownerFuture);
        if (existingFuture == null) {
            try {
                if (logger.isDebugEnabled()) logger.debug("Starting refresh for token hash {}", shortKey(key));
                RefreshResult result = refreshToken(refreshToken);
                if (result.isSuccess()) {
                    refreshCompleted.put(key, new CachedRefreshResult(result, System.currentTimeMillis() + REFRESH_COMPLETED_CACHE_MILLIS));
                }
                ownerFuture.complete(result);
                return result;
            } catch (Exception e) {
                ownerFuture.completeExceptionally(e);
                throw e;
            } finally {
                refreshInFlight.remove(key, ownerFuture);
            }
        }

        if (logger.isDebugEnabled()) logger.debug("Waiting for in-flight refresh for token hash {}", shortKey(key));
        return existingFuture.get(REFRESH_WAIT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
    }

    private static RefreshResult refreshToken(String refreshToken) {
        TokenRequest tokenRequest = new RefreshTokenRequest();
        String csrf = UuidUtil.uuidToBase64(UuidUtil.getUUID());
        tokenRequest.setCsrf(csrf);
        ((RefreshTokenRequest) tokenRequest).setRefreshToken(refreshToken);
        Result<TokenResponse> result = OauthHelper.getTokenResult(tokenRequest);
        if (result.isSuccess()) {
            return RefreshResult.success(result.getResult(), csrf);
        }
        return RefreshResult.failure(result.getError());
    }

    private static void cleanupRefreshCaches() {
        if (refreshInFlight.size() + refreshCompleted.size() <= MAX_REFRESH_TRACKED_ENTRIES) {
            return;
        }
        long now = System.currentTimeMillis();
        refreshCompleted.entrySet().removeIf(entry -> entry.getValue().expiresAtMillis <= now);
        if (refreshInFlight.size() + refreshCompleted.size() > MAX_REFRESH_TRACKED_ENTRIES) {
            refreshCompleted.clear();
        }
    }

    private static String refreshTokenKey(String refreshToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest.digest(refreshToken.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    private static String shortKey(String key) {
        return key.length() <= 12 ? key : key.substring(0, 12);
    }

    public static final class RefreshResult {
        private final TokenResponse response;
        private final String csrf;
        private final Status error;

        private RefreshResult(TokenResponse response, String csrf, Status error) {
            this.response = response;
            this.csrf = csrf;
            this.error = error;
        }

        private static RefreshResult success(TokenResponse response, String csrf) {
            return new RefreshResult(response, csrf, null);
        }

        private static RefreshResult failure(Status error) {
            return new RefreshResult(null, null, error);
        }

        public TokenResponse getResponse() {
            return response;
        }

        public String getCsrf() {
            return csrf;
        }

        public Status getError() {
            return error;
        }

        public boolean isSuccess() {
            return error == null;
        }
    }

    private static class CachedRefreshResult {
        private final RefreshResult result;
        private final long expiresAtMillis;

        private CachedRefreshResult(RefreshResult result, long expiresAtMillis) {
            this.result = result;
            this.expiresAtMillis = expiresAtMillis;
        }
    }
}
