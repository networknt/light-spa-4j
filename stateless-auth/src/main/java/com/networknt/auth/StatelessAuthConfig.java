/*
 * Copyright (c) 2016 Network New Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.networknt.auth;

/**
 * Created by steve on 29/09/16.
 */
public class StatelessAuthConfig {
    public static final String CONFIG_NAME = "statelessAuth";
    boolean enabled;
    String redirectUri;
    String denyUri;
    boolean enableHttp2;
    String authPath;
    String logoutPath;
    String cookieDomain;
    String cookiePath;
    String cookieTimeoutUri;
    boolean cookieSecure;
    String bootstrapToken;
    String googlePath;
    String googleClientId;
    String googleClientSecret;
    String googleRedirectUri;

    String facebookPath;
    String facebookClientId;
    String facebookClientSecret;

    String githubPath;
    String githubClientId;
    String githubClientSecret;

    public StatelessAuthConfig() {
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public boolean isEnableHttp2() {
        return enableHttp2;
    }

    public void setEnableHttp2(boolean enableHttp2) {
        this.enableHttp2 = enableHttp2;
    }

    public String getAuthPath() { return authPath; }

    public void setAuthPath(String authPath) { this.authPath = authPath; }

    public String getCookieDomain() { return cookieDomain; }

    public void setCookieDomain(String cookieDomain) {
        this.cookieDomain = cookieDomain;
    }

    public String getCookiePath() {
        return cookiePath;
    }

    public void setCookiePath(String cookiePath) {
        this.cookiePath = cookiePath;
    }

    public String getCookieTimeoutUri() { return cookieTimeoutUri; }

    public void setCookieTimeoutUri(String cookieTimeoutUri) { this.cookieTimeoutUri = cookieTimeoutUri; }

    public boolean isCookieSecure() { return cookieSecure; }

    public void setCookieSecure(boolean cookieSecure) { this.cookieSecure = cookieSecure; }

    public String getDenyUri() {
        return denyUri;
    }

    public void setDenyUri(String denyUri) {
        this.denyUri = denyUri;
    }

    public String getLogoutPath() {
        return logoutPath;
    }

    public void setLogoutPath(String logoutPath) {
        this.logoutPath = logoutPath;
    }

    public String getGooglePath() {
        return googlePath;
    }

    public void setGooglePath(String googlePath) {
        this.googlePath = googlePath;
    }

    public String getGoogleClientId() {
        return googleClientId;
    }

    public void setGoogleClientId(String googleClientId) {
        this.googleClientId = googleClientId;
    }

    public String getGoogleClientSecret() {
        return googleClientSecret;
    }

    public void setGoogleClientSecret(String googleClientSecret) {
        this.googleClientSecret = googleClientSecret;
    }

    public String getGoogleRedirectUri() {
        return googleRedirectUri;
    }

    public void setGoogleRedirectUri(String googleRedirectUri) {
        this.googleRedirectUri = googleRedirectUri;
    }

    public String getBootstrapToken() {
        return bootstrapToken;
    }

    public void setBootstrapToken(String bootstrapToken) {
        this.bootstrapToken = bootstrapToken;
    }

    public String getFacebookPath() {
        return facebookPath;
    }

    public void setFacebookPath(String facebookPath) {
        this.facebookPath = facebookPath;
    }

    public String getFacebookClientId() {
        return facebookClientId;
    }

    public void setFacebookClientId(String facebookClientId) {
        this.facebookClientId = facebookClientId;
    }

    public String getFacebookClientSecret() {
        return facebookClientSecret;
    }

    public void setFacebookClientSecret(String facebookClientSecret) {
        this.facebookClientSecret = facebookClientSecret;
    }

    public String getGithubPath() {
        return githubPath;
    }

    public void setGithubPath(String githubPath) {
        this.githubPath = githubPath;
    }

    public String getGithubClientId() {
        return githubClientId;
    }

    public void setGithubClientId(String githubClientId) {
        this.githubClientId = githubClientId;
    }

    public String getGithubClientSecret() {
        return githubClientSecret;
    }

    public void setGithubClientSecret(String githubClientSecret) {
        this.githubClientSecret = githubClientSecret;
    }
}
