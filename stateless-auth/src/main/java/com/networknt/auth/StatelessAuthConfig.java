package com.networknt.auth;

import com.networknt.config.Config;
import com.networknt.config.schema.ConfigSchema;
import com.networknt.config.schema.OutputFormat;
import com.networknt.config.schema.BooleanField;
import com.networknt.config.schema.IntegerField;
import com.networknt.config.schema.StringField;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.networknt.server.ModuleRegistry;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Config class for StatelessAuthHandler.
 */
@ConfigSchema(
        configKey = "statelessAuth",
        configName = "statelessAuth",
        configDescription = "This handler is generic request handler for the OAuth 2.0 provider authorization code redirect.\n" +
                "It receives the auth code and goes to the OAuth 2.0 provider to get the subject token. The jwt\n" +
                "token is then sent to the browser with two cookies with splitting header/payload and signature.\n" +
                "Another options is to keep the jwt in session and return sessionId to the browser. In either\n" +
                "case, the csrf token will be send with a separate cookie.\n",
        outputFormats = {OutputFormat.JSON_SCHEMA, OutputFormat.YAML}
)
public class StatelessAuthConfig {

    public static final String CONFIG_NAME = "statelessAuth";

    // --- Constant Fields ---
    private static final String ENABLED = "enabled";
    private static final String REDIRECT_URI = "redirectUri";
    private static final String DENY_URI = "denyUri";
    private static final String ENABLE_HTTP2 = "enableHttp2";
    private static final String AUTH_PATH = "authPath";
    private static final String LOGOUT_PATH = "logoutPath";
    private static final String COOKIE_DOMAIN = "cookieDomain";
    private static final String COOKIE_PATH = "cookiePath";
    private static final String COOKIE_TIMEOUT_URI = "cookieTimeoutUri";
    private static final String COOKIE_SECURE = "cookieSecure";
    private static final String SESSION_TIMEOUT = "sessionTimeout";
    private static final String REMEMBER_ME_TIMEOUT = "rememberMeTimeout";
    private static final String BOOTSTRAP_TOKEN = "bootstrapToken";
    private static final String GOOGLE_PATH = "googlePath";
    private static final String GOOGLE_CLIENT_ID = "googleClientId";
    private static final String GOOGLE_CLIENT_SECRET = "googleClientSecret";
    private static final String GOOGLE_REDIRECT_URI = "googleRedirectUri";
    private static final String FACEBOOK_PATH = "facebookPath";
    private static final String FACEBOOK_CLIENT_ID = "facebookClientId";
    private static final String FACEBOOK_CLIENT_SECRET = "facebookClientSecret";
    private static final String GITHUB_PATH = "githubPath";
    private static final String GITHUB_CLIENT_ID = "githubClientId";
    private static final String GITHUB_CLIENT_SECRET = "githubClientSecret";

    private final Config config;
    private Map<String, Object> mappedConfig;
    private static final Map<String, StatelessAuthConfig> instances = new ConcurrentHashMap<>();

    // --- Annotated Fields ---

    @BooleanField(
            configFieldName = ENABLED,
            externalizedKeyName = ENABLED,
            description = "Indicate if the StatelessAuthHandler is enabled or not",
            defaultValue = "true"
    )
    boolean enabled;

    @StringField(
            configFieldName = REDIRECT_URI,
            externalizedKeyName = REDIRECT_URI,
            description = "Once Authorization is done, which path the UI is redirected.",
            defaultValue = "https://localhost:3000/#/app/dashboard"
    )
    String redirectUri;

    @StringField(
            configFieldName = DENY_URI,
            externalizedKeyName = DENY_URI,
            description = "An optional redirect uri if the user deny or cancel the authorization on the Consent page. Default to redirectUri if missing.",
            defaultValue = "https://localhost:3000/#/app/dashboard"
    )
    String denyUri;

    @BooleanField(
            configFieldName = ENABLE_HTTP2,
            externalizedKeyName = ENABLE_HTTP2,
            description = "If HTTP2 should be used for backend calls (e.g., to the OAuth provider).",
            defaultValue = "false"
    )
    boolean enableHttp2;

    @StringField(
            configFieldName = AUTH_PATH,
            externalizedKeyName = AUTH_PATH,
            description = "Request path for the authorization code handling.",
            defaultValue = "/authorization"
    )
    String authPath;

    @StringField(
            configFieldName = LOGOUT_PATH,
            externalizedKeyName = LOGOUT_PATH,
            description = "Request path for the logout handling to remove HttpOnly access-token and other cookies.",
            defaultValue = "/logout"
    )
    String logoutPath;

    @StringField(
            configFieldName = COOKIE_DOMAIN,
            externalizedKeyName = COOKIE_DOMAIN,
            description = "Cookie domain which is the original site.",
            defaultValue = "localhost"
    )
    String cookieDomain;

    @StringField(
            configFieldName = COOKIE_PATH,
            externalizedKeyName = COOKIE_PATH,
            description = "Cookie path.",
            defaultValue = "/"
    )
    String cookiePath;

    @StringField(
            configFieldName = COOKIE_TIMEOUT_URI,
            externalizedKeyName = COOKIE_TIMEOUT_URI,
            description = "Login uri, redirect to it once session is expired.",
            defaultValue = "/"
    )
    String cookieTimeoutUri;

    @BooleanField(
            configFieldName = COOKIE_SECURE,
            externalizedKeyName = COOKIE_SECURE,
            description = "If Cookie is secured.",
            defaultValue = "true"
    )
    boolean cookieSecure;

    @IntegerField(
            configFieldName = SESSION_TIMEOUT,
            externalizedKeyName = SESSION_TIMEOUT,
            description = "Session timeout in seconds. This is the time after which the session will expire.\n" +
                    "Default is 3600 seconds (1 hour).\n",
            defaultValue = "3600"
    )
    int sessionTimeout;

    @IntegerField(
            configFieldName = REMEMBER_ME_TIMEOUT,
            externalizedKeyName = REMEMBER_ME_TIMEOUT,
            description = "Remember me timeout in seconds. This is the time after which the session will expire\n" +
                    "if rememberMe is set true during login. Default is 604800 seconds (7 days).\n",
            defaultValue = "604800"
    )
    int rememberMeTimeout;

    @StringField(
            configFieldName = BOOTSTRAP_TOKEN,
            externalizedKeyName = BOOTSTRAP_TOKEN,
            description = "Bootstrap token used by oauth-kafka to call light-portal services. This is a client credentials token without user info. \n" +
                    "And it is created with a special tool only available to customers.\n",
            defaultValue = "token"
    )
    String bootstrapToken;

    @StringField(
            configFieldName = GOOGLE_PATH,
            externalizedKeyName = GOOGLE_PATH,
            description = "Google Auth Path.",
            defaultValue = "/google"
    )
    String googlePath;

    @StringField(
            configFieldName = GOOGLE_CLIENT_ID,
            externalizedKeyName = GOOGLE_CLIENT_ID,
            description = "Google Client Id.",
            defaultValue = "google_client_id"
    )
    String googleClientId;

    @StringField(
            configFieldName = GOOGLE_CLIENT_SECRET,
            externalizedKeyName = GOOGLE_CLIENT_SECRET,
            description = "Google Client Secret that is retrieved from the environment variable",
            defaultValue = "secret"
    )
    String googleClientSecret;

    @StringField(
            configFieldName = GOOGLE_REDIRECT_URI,
            externalizedKeyName = GOOGLE_REDIRECT_URI,
            description = "Google Redirect URI.",
            defaultValue = "https://localhost:3000"
    )
    String googleRedirectUri;

    @StringField(
            configFieldName = FACEBOOK_PATH,
            externalizedKeyName = FACEBOOK_PATH,
            description = "Facebook Auth Path.",
            defaultValue = "/facebook"
    )
    String facebookPath;

    @StringField(
            configFieldName = FACEBOOK_CLIENT_ID,
            externalizedKeyName = FACEBOOK_CLIENT_ID,
            description = "Facebook Client Id.",
            defaultValue = "facebook_client_id"
    )
    String facebookClientId;

    @StringField(
            configFieldName = FACEBOOK_CLIENT_SECRET,
            externalizedKeyName = FACEBOOK_CLIENT_SECRET,
            description = "Facebook Client Secret that is retrieved from the environment variable",
            defaultValue = "secret"
    )
    String facebookClientSecret;

    @StringField(
            configFieldName = GITHUB_PATH,
            externalizedKeyName = GITHUB_PATH,
            description = "GitHub Auth Path.",
            defaultValue = "/github"
    )
    String githubPath;

    @StringField(
            configFieldName = GITHUB_CLIENT_ID,
            externalizedKeyName = GITHUB_CLIENT_ID,
            description = "GitHub Client Id.",
            defaultValue = "github_client_id"
    )
    String githubClientId;

    @StringField(
            configFieldName = GITHUB_CLIENT_SECRET,
            externalizedKeyName = GITHUB_CLIENT_SECRET,
            description = "GitHub Client Secret that is retrieved from the environment variable",
            defaultValue = "secret"
    )
    String githubClientSecret;


    // --- Constructor and Loading Logic ---

    public StatelessAuthConfig() {
        this(CONFIG_NAME);
    }

    private StatelessAuthConfig(String configName) {
        config = Config.getInstance();
        mappedConfig = config.getJsonMapConfigNoCache(configName);
        setConfigData();
    }

    public static StatelessAuthConfig load() {
        return load(CONFIG_NAME);
    }

    public static StatelessAuthConfig load(String configName) {
        StatelessAuthConfig instance = instances.get(configName);
        if (instance != null) {
            return instance;
        }
        synchronized (StatelessAuthConfig.class) {
            instance = instances.get(configName);
            if (instance != null) {
                return instance;
            }
            instance = new StatelessAuthConfig(configName);
            instances.put(configName, instance);
            if (CONFIG_NAME.equals(configName)) {
                ModuleRegistry.registerModule(CONFIG_NAME, StatelessAuthConfig.class.getName(), Config.getNoneDecryptedInstance().getJsonMapConfigNoCache(CONFIG_NAME), null);
            }
            return instance;
        }
    }

    public static void reload() {
        reload(CONFIG_NAME);
    }

    public static void reload(String configName) {
        synchronized (StatelessAuthConfig.class) {
            StatelessAuthConfig instance = new StatelessAuthConfig(configName);
            instances.put(configName, instance);
            if (CONFIG_NAME.equals(configName)) {
                ModuleRegistry.registerModule(CONFIG_NAME, StatelessAuthConfig.class.getName(), Config.getNoneDecryptedInstance().getJsonMapConfigNoCache(CONFIG_NAME), null);
            }
        }
    }

    // --- Private Config Loader ---
    private void setConfigData() {
        Object object = mappedConfig.get(ENABLED);
        if (object != null) enabled = Config.loadBooleanValue(ENABLED, object);

        object = mappedConfig.get(REDIRECT_URI);
        if (object != null) redirectUri = (String)object;

        object = mappedConfig.get(DENY_URI);
        if (object != null) denyUri = (String)object;

        object = mappedConfig.get(ENABLE_HTTP2);
        if (object != null) enableHttp2 = Config.loadBooleanValue(ENABLE_HTTP2, object);

        object = mappedConfig.get(AUTH_PATH);
        if (object != null) authPath = (String)object;

        object = mappedConfig.get(LOGOUT_PATH);
        if (object != null) logoutPath = (String)object;

        object = mappedConfig.get(COOKIE_DOMAIN);
        if (object != null) cookieDomain = (String)object;

        object = mappedConfig.get(COOKIE_PATH);
        if (object != null) cookiePath = (String)object;

        object = mappedConfig.get(COOKIE_TIMEOUT_URI);
        if (object != null) cookieTimeoutUri = (String)object;

        object = mappedConfig.get(COOKIE_SECURE);
        if (object != null) cookieSecure = Config.loadBooleanValue(COOKIE_SECURE, object);

        object = mappedConfig.get(SESSION_TIMEOUT);
        if (object != null) sessionTimeout = Config.loadIntegerValue(SESSION_TIMEOUT, object);

        object = mappedConfig.get(REMEMBER_ME_TIMEOUT);
        if (object != null) rememberMeTimeout = Config.loadIntegerValue(REMEMBER_ME_TIMEOUT, object);

        object = mappedConfig.get(BOOTSTRAP_TOKEN);
        if (object != null) bootstrapToken = (String)object;

        object = mappedConfig.get(GOOGLE_PATH);
        if (object != null) googlePath = (String)object;

        object = mappedConfig.get(GOOGLE_CLIENT_ID);
        if (object != null) googleClientId = (String)object;

        object = mappedConfig.get(GOOGLE_CLIENT_SECRET);
        if (object != null) googleClientSecret = (String)object;

        object = mappedConfig.get(GOOGLE_REDIRECT_URI);
        if (object != null) googleRedirectUri = (String)object;

        object = mappedConfig.get(FACEBOOK_PATH);
        if (object != null) facebookPath = (String)object;

        object = mappedConfig.get(FACEBOOK_CLIENT_ID);
        if (object != null) facebookClientId = (String)object;

        object = mappedConfig.get(FACEBOOK_CLIENT_SECRET);
        if (object != null) facebookClientSecret = (String)object;

        object = mappedConfig.get(GITHUB_PATH);
        if (object != null) githubPath = (String)object;

        object = mappedConfig.get(GITHUB_CLIENT_ID);
        if (object != null) githubClientId = (String)object;

        object = mappedConfig.get(GITHUB_CLIENT_SECRET);
        if (object != null) githubClientSecret = (String)object;
    }

    // --- Getters and Setters (Original Methods) ---

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

    public int getSessionTimeout() {
        return sessionTimeout;
    }

    public void setSessionTimeout(int sessionTimeout) {
        this.sessionTimeout = sessionTimeout;
    }

    public int getRememberMeTimeout() {
        return rememberMeTimeout;
    }

    public void setRememberMeTimeout(int rememberMeTimeout) {
        this.rememberMeTimeout = rememberMeTimeout;
    }

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
