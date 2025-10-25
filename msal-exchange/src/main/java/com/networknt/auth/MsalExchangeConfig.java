package com.networknt.auth;

import com.networknt.config.Config;
import com.networknt.config.schema.ConfigSchema; // REQUIRED IMPORT
import com.networknt.config.schema.OutputFormat; // REQUIRED IMPORT
import com.networknt.config.schema.BooleanField; // REQUIRED IMPORT
import com.networknt.config.schema.IntegerField; // REQUIRED IMPORT
import com.networknt.config.schema.StringField; // REQUIRED IMPORT

import java.util.Map;

// <<< REQUIRED ANNOTATION FOR SCHEMA GENERATION >>>
@ConfigSchema(
        configKey = "msal-exchange",
        configName = "msal-exchange",
        configDescription = "Configuration for the MSAL (Microsoft Authentication Library) Exchange Handler, managing token exchange and session cookies.",
        outputFormats = {OutputFormat.JSON_SCHEMA, OutputFormat.YAML}
)
public class MsalExchangeConfig {
    public static final String CONFIG_NAME = "msal-exchange";

    // --- Constant Fields ---
    private static final String ENABLED = "enabled";
    private static final String EXCHANGE_PATH = "exchangePath";
    private static final String LOGOUT_PATH = "logoutPath";
    private static final String COOKIE_DOMAIN = "cookieDomain";
    private static final String COOKIE_PATH = "cookiePath";
    private static final String COOKIE_SECURE = "cookieSecure";
    private static final String SESSION_TIMEOUT = "sessionTimeout";
    private static final String REMEMBER_ME_TIMEOUT = "rememberMeTimeout";

    // --- Annotated Fields ---
    private final Config config;
    private Map<String, Object> mappedConfig;

    @BooleanField(
            configFieldName = ENABLED,
            externalizedKeyName = ENABLED,
            description = "Indicates if the MSAL Exchange is enabled.",
            externalized = true,
            defaultValue = "true"
    )
    boolean enabled;

    @StringField(
            configFieldName = EXCHANGE_PATH,
            externalizedKeyName = EXCHANGE_PATH,
            description = "The new path your React SPA will call with the Microsoft token.",
            externalized = true,
            defaultValue = "/auth/ms/exchange"
    )
    String exchangePath;

    @StringField(
            configFieldName = LOGOUT_PATH,
            externalizedKeyName = LOGOUT_PATH,
            description = "The logout path can remain the same.",
            externalized = true,
            defaultValue = "/auth/ms/logout"
    )
    String logoutPath;

    @StringField(
            configFieldName = COOKIE_DOMAIN,
            externalizedKeyName = COOKIE_DOMAIN,
            description = "The domain to use for the session cookie.",
            externalized = true,
            defaultValue = "localhost"
    )
    String cookieDomain;

    @StringField(
            configFieldName = COOKIE_PATH,
            externalizedKeyName = COOKIE_PATH,
            description = "The path to use for the session cookie.",
            externalized = true,
            defaultValue = "/"
    )
    String cookiePath;

    @BooleanField(
            configFieldName = COOKIE_SECURE,
            externalizedKeyName = COOKIE_SECURE,
            description = "If the session cookie should be marked as secure (requires HTTPS).",
            externalized = true,
            defaultValue = "false"
    )
    boolean cookieSecure;

    @IntegerField(
            configFieldName = SESSION_TIMEOUT,
            externalizedKeyName = SESSION_TIMEOUT,
            description = "Session timeout in seconds. This is the time after which the session will expire.\n" +
                    "Default is 3600 seconds (1 hour).\n",
            externalized = true,
            defaultValue = "3600"
    )
    int sessionTimeout;

    @IntegerField(
            configFieldName = REMEMBER_ME_TIMEOUT,
            externalizedKeyName = REMEMBER_ME_TIMEOUT,
            description = "Remember me timeout in seconds. This is the time after which the session will expire\n" +
                    "if rememberMe is set true during login. Default is 604800 seconds (7 days).\n",
            externalized = true,
            defaultValue = "604800"
    )
    int rememberMeTimeout;

    // --- Constructor and Loading Logic ---

    public MsalExchangeConfig() {
        this(CONFIG_NAME);
    }

    private MsalExchangeConfig(String configName) {
        config = Config.getInstance();
        mappedConfig = config.getJsonMapConfigNoCache(configName);
        setConfigData();
    }

    public static MsalExchangeConfig load() {
        return new MsalExchangeConfig();
    }

    public static MsalExchangeConfig load(String configName) {
        return new MsalExchangeConfig(configName);
    }

    public void reload() {
        mappedConfig = config.getJsonMapConfigNoCache(CONFIG_NAME);
        setConfigData();
    }

    private void setConfigData() {
        // Load fields using Config utilities, consistent with the framework's internal loading
        Object object = mappedConfig.get(ENABLED);
        if (object != null) enabled = Config.loadBooleanValue(ENABLED, object);

        object = mappedConfig.get(EXCHANGE_PATH);
        if (object != null) exchangePath = (String) object;

        object = mappedConfig.get(LOGOUT_PATH);
        if (object != null) logoutPath = (String) object;

        object = mappedConfig.get(COOKIE_DOMAIN);
        if (object != null) cookieDomain = (String) object;

        object = mappedConfig.get(COOKIE_PATH);
        if (object != null) cookiePath = (String) object;

        object = mappedConfig.get(COOKIE_SECURE);
        if (object != null) cookieSecure = Config.loadBooleanValue(COOKIE_SECURE, object);

        object = mappedConfig.get(SESSION_TIMEOUT);
        if (object != null) sessionTimeout = Config.loadIntegerValue(SESSION_TIMEOUT, object);

        object = mappedConfig.get(REMEMBER_ME_TIMEOUT);
        if (object != null) rememberMeTimeout = Config.loadIntegerValue(REMEMBER_ME_TIMEOUT, object);
    }

    // --- Getters and Setters (Original Methods) ---

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getExchangePath() {
        return exchangePath;
    }

    public void setExchangePath(String exchangePath) {
        this.exchangePath = exchangePath;
    }

    public String getLogoutPath() {
        return logoutPath;
    }

    public void setLogoutPath(String logoutPath) {
        this.logoutPath = logoutPath;
    }

    public String getCookieDomain() {
        return cookieDomain;
    }

    public void setCookieDomain(String cookieDomain) {
        this.cookieDomain = cookieDomain;
    }

    public String getCookiePath() {
        return cookiePath;
    }

    public void setCookiePath(String cookiePath) {
        this.cookiePath = cookiePath;
    }

    public boolean isCookieSecure() {
        return cookieSecure;
    }

    public void setCookieSecure(boolean cookieSecure) {
        this.cookieSecure = cookieSecure;
    }

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
}
