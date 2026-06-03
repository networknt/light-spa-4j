package com.networknt.auth;

import com.networknt.config.Config;
import com.networknt.config.schema.ConfigSchema; // REQUIRED IMPORT
import com.networknt.config.schema.OutputFormat; // REQUIRED IMPORT
import com.networknt.config.schema.BooleanField; // REQUIRED IMPORT
import com.networknt.config.schema.IntegerField; // REQUIRED IMPORT
import com.networknt.config.schema.StringField; // REQUIRED IMPORT

import com.networknt.server.ModuleRegistry;
import java.util.Map;

// <<< REQUIRED ANNOTATION FOR SCHEMA GENERATION >>>
/**
 * Configuration for the MSAL (Microsoft Authentication Library) Exchange Handler.
 * This class manages token exchange and session cookies.
 *
 * @author Steve Hu
 */
public class MsalExchangeConfig {
    /**
     * The name of the configuration file.
     */
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
    private static final String AUTHORIZATION_TOKEN = "authorizationToken";
    private static final String LIGHT_TOKEN_HEADER = "lightTokenHeader";
    public static final String AUTHORIZATION_TOKEN_LIGHT_OAUTH = "light-oauth";
    public static final String AUTHORIZATION_TOKEN_AZURE_MSAL = "azure-msal";
    public static final String DEFAULT_LIGHT_TOKEN_HEADER = "X-Light-Token";

    // --- Annotated Fields ---
    // --- Annotated Fields ---
    private final Map<String, Object> mappedConfig;
    private static volatile MsalExchangeConfig instance;

    @BooleanField(
            configFieldName = ENABLED,
            externalizedKeyName = ENABLED,
            description = "Indicates if the MSAL Exchange is enabled.",
            defaultValue = "true"
    )
    boolean enabled;

    @StringField(
            configFieldName = EXCHANGE_PATH,
            externalizedKeyName = EXCHANGE_PATH,
            description = "The new path your React SPA will call with the Microsoft token.",
            defaultValue = "/auth/ms/exchange"
    )
    String exchangePath;

    @StringField(
            configFieldName = LOGOUT_PATH,
            externalizedKeyName = LOGOUT_PATH,
            description = "The logout path can remain the same.",
            defaultValue = "/auth/ms/logout"
    )
    String logoutPath;

    @StringField(
            configFieldName = COOKIE_DOMAIN,
            externalizedKeyName = COOKIE_DOMAIN,
            description = "The domain to use for the session cookie.",
            defaultValue = "localhost"
    )
    String cookieDomain;

    @StringField(
            configFieldName = COOKIE_PATH,
            externalizedKeyName = COOKIE_PATH,
            description = "The path to use for the session cookie.",
            defaultValue = "/"
    )
    String cookiePath;

    @BooleanField(
            configFieldName = COOKIE_SECURE,
            externalizedKeyName = COOKIE_SECURE,
            description = "If the session cookie should be marked as secure (requires HTTPS).",
            defaultValue = "false"
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
            configFieldName = AUTHORIZATION_TOKEN,
            externalizedKeyName = AUTHORIZATION_TOKEN,
            description = "Token to place in the downstream Authorization header. Supported values are light-oauth and azure-msal.",
            defaultValue = AUTHORIZATION_TOKEN_LIGHT_OAUTH
    )
    String authorizationToken = AUTHORIZATION_TOKEN_LIGHT_OAUTH;

    @StringField(
            configFieldName = LIGHT_TOKEN_HEADER,
            externalizedKeyName = LIGHT_TOKEN_HEADER,
            description = "Header used for the light-oauth token when authorizationToken is azure-msal.",
            defaultValue = DEFAULT_LIGHT_TOKEN_HEADER
    )
    String lightTokenHeader = DEFAULT_LIGHT_TOKEN_HEADER;

    // --- Constructor and Loading Logic ---

    /**
     * Default constructor for MsalExchangeConfig.
     */
    public MsalExchangeConfig() {
        this(CONFIG_NAME);
    }

    private MsalExchangeConfig(String configName) {
        mappedConfig = Config.getInstance().getJsonMapConfig(configName);
        setConfigData();
    }

    /**
     * Loads the configuration from the default configuration file.
     * @return an instance of MsalExchangeConfig
     */
    public static MsalExchangeConfig load() {
        return load(CONFIG_NAME);
    }

    /**
     * Loads the configuration from a specific configuration file.
     * @param configName the name of the configuration file
     * @return an instance of MsalExchangeConfig
     */
    public static MsalExchangeConfig load(String configName) {
        if (CONFIG_NAME.equals(configName)) {
            Map<String, Object> mappedConfig = Config.getInstance().getJsonMapConfig(configName);
            if (instance != null && instance.getMappedConfig() == mappedConfig) {
                return instance;
            }
            synchronized (MsalExchangeConfig.class) {
                mappedConfig = Config.getInstance().getJsonMapConfig(configName);
                if (instance != null && instance.getMappedConfig() == mappedConfig) {
                    return instance;
                }
                instance = new MsalExchangeConfig(configName);
                ModuleRegistry.registerModule(CONFIG_NAME, MsalExchangeConfig.class.getName(), Config.getNoneDecryptedInstance().getJsonMapConfigNoCache(CONFIG_NAME), null);
                return instance;
            }
        }
        return new MsalExchangeConfig(configName);
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

        object = mappedConfig.get(AUTHORIZATION_TOKEN);
        if (object != null) authorizationToken = ((String) object).trim();

        object = mappedConfig.get(LIGHT_TOKEN_HEADER);
        if (object != null) lightTokenHeader = ((String) object).trim();

        validateTokenPlacement();
    }

    private void validateTokenPlacement() {
        if (authorizationToken == null || authorizationToken.trim().length() == 0) {
            authorizationToken = AUTHORIZATION_TOKEN_LIGHT_OAUTH;
        }
        if (!AUTHORIZATION_TOKEN_LIGHT_OAUTH.equals(authorizationToken) && !AUTHORIZATION_TOKEN_AZURE_MSAL.equals(authorizationToken)) {
            throw new IllegalArgumentException("msal-exchange.authorizationToken must be light-oauth or azure-msal");
        }
        if (lightTokenHeader == null || lightTokenHeader.trim().length() == 0) {
            lightTokenHeader = DEFAULT_LIGHT_TOKEN_HEADER;
        }
        if (AUTHORIZATION_TOKEN_AZURE_MSAL.equals(authorizationToken) && "Authorization".equalsIgnoreCase(lightTokenHeader)) {
            throw new IllegalArgumentException("msal-exchange.lightTokenHeader must not be Authorization when authorizationToken is azure-msal");
        }
    }

    /**
     * Returns the mapped configuration.
     * @return the mapped configuration
     */
    public Map<String, Object> getMappedConfig() {
        return mappedConfig;
    }

    // --- Getters and Setters (Original Methods) ---

    /**
     * Indicates if the MSAL Exchange is enabled.
     * @return true if enabled
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether the MSAL Exchange is enabled.
     * @param enabled true if enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Gets the exchange path.
     * @return the exchange path
     */
    public String getExchangePath() {
        return exchangePath;
    }

    /**
     * Sets the exchange path.
     * @param exchangePath the exchange path
     */
    public void setExchangePath(String exchangePath) {
        this.exchangePath = exchangePath;
    }

    /**
     * Gets the logout path.
     * @return the logout path
     */
    public String getLogoutPath() {
        return logoutPath;
    }

    /**
     * Sets the logout path.
     * @param logoutPath the logout path
     */
    public void setLogoutPath(String logoutPath) {
        this.logoutPath = logoutPath;
    }

    /**
     * Gets the cookie domain.
     * @return the cookie domain
     */
    public String getCookieDomain() {
        return cookieDomain;
    }

    /**
     * Sets the cookie domain.
     * @param cookieDomain the cookie domain
     */
    public void setCookieDomain(String cookieDomain) {
        this.cookieDomain = cookieDomain;
    }

    /**
     * Gets the cookie path.
     * @return the cookie path
     */
    public String getCookiePath() {
        return cookiePath;
    }

    /**
     * Sets the cookie path.
     * @param cookiePath the cookie path
     */
    public void setCookiePath(String cookiePath) {
        this.cookiePath = cookiePath;
    }

    /**
     * Indicates if the cookie is secure.
     * @return true if secure
     */
    public boolean isCookieSecure() {
        return cookieSecure;
    }

    /**
     * Sets whether the cookie is secure.
     * @param cookieSecure true if secure
     */
    public void setCookieSecure(boolean cookieSecure) {
        this.cookieSecure = cookieSecure;
    }

    /**
     * Gets the session timeout.
     * @return the session timeout
     */
    public int getSessionTimeout() {
        return sessionTimeout;
    }

    /**
     * Sets the session timeout.
     * @param sessionTimeout the session timeout
     */
    public void setSessionTimeout(int sessionTimeout) {
        this.sessionTimeout = sessionTimeout;
    }

    /**
     * Gets the remember me timeout.
     * @return the remember me timeout
     */
    public int getRememberMeTimeout() {
        return rememberMeTimeout;
    }

    /**
     * Sets the remember me timeout.
     * @param rememberMeTimeout the remember me timeout
     */
    public void setRememberMeTimeout(int rememberMeTimeout) {
        this.rememberMeTimeout = rememberMeTimeout;
    }

    /**
     * Gets the token selected for the downstream Authorization header.
     * @return light-oauth or azure-msal
     */
    public String getAuthorizationToken() {
        return authorizationToken;
    }

    /**
     * Sets the token selected for the downstream Authorization header.
     * @param authorizationToken light-oauth or azure-msal
     */
    public void setAuthorizationToken(String authorizationToken) {
        this.authorizationToken = authorizationToken;
    }

    /**
     * Gets the header used for the light-oauth token in azure-msal placement.
     * @return the light-oauth token header
     */
    public String getLightTokenHeader() {
        return lightTokenHeader;
    }

    /**
     * Sets the header used for the light-oauth token in azure-msal placement.
     * @param lightTokenHeader the light-oauth token header
     */
    public void setLightTokenHeader(String lightTokenHeader) {
        this.lightTokenHeader = lightTokenHeader;
    }

    /**
     * Indicates if Azure MSAL should remain in the downstream Authorization header.
     * @return true if azure-msal placement is enabled
     */
    public boolean isAzureMsalAuthorization() {
        return AUTHORIZATION_TOKEN_AZURE_MSAL.equals(authorizationToken);
    }
}
