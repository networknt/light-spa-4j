package com.networknt.auth;

import com.networknt.config.Config;
import com.networknt.config.schema.BooleanField;
import com.networknt.config.schema.IntegerField;
import com.networknt.config.schema.StringField;
import com.networknt.server.ModuleRegistry;

import java.util.Map;

/** Configuration for the direct MSAL BFF authentication handler. */
public class MsalAuthConfig {
    public static final String CONFIG_NAME = "msal-auth";
    private static volatile MsalAuthConfig instance;
    private final Map<String, Object> mappedConfig;

    @BooleanField(configFieldName = "enabled", externalizedKeyName = "enabled",
            description = "Enables direct MSAL authentication.", defaultValue = "true")
    private boolean enabled = true;
    @StringField(configFieldName = "loginPath", externalizedKeyName = "loginPath",
            description = "Endpoint used to establish an MSAL-backed gateway session.", defaultValue = "/auth/ms/login")
    private String loginPath = "/auth/ms/login";
    @StringField(configFieldName = "logoutPath", externalizedKeyName = "logoutPath",
            description = "Endpoint used to clear the MSAL-backed gateway session.", defaultValue = "/auth/ms/logout")
    private String logoutPath = "/auth/ms/logout";
    @BooleanField(configFieldName = "logoutCsrfEnforced", externalizedKeyName = "logoutCsrfEnforced",
            description = "Enforces double-submit CSRF validation on logout.", defaultValue = "false")
    private boolean logoutCsrfEnforced;
    @StringField(configFieldName = "cookieDomain", externalizedKeyName = "cookieDomain",
            description = "Domain for session cookies.", defaultValue = "localhost")
    private String cookieDomain = "localhost";
    @StringField(configFieldName = "cookiePath", externalizedKeyName = "cookiePath",
            description = "Path for session cookies.", defaultValue = "/")
    private String cookiePath = "/";
    @BooleanField(configFieldName = "cookieSecure", externalizedKeyName = "cookieSecure",
            description = "Marks session cookies Secure.", defaultValue = "false")
    private boolean cookieSecure;
    @IntegerField(configFieldName = "sessionTimeout", externalizedKeyName = "sessionTimeout",
            description = "Maximum session-cookie lifetime in seconds.", defaultValue = "3600")
    private int sessionTimeout = 3600;
    @StringField(configFieldName = "cookieSameSite", externalizedKeyName = "cookieSameSite",
            description = "SameSite mode for session cookies.", defaultValue = "None")
    private String cookieSameSite = "None";

    public MsalAuthConfig() { this(CONFIG_NAME); }

    private MsalAuthConfig(String configName) {
        mappedConfig = Config.getInstance().getJsonMapConfig(configName);
        setConfigData();
    }

    public static MsalAuthConfig load() { return load(CONFIG_NAME); }

    public static MsalAuthConfig load(String configName) {
        if (!CONFIG_NAME.equals(configName)) return new MsalAuthConfig(configName);
        Map<String, Object> config = Config.getInstance().getJsonMapConfig(configName);
        if (instance != null && instance.mappedConfig == config) return instance;
        synchronized (MsalAuthConfig.class) {
            config = Config.getInstance().getJsonMapConfig(configName);
            if (instance != null && instance.mappedConfig == config) return instance;
            instance = new MsalAuthConfig(configName);
            ModuleRegistry.registerModule(CONFIG_NAME, MsalAuthConfig.class.getName(),
                    Config.getNoneDecryptedInstance().getJsonMapConfigNoCache(CONFIG_NAME), null);
            return instance;
        }
    }

    private void setConfigData() {
        Object value = mappedConfig.get("enabled");
        if (value != null) enabled = Config.loadBooleanValue("enabled", value);
        value = mappedConfig.get("loginPath"); if (value != null) loginPath = (String) value;
        value = mappedConfig.get("logoutPath"); if (value != null) logoutPath = (String) value;
        value = mappedConfig.get("logoutCsrfEnforced");
        if (value != null) logoutCsrfEnforced = Config.loadBooleanValue("logoutCsrfEnforced", value);
        value = mappedConfig.get("cookieDomain"); if (value != null) cookieDomain = (String) value;
        value = mappedConfig.get("cookiePath"); if (value != null) cookiePath = (String) value;
        value = mappedConfig.get("cookieSecure");
        if (value != null) cookieSecure = Config.loadBooleanValue("cookieSecure", value);
        value = mappedConfig.get("sessionTimeout");
        if (value != null) sessionTimeout = Config.loadIntegerValue("sessionTimeout", value);
        value = mappedConfig.get("cookieSameSite"); if (value != null) cookieSameSite = (String) value;
    }

    public boolean isEnabled() { return enabled; }
    public String getLoginPath() { return loginPath; }
    public String getLogoutPath() { return logoutPath; }
    public boolean isLogoutCsrfEnforced() { return logoutCsrfEnforced; }
    public String getCookieDomain() { return cookieDomain; }
    public String getCookiePath() { return cookiePath; }
    public boolean isCookieSecure() { return cookieSecure; }
    public int getSessionTimeout() { return sessionTimeout; }
    public String getCookieSameSite() { return cookieSameSite; }
    Map<String, Object> getMappedConfig() { return mappedConfig; }
}
