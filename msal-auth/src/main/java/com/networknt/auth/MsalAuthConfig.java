package com.networknt.auth;

import com.networknt.config.Config;
import com.networknt.config.JsonMapper;
import com.networknt.config.schema.BooleanField;
import com.networknt.config.schema.IntegerField;
import com.networknt.config.schema.StringField;
import com.networknt.config.schema.ArrayField;
import com.networknt.server.ModuleRegistry;

import java.util.Map;
import java.util.List;
import java.util.Arrays;

/** Configuration for the direct MSAL BFF authentication handler. */
public class MsalAuthConfig {
    public static final String CONFIG_NAME = "msal-auth";
    private static volatile LoadState state;
    private record LoadState(Map<String, Object> source, MsalAuthConfig config, RuntimeException failure) {
        MsalAuthConfig result() {
            if (failure != null) throw failure;
            return config;
        }
    }
    private final Map<String, Object> mappedConfig;

    @BooleanField(configFieldName = "enabled", externalizedKeyName = "enabled",
            description = "Enables direct MSAL authentication.", defaultValue = "true")
    private boolean enabled = true;
    @StringField(configFieldName = "tenantId", externalizedKeyName = "tenantId",
            description = "Required Entra tenant UUID. Common/organizations authorities are not accepted.")
    private String tenantId;
    @StringField(configFieldName = "issuer", externalizedKeyName = "issuer",
            description = "Exact tenant-specific HTTPS issuer from the Entra metadata document.")
    private String issuer;
    @StringField(configFieldName = "audience", externalizedKeyName = "audience",
            description = "Exact audience of this API, not Microsoft Graph or the SPA client.")
    private String audience;
    @ArrayField(configFieldName = "requiredScopes", externalizedKeyName = "requiredScopes", items = String.class,
            description = "Nonempty list of delegated API scopes. Every listed scope is required.")
    private List<String> requiredScopes = List.of();
    @ArrayField(configFieldName = "allowedClientIds", externalizedKeyName = "allowedClientIds", items = String.class,
            description = "Nonempty list of client application UUIDs allowed to establish browser sessions.")
    private List<String> allowedClientIds = List.of();
    private MsalTokenPolicy tokenPolicy;
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
        this(Config.getInstance().getJsonMapConfig(configName));
    }

    MsalAuthConfig(Map<String, Object> config) {
        mappedConfig = config;
        setConfigData();
    }

    public static MsalAuthConfig load() { return load(CONFIG_NAME); }

    public static MsalAuthConfig load(String configName) {
        if (!CONFIG_NAME.equals(configName)) return new MsalAuthConfig(configName);
        Map<String, Object> config = Config.getInstance().getJsonMapConfig(configName);
        return loadSnapshot(config);
    }

    static MsalAuthConfig loadSnapshot(Map<String, Object> config) {
        LoadState current = state;
        if (current != null && current.source == config) return current.result();
        synchronized (MsalAuthConfig.class) {
            current = state;
            if (current != null && current.source == config) return current.result();
            MsalAuthConfig loaded;
            try {
                loaded = new MsalAuthConfig(config);
            } catch (RuntimeException e) {
                state = new LoadState(config, null, e);
                throw e;
            }
            state = new LoadState(config, loaded, null);
            ModuleRegistry.registerModule(CONFIG_NAME, MsalAuthConfig.class.getName(),
                    Config.getNoneDecryptedInstance().getJsonMapConfigNoCache(CONFIG_NAME), null);
            return loaded;
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
        tenantId = stringSetting("tenantId");
        issuer = stringSetting("issuer");
        audience = stringSetting("audience");
        requiredScopes = stringListSetting("requiredScopes");
        allowedClientIds = stringListSetting("allowedClientIds");
        if (enabled) tokenPolicy = new MsalTokenPolicy(tenantId, issuer, audience, requiredScopes, allowedClientIds);
    }

    private String stringSetting(String name) {
        Object value = mappedConfig.get(name);
        if (value == null) return null;
        if (!(value instanceof String text))
            throw new IllegalArgumentException("msal-auth." + name + " must be a string");
        return text;
    }

    private List<String> stringListSetting(String name) {
        Object value = mappedConfig.get(name);
        if (value == null) return List.of();
        if (value instanceof String text) {
            text = text.trim();
            if (text.isEmpty()) return List.of();
            if (text.startsWith("[")) {
                try {
                    value = JsonMapper.fromJson(text, List.class);
                } catch (Exception e) {
                    throw new IllegalArgumentException("msal-auth." + name + " must be an array or comma-separated string");
                }
            } else {
                value = Arrays.stream(text.split(",", -1)).map(String::trim).toList();
            }
        }
        if (!(value instanceof List<?> list) || list.stream().anyMatch(item -> !(item instanceof String)))
            throw new IllegalArgumentException("msal-auth." + name + " must be a list of strings");
        return list.stream().map(String.class::cast).toList();
    }

    MsalTokenPolicy getTokenPolicy() { return tokenPolicy; }
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
