package com.belch.ui.model;

import burp.api.montoya.MontoyaApi;
import com.belch.config.ApiConfig;

/**
 * Model class for configuration data
 */
public class ConfigModel {
    private final ApiConfig apiConfig;
    private final MontoyaApi api;
    
    private String port;
    private String host;
    private String databasePath;
    private String sessionTag;
    private boolean verboseLogging;
    private boolean isDarkMode;

    public ConfigModel(MontoyaApi api, ApiConfig apiConfig) {
        this.api = api;
        this.apiConfig = apiConfig;
        loadFromConfig();
    }

    private void loadFromConfig() {
        this.port = String.valueOf(apiConfig.getPort());
        this.host = "127.0.0.1"; // Default host since ApiConfig doesn't have getHost()
        this.databasePath = apiConfig.getDatabasePath();
        this.sessionTag = apiConfig.getSessionTag();
        this.verboseLogging = apiConfig.isVerboseLogging();
    }

    public void saveToConfig() {
        apiConfig.setPort(Integer.parseInt(port));
        // Note: ApiConfig doesn't have setHost() method - host is managed in UI only
        apiConfig.setDatabasePath(databasePath);
        apiConfig.setSessionTag(sessionTag);
        apiConfig.setVerboseLogging(verboseLogging);
    }

    // Getters and setters
    public String getPort() { return port; }
    public void setPort(String port) { this.port = port; }
    
    public String getHost() { return host; }
    public void setHost(String host) { this.host = host; }
    
    public String getDatabasePath() { return databasePath; }
    public void setDatabasePath(String path) { this.databasePath = path; }
    
    public String getSessionTag() { return sessionTag; }
    public void setSessionTag(String tag) { this.sessionTag = tag; }
    
    public boolean isVerboseLogging() { return verboseLogging; }
    public void setVerboseLogging(boolean verbose) { this.verboseLogging = verbose; }
    
    public boolean isDarkMode() { return isDarkMode; }
    public void setDarkMode(boolean darkMode) { this.isDarkMode = darkMode; }

    public boolean validatePort() {
        try {
            int portNum = Integer.parseInt(port);
            return portNum >= 1024 && portNum <= 65535;
        } catch (NumberFormatException e) {
            return false;
        }
    }
} 