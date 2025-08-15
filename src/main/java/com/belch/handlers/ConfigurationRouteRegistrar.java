package com.belch.handlers;

import com.belch.config.ApiConfig;
import com.belch.database.DatabaseService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.Javalin;
import io.javalin.http.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Responsible for registering configuration management API routes.
 * Provides endpoints for reading, updating, and managing application configuration.
 */
public class ConfigurationRouteRegistrar {
    private static final Logger logger = LoggerFactory.getLogger(ConfigurationRouteRegistrar.class);
    
    private final DatabaseService databaseService;
    private final ApiConfig config;
    private final ObjectMapper objectMapper;
    
    // Configuration profiles storage
    private final Map<String, Map<String, Object>> configProfiles = new ConcurrentHashMap<>();
    
    // Default configuration profile
    private static final String DEFAULT_PROFILE = "default";
    
    /**
     * Constructor for ConfigurationRouteRegistrar
     * @param databaseService The database service for data persistence
     * @param config The API configuration
     */
    public ConfigurationRouteRegistrar(DatabaseService databaseService, ApiConfig config) {
        if (databaseService == null) {
            throw new NullPointerException("DatabaseService cannot be null");
        }
        if (config == null) {
            throw new NullPointerException("ApiConfig cannot be null");
        }
        
        this.databaseService = databaseService;
        this.config = config;
        this.objectMapper = new ObjectMapper();
        
        // Initialize default profile
        initializeDefaultProfile();
    }
    
    /**
     * Register all configuration-related routes.
     * @param app The Javalin app instance
     */
    public void registerRoutes(Javalin app) {
        
        // Get current configuration
        app.get("/config", this::getCurrentConfiguration);
        
        // Update configuration
        app.put("/config", this::updateConfiguration);
        
        // Configuration profiles
        app.get("/config/profiles", this::getConfigurationProfiles);
        app.get("/config/profiles/{profile}", this::getConfigurationProfile);
        app.put("/config/profiles/{profile}", this::saveConfigurationProfile);
        app.delete("/config/profiles/{profile}", this::deleteConfigurationProfile);
        
        // Environment variables
        app.get("/config/environment", this::getEnvironmentVariables);
        
        // Configuration validation
        app.post("/config/validate", this::validateConfiguration);
        
        // Hot reload configuration
        app.post("/config/reload", this::reloadConfiguration);
        
        // Database management
        app.get("/config/databases", this::listDatabases);
        app.delete("/config/databases/{name}", this::deleteDatabase);
        
        logger.info("Configuration management routes registered");
    }
    
    /**
     * Get current configuration
     */
    private void getCurrentConfiguration(Context ctx) {
        try {
            Map<String, Object> currentConfig = new HashMap<>();
            currentConfig.put("api.port", config.getPort());
            currentConfig.put("database.path", config.getDatabasePath());
            currentConfig.put("logging.verbose", config.isVerboseLogging());
            currentConfig.put("session.tag", config.getSessionTag());
            
            // Add runtime information
            Map<String, Object> runtime = new HashMap<>();
            runtime.put("uptime", System.currentTimeMillis());
            runtime.put("java_version", System.getProperty("java.version"));
            runtime.put("working_directory", System.getProperty("user.dir"));
            currentConfig.put("runtime", runtime);
            
            ctx.json(Map.of(
                "status", "success",
                "configuration", currentConfig,
                "timestamp", System.currentTimeMillis()
            ));
            
        } catch (Exception e) {
            logger.error("Failed to get current configuration", e);
            ctx.status(500).json(Map.of(
                "status", "error",
                "message", "Failed to retrieve configuration: " + e.getMessage()
            ));
        }
    }
    
    /**
     * Update configuration with validation and hot reload
     */
    private void updateConfiguration(Context ctx) {
        try {
            Map<String, Object> updateRequest = ctx.bodyAsClass(Map.class);
            Map<String, Object> newConfig = (Map<String, Object>) updateRequest.get("configuration");
            
            if (newConfig == null) {
                ctx.status(400).json(Map.of(
                    "status", "error",
                    "message", "Missing 'configuration' field in request body"
                ));
                return;
            }
            
            // Validate configuration before applying
            List<String> validationErrors = validateConfigurationData(newConfig);
            if (!validationErrors.isEmpty()) {
                ctx.status(400).json(Map.of(
                    "status", "error",
                    "message", "Configuration validation failed",
                    "errors", validationErrors
                ));
                return;
            }
            
            // Store previous configuration for rollback
            Map<String, Object> previousConfig = getCurrentConfigAsMap();
            
            try {
                // Apply configuration changes
                applyConfigurationChanges(newConfig);
                
                // Save to file if requested
                Boolean persist = (Boolean) updateRequest.getOrDefault("persist", false);
                if (persist) {
                    saveConfigurationToFile(newConfig);
                }
                
                ctx.json(Map.of(
                    "status", "success",
                    "message", "Configuration updated successfully",
                    "applied_changes", getChangedFields(previousConfig, newConfig),
                    "timestamp", System.currentTimeMillis()
                ));
                
            } catch (Exception e) {
                // Rollback on failure
                logger.warn("Configuration update failed, rolling back", e);
                applyConfigurationChanges(previousConfig);
                throw e;
            }
            
        } catch (Exception e) {
            logger.error("Failed to update configuration", e);
            ctx.status(500).json(Map.of(
                "status", "error",
                "message", "Failed to update configuration: " + e.getMessage()
            ));
        }
    }
    
    /**
     * Get all configuration profiles
     */
    private void getConfigurationProfiles(Context ctx) {
        try {
            Map<String, Object> response = new HashMap<>();
            response.put("profiles", new ArrayList<>(configProfiles.keySet()));
            response.put("active_profile", DEFAULT_PROFILE);
            response.put("total_profiles", configProfiles.size());
            
            ctx.json(Map.of(
                "status", "success",
                "data", response
            ));
            
        } catch (Exception e) {
            logger.error("Failed to get configuration profiles", e);
            ctx.status(500).json(Map.of(
                "status", "error",
                "message", "Failed to retrieve configuration profiles: " + e.getMessage()
            ));
        }
    }
    
    /**
     * Get specific configuration profile
     */
    private void getConfigurationProfile(Context ctx) {
        try {
            String profileName = ctx.pathParam("profile");
            
            if (!configProfiles.containsKey(profileName)) {
                ctx.status(404).json(Map.of(
                    "status", "error",
                    "message", "Configuration profile not found: " + profileName
                ));
                return;
            }
            
            ctx.json(Map.of(
                "status", "success",
                "profile", profileName,
                "configuration", configProfiles.get(profileName)
            ));
            
        } catch (Exception e) {
            logger.error("Failed to get configuration profile", e);
            ctx.status(500).json(Map.of(
                "status", "error",
                "message", "Failed to retrieve configuration profile: " + e.getMessage()
            ));
        }
    }
    
    /**
     * Save configuration profile
     */
    private void saveConfigurationProfile(Context ctx) {
        try {
            String profileName = ctx.pathParam("profile");
            Map<String, Object> profileConfig = ctx.bodyAsClass(Map.class);
            
            // Validate profile configuration
            List<String> validationErrors = validateConfigurationData(profileConfig);
            if (!validationErrors.isEmpty()) {
                ctx.status(400).json(Map.of(
                    "status", "error",
                    "message", "Profile configuration validation failed",
                    "errors", validationErrors
                ));
                return;
            }
            
            configProfiles.put(profileName, new HashMap<>(profileConfig));
            
            ctx.json(Map.of(
                "status", "success",
                "message", "Configuration profile saved successfully",
                "profile", profileName
            ));
            
        } catch (Exception e) {
            logger.error("Failed to save configuration profile", e);
            ctx.status(500).json(Map.of(
                "status", "error",
                "message", "Failed to save configuration profile: " + e.getMessage()
            ));
        }
    }
    
    /**
     * Delete configuration profile
     */
    private void deleteConfigurationProfile(Context ctx) {
        try {
            String profileName = ctx.pathParam("profile");
            
            if (DEFAULT_PROFILE.equals(profileName)) {
                ctx.status(400).json(Map.of(
                    "status", "error",
                    "message", "Cannot delete the default profile"
                ));
                return;
            }
            
            if (!configProfiles.containsKey(profileName)) {
                ctx.status(404).json(Map.of(
                    "status", "error",
                    "message", "Configuration profile not found: " + profileName
                ));
                return;
            }
            
            configProfiles.remove(profileName);
            
            ctx.json(Map.of(
                "status", "success",
                "message", "Configuration profile deleted successfully",
                "profile", profileName
            ));
            
        } catch (Exception e) {
            logger.error("Failed to delete configuration profile", e);
            ctx.status(500).json(Map.of(
                "status", "error",
                "message", "Failed to delete configuration profile: " + e.getMessage()
            ));
        }
    }
    
    /**
     * Get environment variables related to configuration
     */
    private void getEnvironmentVariables(Context ctx) {
        try {
            Map<String, String> relevantEnvVars = new HashMap<>();
            
            // Filter environment variables relevant to our application
            String[] configEnvVars = {
                "BURP_API_PORT", "BURP_API_DB_PATH", "BURP_API_VERBOSE", "BURP_API_SESSION_TAG"
            };
            
            for (String envVar : configEnvVars) {
                String value = System.getenv(envVar);
                if (value != null) {
                    relevantEnvVars.put(envVar, value);
                }
            }
            
            ctx.json(Map.of(
                "status", "success",
                "environment_variables", relevantEnvVars,
                "total_variables", relevantEnvVars.size()
            ));
            
        } catch (Exception e) {
            logger.error("Failed to get environment variables", e);
            ctx.status(500).json(Map.of(
                "status", "error",
                "message", "Failed to retrieve environment variables: " + e.getMessage()
            ));
        }
    }
    
    /**
     * Validate configuration without applying changes
     */
    private void validateConfiguration(Context ctx) {
        try {
            Map<String, Object> configToValidate = ctx.bodyAsClass(Map.class);
            
            List<String> validationErrors = validateConfigurationData(configToValidate);
            
            if (validationErrors.isEmpty()) {
                ctx.json(Map.of(
                    "status", "success",
                    "message", "Configuration is valid",
                    "validation_passed", true
                ));
            } else {
                ctx.status(400).json(Map.of(
                    "status", "error",
                    "message", "Configuration validation failed",
                    "validation_passed", false,
                    "errors", validationErrors
                ));
            }
            
        } catch (Exception e) {
            logger.error("Failed to validate configuration", e);
            ctx.status(500).json(Map.of(
                "status", "error",
                "message", "Failed to validate configuration: " + e.getMessage()
            ));
        }
    }
    
    /**
     * Hot reload configuration from file
     */
    private void reloadConfiguration(Context ctx) {
        try {
            // Reload configuration from properties file
            Properties properties = new Properties();
            String configFile = "/config/application.properties";
            
            try (InputStream inputStream = getClass().getResourceAsStream(configFile)) {
                if (inputStream != null) {
                    properties.load(inputStream);
                } else {
                    ctx.status(404).json(Map.of(
                        "status", "error",
                        "message", "Configuration file not found: " + configFile
                    ));
                    return;
                }
            }
            
            // Apply configuration from properties
            Map<String, Object> newConfig = new HashMap<>();
            properties.forEach((key, value) -> newConfig.put(key.toString(), value));
            
            applyConfigurationChanges(newConfig);
            
            ctx.json(Map.of(
                "status", "success",
                "message", "Configuration reloaded successfully",
                "reloaded_properties", newConfig.size()
            ));
            
        } catch (Exception e) {
            logger.error("Failed to reload configuration", e);
            ctx.status(500).json(Map.of(
                "status", "error",
                "message", "Failed to reload configuration: " + e.getMessage()
            ));
        }
    }
    
    /**
     * List available databases
     */
    private void listDatabases(Context ctx) {
        try {
            String belchDir = System.getProperty("user.home") + File.separator + ".belch";
            Path belchDirPath = Paths.get(belchDir);
            
            List<Map<String, Object>> databases = new ArrayList<>();
            
            if (Files.exists(belchDirPath) && Files.isDirectory(belchDirPath)) {
                Files.list(belchDirPath)
                    .filter(path -> path.toString().endsWith(".db"))
                    .forEach(dbPath -> {
                        try {
                            Map<String, Object> dbInfo = new HashMap<>();
                            dbInfo.put("name", dbPath.getFileName().toString());
                            dbInfo.put("path", dbPath.toString());
                            dbInfo.put("size", Files.size(dbPath));
                            dbInfo.put("last_modified", Files.getLastModifiedTime(dbPath).toMillis());
                            dbInfo.put("is_current", dbPath.toString().equals(config.getDatabasePath()));
                            databases.add(dbInfo);
                        } catch (IOException e) {
                            logger.warn("Failed to get info for database: {}", dbPath, e);
                        }
                    });
            }
            
            ctx.json(Map.of(
                "status", "success",
                "databases", databases,
                "total_databases", databases.size(),
                "current_database", config.getDatabasePath()
            ));
            
        } catch (Exception e) {
            logger.error("Failed to list databases", e);
            ctx.status(500).json(Map.of(
                "status", "error",
                "message", "Failed to list databases: " + e.getMessage()
            ));
        }
    }
    
    /**
     * Delete a database file
     */
    private void deleteDatabase(Context ctx) {
        try {
            String dbName = ctx.pathParam("name");
            String belchDir = System.getProperty("user.home") + File.separator + ".belch";
            Path dbPath = Paths.get(belchDir, dbName);
            
            // Prevent deletion of current database
            if (dbPath.toString().equals(config.getDatabasePath())) {
                ctx.status(400).json(Map.of(
                    "status", "error",
                    "message", "Cannot delete the currently active database"
                ));
                return;
            }
            
            // Validate file extension for safety
            if (!dbName.endsWith(".db")) {
                ctx.status(400).json(Map.of(
                    "status", "error",
                    "message", "Only .db files can be deleted"
                ));
                return;
            }
            
            // Check if file exists and delete
            if (Files.exists(dbPath)) {
                Files.delete(dbPath);
                logger.info("Deleted database file: {}", dbPath);
                
                ctx.json(Map.of(
                    "status", "success",
                    "message", "Database deleted successfully",
                    "deleted_database", dbName
                ));
            } else {
                ctx.status(404).json(Map.of(
                    "status", "error",
                    "message", "Database file not found: " + dbName
                ));
            }
            
        } catch (Exception e) {
            logger.error("Failed to delete database", e);
            ctx.status(500).json(Map.of(
                "status", "error",
                "message", "Failed to delete database: " + e.getMessage()
            ));
        }
    }
    
    // Helper methods
    
    /**
     * Initialize default configuration profile
     */
    private void initializeDefaultProfile() {
        Map<String, Object> defaultConfig = getCurrentConfigAsMap();
        configProfiles.put(DEFAULT_PROFILE, defaultConfig);
    }
    
    /**
     * Get current configuration as a map
     */
    private Map<String, Object> getCurrentConfigAsMap() {
        Map<String, Object> currentConfig = new HashMap<>();
        currentConfig.put("api.port", config.getPort());
        currentConfig.put("database.path", config.getDatabasePath());
        currentConfig.put("logging.verbose", config.isVerboseLogging());
        currentConfig.put("session.tag", config.getSessionTag());
        return currentConfig;
    }
    
    /**
     * Validate configuration data
     */
    private List<String> validateConfigurationData(Map<String, Object> configData) {
        List<String> errors = new ArrayList<>();
        
        // Validate port
        Object portObj = configData.get("api.port");
        if (portObj != null) {
            try {
                int port = Integer.parseInt(portObj.toString());
                if (port < 1 || port > 65535) {
                    errors.add("Port must be between 1 and 65535");
                }
            } catch (NumberFormatException e) {
                errors.add("Port must be a valid integer");
            }
        }
        
        // Validate database path
        Object dbPathObj = configData.get("database.path");
        if (dbPathObj != null) {
            String dbPath = dbPathObj.toString();
            if (dbPath.trim().isEmpty()) {
                errors.add("Database path cannot be empty");
            }
        }
        
        // Validate verbose logging
        Object verboseObj = configData.get("logging.verbose");
        if (verboseObj != null && !(verboseObj instanceof Boolean)) {
            String verboseStr = verboseObj.toString().toLowerCase();
            if (!verboseStr.equals("true") && !verboseStr.equals("false")) {
                errors.add("Verbose logging must be true or false");
            }
        }
        
        return errors;
    }
    
    /**
     * Apply configuration changes to the config object
     */
    private void applyConfigurationChanges(Map<String, Object> newConfig) {
        Object portObj = newConfig.get("api.port");
        if (portObj != null) {
            config.setPort(Integer.parseInt(portObj.toString()));
        }
        
        Object dbPathObj = newConfig.get("database.path");
        if (dbPathObj != null) {
            config.setDatabasePath(dbPathObj.toString());
        }
        
        Object verboseObj = newConfig.get("logging.verbose");
        if (verboseObj != null) {
            boolean verbose = verboseObj instanceof Boolean ? 
                (Boolean) verboseObj : Boolean.parseBoolean(verboseObj.toString());
            config.setVerboseLogging(verbose);
        }
        
        Object sessionTagObj = newConfig.get("session.tag");
        if (sessionTagObj != null) {
            config.setSessionTag(sessionTagObj.toString());
        }
    }
    
    /**
     * Get fields that changed between configurations
     */
    private List<String> getChangedFields(Map<String, Object> oldConfig, Map<String, Object> newConfig) {
        List<String> changedFields = new ArrayList<>();
        
        for (String key : newConfig.keySet()) {
            Object oldValue = oldConfig.get(key);
            Object newValue = newConfig.get(key);
            
            if (!Objects.equals(oldValue, newValue)) {
                changedFields.add(key);
            }
        }
        
        return changedFields;
    }
    
    /**
     * Save configuration to properties file
     */
    private void saveConfigurationToFile(Map<String, Object> configData) throws IOException {
        String configDir = System.getProperty("user.home") + File.separator + ".belch";
        String configFile = configDir + File.separator + "extension.properties";
        
        // Ensure directory exists
        Files.createDirectories(Paths.get(configDir));
        
        Properties properties = new Properties();
        configData.forEach((key, value) -> properties.setProperty(key, value.toString()));
        
        try (FileOutputStream fos = new FileOutputStream(configFile)) {
            properties.store(fos, "Belch API Configuration - Updated via API");
        }
        
        logger.info("Configuration saved to file: {}", configFile);
    }
}