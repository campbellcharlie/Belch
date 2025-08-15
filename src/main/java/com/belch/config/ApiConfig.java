package com.belch.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.io.File;

/**
 * Configuration class for the Belch - Burp Suite REST API Extension.
 * Manages all configuration settings including port, database path,
 * and other runtime parameters.
 * 
 * @author Charlie Campbell
 * @version 1.0.0
 */
public class ApiConfig {
    
    private static final Logger logger = LoggerFactory.getLogger(ApiConfig.class);
    
    // Default configuration values
    private static final int DEFAULT_PORT = 7850;
    private static final String DEFAULT_DB_PATH = "belch.db";
    private static final boolean DEFAULT_VERBOSE_LOGGING = false;
    private static final String DEFAULT_SESSION_TAG = ""; // Will be auto-generated if empty
    
    // Configuration keys
    private static final String CONFIG_FILE = "/config/application.properties";
    private static final String PORT_KEY = "api.port";
    private static final String DB_PATH_KEY = "database.path";
    private static final String VERBOSE_LOGGING_KEY = "logging.verbose";
    private static final String SESSION_TAG_KEY = "session.tag";
    
    // Configuration values
    private int port;
    private String databasePath;
    private boolean verboseLogging;
    private String sessionTag;
    
    /**
     * Constructor that loads configuration from properties file
     * with fallback to environment variables and defaults.
     */
    public ApiConfig() {
        // First, try to load from UI saved configuration
        loadFromUiConfiguration();
        
        // Then load from properties file (can override UI config)
        Properties properties = loadProperties();
        
        // Load configuration with fallbacks to environment variables and defaults
        this.port = getIntProperty(properties, PORT_KEY, "BURP_API_PORT", this.port != 0 ? this.port : DEFAULT_PORT);
        String configuredDbPath = getStringProperty(properties, DB_PATH_KEY, "BURP_API_DB_PATH", this.databasePath != null ? this.databasePath : DEFAULT_DB_PATH);
        
        // Apply path conversion logic for database path
        if (!configuredDbPath.startsWith("/") && !configuredDbPath.contains(":")) {
            String defaultDbDir = System.getProperty("user.home") + File.separator + ".belch";
            File dbDir = new File(defaultDbDir);
            if (!dbDir.exists()) {
                dbDir.mkdirs();
                logger.info("Created database directory: {}", defaultDbDir);
            }
            this.databasePath = defaultDbDir + File.separator + configuredDbPath;
            logger.info("Converted relative database path to absolute: {}", this.databasePath);
        } else {
            this.databasePath = configuredDbPath;
        }
        
        this.verboseLogging = getBooleanProperty(properties, VERBOSE_LOGGING_KEY, "BURP_API_VERBOSE", this.verboseLogging);
        
        // Handle session tag with auto-generation if empty/null
        String configuredSessionTag = getStringProperty(properties, SESSION_TAG_KEY, "BURP_API_SESSION_TAG", this.sessionTag != null ? this.sessionTag : DEFAULT_SESSION_TAG);
        this.sessionTag = generateSessionTagIfNeeded(configuredSessionTag);
        
        logger.info("Configuration loaded - Port: {}, Database: {}, Verbose: {}, Session Tag: '{}'", 
                   port, databasePath, verboseLogging, sessionTag);
        logger.info("🐛 CONFIG DEBUG: configured DB path: '{}', default: '{}', final path: '{}'", 
                   configuredDbPath, DEFAULT_DB_PATH, this.databasePath);
                   
        // Apply initial verbose logging setting
        com.belch.logging.ApiLogger.setVerbose(verboseLogging);
    }
    
    /**
     * Loads configuration from the UI configuration file if it exists.
     */
    private void loadFromUiConfiguration() {
        try {
            // Import ConfigurationPanel statically to avoid circular dependency
            String configDir = System.getProperty("user.home") + File.separator + ".belch";
            String configFile = configDir + File.separator + "extension.properties";
            
            File uiConfigFile = new File(configFile);
            if (!uiConfigFile.exists()) {
                // Initialize with smart defaults
                this.port = DEFAULT_PORT;
                this.verboseLogging = DEFAULT_VERBOSE_LOGGING;
                this.sessionTag = generateSessionTagIfNeeded(DEFAULT_SESSION_TAG);
                
                // Create default database directory and path
                String defaultDbDir = System.getProperty("user.home") + File.separator + ".belch";
                File dbDir = new File(defaultDbDir);
                if (!dbDir.exists()) {
                    dbDir.mkdirs();
                    logger.info("Created default database directory: {}", defaultDbDir);
                }
                this.databasePath = defaultDbDir + File.separator + "belch.db";
                logger.info("Using default database path: {}", this.databasePath);
                return;
            }
            
            Properties uiProps = new Properties();
            try (InputStream fis = new java.io.FileInputStream(uiConfigFile)) {
                uiProps.load(fis);
            }
            
            // Load UI configuration
            this.port = Integer.parseInt(uiProps.getProperty("api.port", String.valueOf(DEFAULT_PORT)));
            String configuredDbPath = uiProps.getProperty("database.path", DEFAULT_DB_PATH);
            
            // If the configured path is relative, make it absolute in the user's home
            if (!configuredDbPath.startsWith("/") && !configuredDbPath.contains(":")) {
                String defaultDbDir = System.getProperty("user.home") + File.separator + ".belch";
                File dbDir = new File(defaultDbDir);
                if (!dbDir.exists()) {
                    dbDir.mkdirs();
                    logger.info("Created database directory: {}", defaultDbDir);
                }
                this.databasePath = defaultDbDir + File.separator + configuredDbPath;
                logger.info("Converted relative database path to absolute: {}", this.databasePath);
            } else {
                this.databasePath = configuredDbPath;
            }
            
            this.verboseLogging = Boolean.parseBoolean(uiProps.getProperty("logging.verbose", String.valueOf(DEFAULT_VERBOSE_LOGGING)));
            this.sessionTag = generateSessionTagIfNeeded(uiProps.getProperty("session.tag", DEFAULT_SESSION_TAG));
            
            logger.debug("Loaded configuration from UI config file: {}", configFile);
            
        } catch (Exception e) {
            logger.debug("No UI configuration found or failed to load, using defaults: {}", e.getMessage());
            // Initialize with smart defaults
            this.port = DEFAULT_PORT;
            this.verboseLogging = DEFAULT_VERBOSE_LOGGING;
            this.sessionTag = generateSessionTagIfNeeded(DEFAULT_SESSION_TAG);
            
            // Create default database directory and path
            String defaultDbDir = System.getProperty("user.home") + File.separator + ".belch";
            File dbDir = new File(defaultDbDir);
            if (!dbDir.exists()) {
                dbDir.mkdirs();
                logger.info("Created default database directory: {}", defaultDbDir);
            }
            this.databasePath = defaultDbDir + File.separator + "belch.db";
            logger.info("Using default database path: {}", this.databasePath);
        }
    }
    
    /**
     * Loads properties from the configuration file.
     * 
     * @return Properties object with loaded configuration
     */
    private Properties loadProperties() {
        Properties properties = new Properties();
        
        try (InputStream inputStream = getClass().getResourceAsStream(CONFIG_FILE)) {
            if (inputStream != null) {
                properties.load(inputStream);
                logger.debug("Configuration file loaded successfully");
            } else {
                logger.warn("Configuration file not found: {}, using defaults", CONFIG_FILE);
            }
        } catch (IOException e) {
            logger.warn("Failed to load configuration file: {}, using defaults", CONFIG_FILE, e);
        }
        
        return properties;
    }
    
    /**
     * Gets an integer property with environment variable and default fallback.
     */
    private int getIntProperty(Properties properties, String propertyKey, String envKey, int defaultValue) {
        String value = properties.getProperty(propertyKey);
        if (value == null) {
            value = System.getenv(envKey);
        }
        
        if (value != null) {
            try {
                return Integer.parseInt(value.trim());
            } catch (NumberFormatException e) {
                logger.warn("Invalid integer value for {}: {}, using default: {}", propertyKey, value, defaultValue);
            }
        }
        
        return defaultValue;
    }
    
    /**
     * Gets a string property with environment variable and default fallback.
     */
    private String getStringProperty(Properties properties, String propertyKey, String envKey, String defaultValue) {
        String value = properties.getProperty(propertyKey);
        if (value == null) {
            value = System.getenv(envKey);
        }
        
        return value != null ? value.trim() : defaultValue;
    }
    
    /**
     * Gets a boolean property with environment variable and default fallback.
     */
    private boolean getBooleanProperty(Properties properties, String propertyKey, String envKey, boolean defaultValue) {
        String value = properties.getProperty(propertyKey);
        if (value == null) {
            value = System.getenv(envKey);
        }
        
        if (value != null) {
            return Boolean.parseBoolean(value.trim());
        }
        
        return defaultValue;
    }
    
    /**
     * Generates a session tag if the provided one is null or empty.
     * Creates a meaningful default using timestamp and session info.
     * 
     * @param configuredTag The configured session tag (may be null/empty)
     * @return A valid session tag (auto-generated if needed)
     */
    private String generateSessionTagIfNeeded(String configuredTag) {
        if (configuredTag != null && !configuredTag.trim().isEmpty()) {
            return configuredTag.trim();
        }
        
        // Auto-generate a meaningful session tag
        java.time.LocalDateTime now = java.time.LocalDateTime.now();
        java.time.format.DateTimeFormatter formatter = java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss");
        String timestamp = now.format(formatter);
        
        // Include some context about the session
        String autoTag = String.format("session_%s", timestamp);
        
        logger.info("🏷️ Auto-generated session tag: '{}' (no session tag was configured)", autoTag);
        return autoTag;
    }
    
    /**
     * Updates the session tag with auto-generation logic.
     * This can be called from the UI or API to set a new session tag.
     * 
     * @param sessionTag The new session tag (will be auto-generated if null/empty)
     */
    public void updateSessionTag(String sessionTag) {
        this.sessionTag = generateSessionTagIfNeeded(sessionTag);
        logger.info("Session tag updated to: '{}'", this.sessionTag);
    }
    
    /**
     * Generates a new auto session tag for starting a new session.
     * Useful for creating new testing sessions programmatically.
     * 
     * @param prefix Optional prefix for the session tag (e.g., "test", "scan", "manual")
     * @return A new auto-generated session tag
     */
    public String generateNewSessionTag(String prefix) {
        java.time.LocalDateTime now = java.time.LocalDateTime.now();
        java.time.format.DateTimeFormatter formatter = java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss");
        String timestamp = now.format(formatter);
        
        if (prefix != null && !prefix.trim().isEmpty()) {
            String newTag = String.format("%s_%s", prefix.trim(), timestamp);
            logger.info("🏷️ Generated new session tag with prefix: '{}'", newTag);
            return newTag;
        } else {
            String newTag = String.format("session_%s", timestamp);
            logger.info("🏷️ Generated new session tag: '{}'", newTag);
            return newTag;
        }
    }
    
    // Getters
    
    public int getPort() {
        return port;
    }
    
    public String getDatabasePath() {
        return databasePath;
    }
    
    public boolean isVerboseLogging() {
        return verboseLogging;
    }
    
    public String getSessionTag() {
        return sessionTag;
    }
    
    // Setters (for standalone mode configuration override)
    
    public void setPort(int port) {
        this.port = port;
    }
    
    public void setDatabasePath(String databasePath) {
        this.databasePath = databasePath;
    }
    
    public void setVerboseLogging(boolean verboseLogging) {
        this.verboseLogging = verboseLogging;
        // Apply the verbose logging setting to the logger
        com.belch.logging.ApiLogger.setVerbose(verboseLogging);
    }
    
    public void setSessionTag(String sessionTag) {
        this.sessionTag = sessionTag;
    }
    
    
    @Override
    public String toString() {
        return "ApiConfig{" +
                "port=" + port +
                ", databasePath='" + databasePath + '\'' +
                ", verboseLogging=" + verboseLogging +
                ", sessionTag='" + sessionTag + '\'' +
                '}';
    }
} 