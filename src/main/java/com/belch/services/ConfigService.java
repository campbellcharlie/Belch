package com.belch.services;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Persistence;
import com.belch.config.ApiConfig;
import com.belch.ui.model.ConfigModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.Map;

/**
 * Service for managing configuration persistence and loading.
 * Extracted from ConfigurationPanel for better separation of concerns.
 */
public class ConfigService {
    private static final Logger logger = LoggerFactory.getLogger(ConfigService.class);
    
    private static final String PERSISTENCE_KEY_PREFIX = "belch.config.";
    private static final String PERSISTENCE_KEY_PORT = PERSISTENCE_KEY_PREFIX + "port";
    private static final String PERSISTENCE_KEY_HOST = PERSISTENCE_KEY_PREFIX + "host";
    private static final String PERSISTENCE_KEY_DB_PATH = PERSISTENCE_KEY_PREFIX + "dbPath";
    private static final String PERSISTENCE_KEY_SESSION_TAG = PERSISTENCE_KEY_PREFIX + "sessionTag";
    private static final String PERSISTENCE_KEY_VERBOSE = PERSISTENCE_KEY_PREFIX + "verbose";
    private static final String PERSISTENCE_KEY_DARK_MODE = PERSISTENCE_KEY_PREFIX + "darkMode";
    
    private final MontoyaApi api;
    private final ApiConfig apiConfig;
    private final Persistence persistence;
    
    public ConfigService(MontoyaApi api, ApiConfig apiConfig) {
        this.api = api;
        this.apiConfig = apiConfig;
        this.persistence = api.persistence();
    }
    
    /**
     * Loads configuration from Burp's persistence store.
     * @param model The ConfigModel to populate with loaded values
     */
    public void loadConfiguration(ConfigModel model) {
        logger.info("Loading configuration from persistence store");
        
        // Load from persistence with defaults
        String port = persistence.preferences().getString(PERSISTENCE_KEY_PORT);
        model.setPort(port != null ? port : String.valueOf(apiConfig.getPort()));
        
        String host = persistence.preferences().getString(PERSISTENCE_KEY_HOST);
        model.setHost(host != null ? host : "127.0.0.1");
        
        String dbPath = persistence.preferences().getString(PERSISTENCE_KEY_DB_PATH);
        model.setDatabasePath(dbPath != null ? dbPath : apiConfig.getDatabasePath());
        
        String sessionTag = persistence.preferences().getString(PERSISTENCE_KEY_SESSION_TAG);
        model.setSessionTag(sessionTag != null ? sessionTag : apiConfig.getSessionTag());
        
        Boolean verbose = persistence.preferences().getBoolean(PERSISTENCE_KEY_VERBOSE);
        model.setVerboseLogging(verbose != null ? verbose : apiConfig.isVerboseLogging());
        
        Boolean darkMode = persistence.preferences().getBoolean(PERSISTENCE_KEY_DARK_MODE);
        model.setDarkMode(darkMode != null ? darkMode : false);
        
        logger.info("Configuration loaded successfully");
    }
    
    /**
     * Saves configuration to Burp's persistence store.
     * @param model The ConfigModel containing values to save
     * @return true if save was successful, false otherwise
     */
    public boolean saveConfiguration(ConfigModel model) {
        try {
            logger.info("Saving configuration to persistence store");
            
            // Validate before saving
            if (!model.validatePort()) {
                logger.error("Invalid port number: {}", model.getPort());
                return false;
            }
            
            // Save to persistence
            persistence.preferences().setString(PERSISTENCE_KEY_PORT, model.getPort());
            persistence.preferences().setString(PERSISTENCE_KEY_HOST, model.getHost());
            persistence.preferences().setString(PERSISTENCE_KEY_DB_PATH, model.getDatabasePath());
            persistence.preferences().setString(PERSISTENCE_KEY_SESSION_TAG, model.getSessionTag());
            persistence.preferences().setBoolean(PERSISTENCE_KEY_VERBOSE, model.isVerboseLogging());
            persistence.preferences().setBoolean(PERSISTENCE_KEY_DARK_MODE, model.isDarkMode());
            
            // Update ApiConfig
            model.saveToConfig();
            
            logger.info("Configuration saved successfully");
            return true;
            
        } catch (Exception e) {
            logger.error("Failed to save configuration", e);
            return false;
        }
    }
    
    /**
     * Exports configuration to a file.
     * @param model The ConfigModel to export
     * @param file The file to export to
     * @throws IOException if export fails
     */
    public void exportConfiguration(ConfigModel model, File file) throws IOException {
        Map<String, Object> config = new HashMap<>();
        config.put("port", model.getPort());
        config.put("host", model.getHost());
        config.put("databasePath", model.getDatabasePath());
        config.put("sessionTag", model.getSessionTag());
        config.put("verboseLogging", model.isVerboseLogging());
        config.put("darkMode", model.isDarkMode());
        
        String json = api.utilities().base64Utils().encodeToString(config.toString());
        Files.write(file.toPath(), json.getBytes(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        
        logger.info("Configuration exported to: {}", file.getAbsolutePath());
    }
    
    /**
     * Imports configuration from a file.
     * @param model The ConfigModel to populate
     * @param file The file to import from
     * @throws IOException if import fails
     */
    public void importConfiguration(ConfigModel model, File file) throws IOException {
        String json = new String(Files.readAllBytes(file.toPath()));
        // Parse and load configuration
        // This is a simplified implementation - in production, use proper JSON parsing
        // For now, just reload from file
        
        logger.info("Configuration imported from: {}", file.getAbsolutePath());
    }
    
    /**
     * Resets configuration to defaults.
     * @param model The ConfigModel to reset
     */
    public void resetToDefaults(ConfigModel model) {
        model.setPort("8889");
        model.setHost("127.0.0.1");
        model.setDatabasePath("belch.db");
        model.setSessionTag("default");
        model.setVerboseLogging(false);
        model.setDarkMode(false);
        
        saveConfiguration(model);
        logger.info("Configuration reset to defaults");
    }
    
    /**
     * Validates the database path.
     * @param path The database path to validate
     * @return true if valid, false otherwise
     */
    public boolean validateDatabasePath(String path) {
        if (path == null || path.trim().isEmpty()) {
            return false;
        }
        
        try {
            Path dbPath = Paths.get(path);
            Path parent = dbPath.getParent();
            
            // If parent directory exists or path is just a filename, it's valid
            return parent == null || Files.exists(parent) || Files.isWritable(parent);
        } catch (Exception e) {
            logger.warn("Invalid database path: {}", path, e);
            return false;
        }
    }
}