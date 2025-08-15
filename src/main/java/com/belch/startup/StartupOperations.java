package com.belch.startup;

import burp.api.montoya.MontoyaApi;
import com.belch.database.DatabaseService;
import com.belch.database.TrafficQueue;
import com.belch.logging.AllToolsLogger;
import com.belch.logging.TrafficSource;
import com.belch.config.ApiConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles startup operations including database initialization and proxy history import.
 * This class orchestrates the initial setup when the extension loads.
 * 
 * @author Charlie Campbell
 * @version 2.0.0
 */
public class StartupOperations {
    
    private static final Logger logger = LoggerFactory.getLogger(StartupOperations.class);
    
    private final MontoyaApi api;
    private final DatabaseService databaseService;
    private final ApiConfig config;
    
    /**
     * Constructor for StartupOperations.
     * 
     * @param api The MontoyaApi instance
     * @param databaseService The database service
     * @param config The API configuration
     */
    public StartupOperations(MontoyaApi api, DatabaseService databaseService, ApiConfig config) {
        this.api = api;
        this.databaseService = databaseService;
        this.config = config;
    }
    
    /**
     * Performs all startup operations:
     * 1. Initialize database (create if doesn't exist)
     * 2. Import existing proxy history and label as "imported"
     * 3. Start all-tools logger for future traffic
     * 
     * @return The initialized AllToolsLogger instance
     */
    public AllToolsLogger performStartupInitialization() {
        logger.info("🚀 Starting Belch - Burp Suite REST API Extension initialization...");
        
        try {
            // 1. Initialize database (already done by DatabaseService.initialize())
            if (!databaseService.isInitialized()) {
                logger.error("Database service is not initialized - cannot proceed");
                return null;
            }
            
            // 2. Import existing proxy history as "imported"
            importExistingProxyHistory();
            
            // 3. Initialize TrafficQueue for asynchronous processing
            TrafficQueue trafficQueue = new TrafficQueue(databaseService, config);
            trafficQueue.start();
            
            // 4. Initialize AllToolsLogger to capture future traffic from ALL tools
            AllToolsLogger allToolsLogger = new AllToolsLogger(api, databaseService, trafficQueue, config);
            allToolsLogger.initialize();
            
            logger.info("✅ Startup initialization completed successfully");
            api.logging().logToOutput("Belch: Ready to capture traffic from ALL tools");
            
            return allToolsLogger;
            
        } catch (Exception e) {
            logger.error("❌ Failed during startup initialization", e);
            api.logging().logToError("Belch startup failed: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Imports existing proxy history and labels it as "imported".
     */
    private void importExistingProxyHistory() {
        try {
            logger.info("📥 Checking for existing proxy history to import...");
            
            // Use the legacy import method to import existing proxy history
            String sessionTag = config.getSessionTag();
            int importedCount = databaseService.importExistingProxyHistory(api, sessionTag);
            
            if (importedCount > 0) {
                logger.info("📥 Successfully imported {} existing proxy history records", importedCount);
                api.logging().logToOutput("Imported " + importedCount + " existing proxy history records as 'IMPORTED'");
            } else {
                logger.info("📥 No existing proxy history found to import");
            }
            
        } catch (Exception e) {
            logger.warn("Failed to import existing proxy history (continuing anyway): {}", e.getMessage());
        }
    }
} 