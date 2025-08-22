package com.belch;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.belch.config.ApiConfig;
import com.belch.ui.ConfigurationPanel;
import com.belch.database.DatabaseService;
import com.belch.database.TrafficQueue;
import com.belch.handlers.RouteHandler;
import com.belch.logging.ProxyLogger;
import com.belch.logging.RepeaterLogger;
import com.belch.logging.AllToolsLogger;
import com.belch.startup.StartupOperations;
import com.belch.services.DatabaseMaintenanceService;
import io.javalin.Javalin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PreDestroy;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * Main Burp Extension class for Belch v1.0 - the REST API with dual-strategy traffic capture.
 * 
 * STRATEGY 1: Real-time comprehensive capture from ALL tools (prevents data loss from Burp limits)
 * STRATEGY 2: Proxy history import for save file scenarios (only proxy data persists in saves)
 * 
 * @author Charlie Campbell
 * @version 1.0.0
 */
public class BurpApiExtension implements BurpExtension {
    
    private static final Logger logger = LoggerFactory.getLogger(BurpApiExtension.class);
    private static final String EXTENSION_NAME = "Belch";
    private static final String EXTENSION_VERSION = "1.0.0";
    
    private MontoyaApi api;
    private Javalin javalinApp;
    private DatabaseService databaseService;
    private TrafficQueue trafficQueue;
    private RouteHandler routeHandler;
    private ProxyLogger proxyLogger;
    private RepeaterLogger repeaterLogger;
    private AllToolsLogger allToolsLogger; // NEW: Comprehensive real-time capture
    private StartupOperations startupOperations; // NEW: Coordinated initialization
    private DatabaseMaintenanceService maintenanceService; // Automated DB maintenance
    private ApiConfig config;
    private ConfigurationPanel configPanel;
    
    /**
     * Called by Burp Suite when the extension is loaded.
     * Implements dual-strategy traffic capture architecture.
     * 
     * @param api The MontoyaApi instance provided by Burp Suite
     */
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        
        // Set extension details
        api.extension().setName(EXTENSION_NAME + " v" + EXTENSION_VERSION);
        
        // Register unloading callback to ensure proper cleanup
        api.extension().registerUnloadingHandler(this::cleanup);
        
        logger.info("[*] Starting {} v{} with Dual-Strategy Traffic Capture", EXTENSION_NAME, EXTENSION_VERSION);
        logger.info("[*] Strategy 1: Real-time comprehensive capture (ALL tools)");
        logger.info("[*] Strategy 2: Proxy history import (save file compatibility)");
        logger.info("Java version: {}", System.getProperty("java.version"));
        logger.info("Burp version: {}", api.burpSuite().version());
        
        try {
            // Core Infrastructure
            logger.info("Initializing core infrastructure...");
            initializeCoreInfrastructure();
            
            // Dual-Strategy Traffic Capture
            logger.info("Initializing dual-strategy traffic capture...");
            initializeDualStrategyCapture();
            
            // API Server and UI
            logger.info("Starting API server and UI...");
            initializeApiServerAndUI();
            
            //  Final Setup and Success Message
            logger.info("Completing initialization...");
            completeInitialization();
            
        } catch (Exception e) {
            String errorMessage = "CRITICAL: Failed to initialize " + EXTENSION_NAME + ": " + e.getMessage();
            logger.error(errorMessage, e);
            api.logging().logToError(errorMessage);
            
            // Attempt cleanup on failure
            cleanup();
            throw new RuntimeException("Extension initialization failed", e);
        }
    }
    
    /**
     * Initialize core infrastructure (config, database, queue).
     */
    private void initializeCoreInfrastructure() {
        // Initialize configuration
        logger.info("[*] Initializing configuration...");
        config = new ApiConfig();
        logger.info("[+] Configuration initialized");
        
        // Initialize database service with schema migration
        logger.info("[*] Initializing database service with traffic source tracking...");
        databaseService = new DatabaseService(api, config);
        databaseService.initialize();
        logger.info("[+] Database service initialized with traffic source support");
        
        // Initialize asynchronous traffic queue for high-volume scenarios
        logger.info("[*] Initializing traffic queue system...");
        trafficQueue = new TrafficQueue(databaseService, config);
        trafficQueue.start();
        logger.info("[+] Traffic queue system started (50K capacity, async processing)");
    }
    
    /**
     * Initialize dual-strategy traffic capture system.
     */
    private void initializeDualStrategyCapture() {
        // STRATEGY 1: Keep existing proven loggers + add comprehensive capture
        logger.info("[*] Strategy 1: Initializing proven traffic capture system...");
        
        // Initialize loggers
        this.repeaterLogger = new RepeaterLogger(api, trafficQueue, databaseService);
        this.proxyLogger = new ProxyLogger(api, trafficQueue, databaseService);
        proxyLogger.initialize();
        logger.info("[+] ProxyLogger initialized with async processing");
        
        // DISABLED: RepeaterLogger to eliminate conflict with AllToolsLogger
        logger.info("[!] RepeaterLogger DISABLED - AllToolsLogger handles all traffic including Repeater");
        
        // Add comprehensive logger for ALL other tools (Intruder, Scanner, etc.)
        allToolsLogger = new AllToolsLogger(api, databaseService, trafficQueue, config);
        allToolsLogger.initialize();
        logger.info("[+] AllToolsLogger initialized - capturing from ALL Burp tools");
        
        // STRATEGY 2: Import from save files + coordinated startup
        logger.info("[*] Strategy 2: Initializing startup operations and import...");
        startupOperations = new StartupOperations(api, databaseService, config);
        logger.info("[+] StartupOperations initialized - ready for proxy history import");
        
        // Queue proxy history import for background execution
        logger.info("[*] Queueing automatic proxy history import for background execution...");
        logger.info("[+] Import will start after extension initialization completes");
    }
    
    /**
     * Initialize API server and user interface.
     */
    private void initializeApiServerAndUI() {
        // Initialize route handler with enhanced database capabilities  
        logger.info("[*] Initializing enhanced route handler with WebSocket support...");
        
        // Diagnostic check - verify key dependencies are available
        logger.info("[*] Checking RouteHandler dependencies...");
        try {
            Class.forName("com.belch.handlers.RouteHandler");
            logger.info("[+] RouteHandler class found");
            Class.forName("io.javalin.Javalin");
            logger.info("[+] Javalin class found");
            Class.forName("com.fasterxml.jackson.databind.ObjectMapper");
            logger.info("[+] Jackson ObjectMapper class found");
        } catch (ClassNotFoundException e) {
            logger.error("Critical dependency missing: {}", e.getMessage());
            throw new RuntimeException("Missing critical dependency", e);
        }
        
        try {
            routeHandler = new RouteHandler(api, databaseService, trafficQueue, config);
            logger.info("[+] Route handler initialized with traffic source analytics");
        } catch (NoClassDefFoundError e) {
            logger.error("RouteHandler dependency missing: {}", e.getMessage());
            logger.error("Missing class: {}", e.getMessage());
            throw new RuntimeException("RouteHandler dependency error", e);
        } catch (Exception e) {
            logger.error("RouteHandler initialization failed: {}", e.getMessage(), e);
            throw new RuntimeException("RouteHandler initialization failed", e);
        }
        
        // Connect WebSocket broadcasting to TrafficQueue
        logger.info("[*] Connecting WebSocket broadcasting to traffic capture...");
        trafficQueue.setEventBroadcaster(routeHandler.getEventBroadcaster());
        logger.info("[+] WebSocket real-time streaming connected to traffic capture");
        
        // Start API server
        logger.info("[*] Starting API server with WebSocket support...");
        startApiServer();
        logger.info("[+] API server started on port {} with real-time WebSocket streaming", config.getPort());
        
        // Create configuration panel with new features
        logger.info("[*] Creating configuration panel...");
        configPanel = new ConfigurationPanel(config, databaseService, trafficQueue);
        api.userInterface().registerSuiteTab("Belch Config", configPanel);
        logger.info("[+] Configuration panel created with traffic source analytics");
    }
    
    /**
     *  Complete initialization and display success message.
     */
    private void completeInitialization() {
        // Get current database stats for success message
        Map<String, Object> stats = databaseService.getTrafficStats(new HashMap<>());
        long totalRecords = 0;
        if (stats.containsKey("total_requests")) {
            Object totalObj = stats.get("total_requests");
            if (totalObj instanceof Number) {
                totalRecords = ((Number) totalObj).longValue();
            }
        }
        
        // Log comprehensive success message
        String successMessage = String.format(
            "[*] %s v%s READY!\n\n" +
            "[API ENDPOINTS]:\n" +
            "  * Main API: http://localhost:%d\n" +
            "  * Documentation: http://localhost:%d/docs\n" +
            "  * OpenAPI Spec: http://localhost:%d/openapi\n" +
            "  * Traffic Stats: http://localhost:%d/proxy/stats\n" +
            "  * WebSocket Stream: ws://localhost:%d/ws/stream\n" +
            "  * WebSocket Stats: http://localhost:%d/ws/stats\n\n" +
            "[DATABASE]:\n" +
            "  * Project: %s\n" +
            "  * Database: %s\n" +
            "  * Current Records: %d\n" +
            "  * Session Tag: %s",
            
            EXTENSION_NAME, EXTENSION_VERSION,
            config.getPort(), config.getPort(), config.getPort(), config.getPort(), config.getPort(), config.getPort(),
            databaseService.getCurrentProjectName(),
            databaseService.getCurrentDatabasePath(),
            totalRecords,
            config.getSessionTag()
        );
        
        logger.info(successMessage);
        api.logging().logToOutput(successMessage);
        
        // Log pending request count for debugging
        if (allToolsLogger != null) {
            logger.debug("AllToolsLogger pending requests: {}", allToolsLogger.getPendingRequestCount());
        }
        
        // Start automated database maintenance service
        logger.info("Starting automated database maintenance...");
        try {
            maintenanceService = new DatabaseMaintenanceService(databaseService);
            maintenanceService.start();
            logger.info("Database maintenance service started - automated ANALYZE/VACUUM/CHECKPOINT enabled");
        } catch (Exception e) {
            logger.error("Database maintenance service failed to start: {}", e.getMessage());
            // Continue without maintenance - not critical for core functionality
        }
        
        // Start proxy history import after all services are running
        logger.info("Starting background proxy history import...");
        if (startupOperations != null) {
            // Run import in separate thread to avoid blocking
            Thread.ofVirtual().name("ProxyHistoryImport").start(() -> {
                try {
                    Thread.sleep(2000); // Give services time to fully start
                    logger.info("[*] Beginning automatic proxy history import...");
                    startupOperations.importExistingProxyHistoryOnly();
                    logger.info("Background proxy history import completed successfully");
                } catch (Exception e) {
                    logger.warn("Background proxy history import failed: {}", e.getMessage());
                }
            });
        }
    }
    
    /**
     * Starts the Javalin API server with all routes.
     */
    private void startApiServer() {
        try {
            // Create Javalin app with JSON configuration
            javalinApp = Javalin.create(javalinConfig -> {
                javalinConfig.showJavalinBanner = false;
                javalinConfig.jsonMapper(routeHandler.getJsonMapper());
            });
            
            // Register all routes (including new traffic source analytics)
            routeHandler.registerRoutes(javalinApp);
            
            // Start the server
            javalinApp.start(config.getPort());
            
            logger.info("REST API server started successfully on port {}", config.getPort());
            
        } catch (Exception e) {
            logger.error("Failed to start API server", e);
            throw new RuntimeException("API server startup failed", e);
        }
    }
    
    /**
     * Cleanup method called when the extension is unloaded.
     * Ensures all resources are properly released.
     */
    @PreDestroy
    public void cleanup() {
        logger.info("[*] Starting extension cleanup...");
        
        try {
            // Shutdown all traffic loggers
            if (allToolsLogger != null) {
                logger.info("Shutting down AllToolsLogger...");
                allToolsLogger.shutdown();
            }
            
            if (proxyLogger != null) {
                logger.info("Shutting down ProxyLogger...");
                proxyLogger.shutdown();
            }
            
            if (repeaterLogger != null) {
                logger.info("Shutting down RepeaterLogger...");
                repeaterLogger.shutdown();
            }
            
            // Shutdown traffic queue
            if (trafficQueue != null) {
                logger.info("Shutting down TrafficQueue...");
                trafficQueue.stop();
            }
            
            // Shutdown WebSocket components
            if (routeHandler != null) {
                logger.info("Shutting down WebSocket components...");
                routeHandler.shutdown();
            }
            
            // Shutdown API server
            if (javalinApp != null) {
                logger.info("Shutting down API server...");
                javalinApp.stop();
            }
            
            // Shutdown database maintenance service
            if (maintenanceService != null) {
                logger.info("Shutting down Database Maintenance Service...");
                maintenanceService.shutdown();
            }
            
            // Shutdown database service
            if (databaseService != null) {
                logger.info("Shutting down DatabaseService...");
                databaseService.shutdown();
            }
            
            logger.info("[+] Extension cleanup completed successfully");
            
        } catch (Exception e) {
            logger.error("[!] Error during cleanup", e);
        }
    }
    
    /**
     * Gets the current API configuration.
     * 
     * @return The API configuration
     */
    public ApiConfig getConfig() {
        return config;
    }
    
    /**
     * Gets the database service instance.
     * 
     * @return The database service
     */
    public DatabaseService getDatabaseService() {
        return databaseService;
    }
    
    /**
     * Gets the all-tools logger instance.
     * 
     * @return The all-tools logger
     */
    public AllToolsLogger getAllToolsLogger() {
        return allToolsLogger;
    }
    
    /**
     * Gets the extension version.
     * 
     * @return Extension version string
     */
    public static String getVersion() {
        return EXTENSION_VERSION;
    }
    
    /**
     * Gets the extension name.
     * 
     * @return Extension name string
     */
    public static String getName() {
        return EXTENSION_NAME;
    }
} 