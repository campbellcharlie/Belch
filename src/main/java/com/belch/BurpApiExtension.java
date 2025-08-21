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
            // Phase 1: Core Infrastructure
            logger.info("🔧 Phase 1: Initializing core infrastructure...");
            initializeCoreInfrastructure();
            
            // Phase 2: Dual-Strategy Traffic Capture
            logger.info("🔧 Phase 2: Initializing dual-strategy traffic capture...");
            initializeDualStrategyCapture();
            
            // Phase 3: API Server and UI
            logger.info("🔧 Phase 3: Starting API server and UI...");
            initializeApiServerAndUI();
            
            // Phase 4: Final Setup and Success Message
            logger.info("🔧 Phase 4: Completing initialization...");
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
     * Phase 1: Initialize core infrastructure (config, database, queue).
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
     * Phase 2: Initialize dual-strategy traffic capture system.
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
        
        // Re-enable automatic proxy history import on startup
        logger.info("[*] Starting automatic proxy history import...");
        try {
            startupOperations.importExistingProxyHistoryOnly();
            logger.info("[+] Automatic proxy history import completed successfully");
        } catch (Exception e) {
            logger.warn("Automatic proxy history import failed (continuing anyway): {}", e.getMessage());
        }
    }
    
    /**
     * Phase 3: Initialize API server and user interface.
     */
    private void initializeApiServerAndUI() {
        // Initialize route handler with enhanced database capabilities
        logger.info("[*] Initializing enhanced route handler with WebSocket support...");
        routeHandler = new RouteHandler(api, databaseService, trafficQueue, config);
        logger.info("[+] Route handler initialized with traffic source analytics");
        
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
     * Phase 4: Complete initialization and display success message.
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