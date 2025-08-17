package com.belch.handlers;

import com.belch.config.ApiConfig;
import com.belch.database.DatabaseService;
import io.javalin.Javalin;
import io.javalin.http.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * Responsible for registering session-related API routes.
 * Extracted from RouteHandler for modularity and maintainability.
 */
public class SessionRouteRegistrar {
    private static final Logger logger = LoggerFactory.getLogger(SessionRouteRegistrar.class);
    
    private final DatabaseService databaseService;
    private final ApiConfig config;
    
    /**
     * Constructor for SessionRouteRegistrar
     * @param databaseService The database service for data persistence
     * @param config The API configuration
     */
    public SessionRouteRegistrar(DatabaseService databaseService, ApiConfig config) {
        this.databaseService = databaseService;
        this.config = config;
    }
    
    /**
     * Register all session-related routes.
     * @param app The Javalin app instance
     */
    public void registerRoutes(Javalin app) {
        // Get current session tag with statistics
        app.get("/session/current", ctx -> {
            Map<String, Object> response = new HashMap<>();
            response.put("session_tag", config.getSessionTag());
            response.put("timestamp", System.currentTimeMillis());
            
            // Add session statistics if database is available
            if (databaseService != null && databaseService.isInitialized()) {
                Map<String, String> sessionParams = new HashMap<>();
                sessionParams.put("session_tag", config.getSessionTag());
                Map<String, Object> sessionStats = databaseService.getTrafficStats(sessionParams);
                response.put("session_statistics", sessionStats);
            }
            
            ctx.json(response);
        });
        
        // Update session tag with auto-generation support
        app.post("/session/tag", ctx -> {
            try {
                @SuppressWarnings("unchecked")
                Map<String, Object> requestData = ctx.bodyAsClass(Map.class);
                String newSessionTag = (String) requestData.get("session_tag");
                
                // Update the configuration with auto-generation if needed
                config.updateSessionTag(newSessionTag);
                
                Map<String, Object> response = new HashMap<>();
                response.put("session_tag", config.getSessionTag());
                response.put("message", "Session tag updated successfully");
                response.put("auto_generated", newSessionTag == null || newSessionTag.trim().isEmpty());
                response.put("timestamp", System.currentTimeMillis());
                
                ctx.json(response);
                
            } catch (Exception e) {
                logger.error("Failed to update session tag", e);
                ctx.status(400).json(Map.of(
                    "error", "Failed to update session tag",
                    "message", e.getMessage()
                ));
            }
        });
        
        // Generate a new session tag and apply it
        app.post("/session/new", ctx -> {
            try {
                String prefix = ctx.queryParam("prefix");
                String newSessionTag = config.generateNewSessionTag(prefix);
                
                // Apply the new session tag
                config.setSessionTag(newSessionTag);
                
                Map<String, Object> response = new HashMap<>();
                response.put("session_tag", newSessionTag);
                response.put("message", "New session tag generated and applied");
                response.put("prefix", prefix);
                response.put("timestamp", System.currentTimeMillis());
                
                ctx.json(response);
                
            } catch (Exception e) {
                logger.error("Failed to generate new session tag", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to generate new session tag",
                    "message", e.getMessage()
                ));
            }
        });
        
        // Get complete session history and statistics
        app.get("/session/history", ctx -> {
            if (!checkDatabaseAvailable(ctx)) return;
            
            try {
                // Get all unique session tags
                Map<String, String> emptyParams = new HashMap<>();
                Map<String, Object> stats = databaseService.getTrafficStats(emptyParams);
                
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> sessionStats = (List<Map<String, Object>>) stats.get("by_session_tag");
                
                Map<String, Object> response = new HashMap<>();
                response.put("current_session", config.getSessionTag());
                response.put("all_sessions", sessionStats != null ? sessionStats : new ArrayList<>());
                response.put("total_sessions", sessionStats != null ? sessionStats.size() : 0);
                response.put("timestamp", System.currentTimeMillis());
                
                ctx.json(response);
                
            } catch (Exception e) {
                logger.error("Failed to get session history", e);
                ctx.status(500).json(Map.of(
                    "error", "Failed to get session history",
                    "message", e.getMessage()
                ));
            }
        });
        
        // Complete documentation for session management API
        app.get("/session/help", ctx -> {
            Map<String, Object> response = new HashMap<>();
            
            response.put("description", "Session tag management for organizing proxy traffic");
            response.put("current_session", config.getSessionTag());
            
            // API examples
            Map<String, Object> examples = new HashMap<>();
            examples.put("get_current_session", "GET /session/current");
            examples.put("update_session_tag", Map.of(
                "method", "POST",
                "url", "/session/tag",
                "body", Map.of("session_tag", "my_test_session")
            ));
            examples.put("auto_generate_tag", Map.of(
                "method", "POST", 
                "url", "/session/tag",
                "body", Map.of("session_tag", "")
            ));
            examples.put("new_session_with_prefix", "POST /session/new?prefix=scan");
            examples.put("session_history", "GET /session/history");
            
            response.put("examples", examples);
            
            // Auto-generation info
            Map<String, Object> autoGenInfo = new HashMap<>();
            autoGenInfo.put("format", "session_YYYY-MM-DD_HH-mm-ss or prefix_YYYY-MM-DD_HH-mm-ss");
            autoGenInfo.put("triggers", List.of(
                "Empty or null session tag in configuration",
                "Empty session_tag in POST /session/tag",
                "Using POST /session/new endpoint"
            ));
            autoGenInfo.put("examples", List.of(
                "session_2024-05-31_15-30-45",
                "test_2024-05-31_15-30-45",
                "scan_2024-05-31_15-30-45"
            ));
            
            response.put("auto_generation", autoGenInfo);
            response.put("timestamp", System.currentTimeMillis());
            
            ctx.json(response);
        });
    }
    
    /**
     * Checks if database service is available and returns appropriate error response if not.
     * Helper method for routes that require database access.
     * 
     * @param ctx The Javalin context
     * @return true if database is available, false if error response was sent
     */
    private boolean checkDatabaseAvailable(Context ctx) {
        if (databaseService == null || !databaseService.isInitialized()) {
            ctx.status(503).json(Map.of(
                "error", "Database service unavailable",
                "message", "Database service is not initialized or not available"
            ));
            return false;
        }
        
        // Check for project changes and reinitialize if needed
        try {
            databaseService.checkForProjectChangeAndReinitialize();
        } catch (Exception e) {
            logger.warn("Failed to check for project changes: {}", e.getMessage());
            // Don't fail the request, but log the issue
        }
        
        return true;
    }
}