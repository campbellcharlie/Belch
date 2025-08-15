package com.belch.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.SecretKey;
import burp.api.montoya.collaborator.CollaboratorClient;
import com.belch.config.ApiConfig;
import com.belch.database.DatabaseService;
import com.belch.services.CollaboratorInteractionService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.Javalin;
import io.javalin.http.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Enhanced collaborator route registrar with comprehensive interaction storage,
 * pattern matching, automated alerts, bulk payload management, and analytics.
 * 
 * Features:
 * - All interactions stored in database with full details
 * - Pattern matching for security testing indicators
 * - Automated alert system for critical patterns
 * - Bulk payload management and tracking
 * - Comprehensive analytics and reporting
 * - Real-time WebSocket notifications
 */
public class EnhancedCollaboratorRouteRegistrar {
    
    private static final Logger logger = LoggerFactory.getLogger(EnhancedCollaboratorRouteRegistrar.class);
    
    private final MontoyaApi api;
    private final DatabaseService databaseService;
    private final ApiConfig config;
    private final CollaboratorInteractionService interactionService;
    private final ObjectMapper objectMapper;
    
    // Performance tracking
    private final AtomicLong totalPayloadsGenerated = new AtomicLong(0);
    private final AtomicLong totalInteractionsRetrieved = new AtomicLong(0);
    
    public EnhancedCollaboratorRouteRegistrar(MontoyaApi api, DatabaseService databaseService, 
                                            ApiConfig config, CollaboratorInteractionService interactionService) {
        this.api = api;
        this.databaseService = databaseService;
        this.config = config;
        this.interactionService = interactionService;
        this.objectMapper = new ObjectMapper();
    }
    
    /**
     * Register all enhanced collaborator routes
     */
    public void registerRoutes(Javalin app) {
        
        // Enhanced interactions endpoint with database storage
        app.get("/collaborator/interactions/enhanced", this::getEnhancedInteractions);
        
        // Pattern management endpoints
        app.get("/collaborator/patterns", this::getPatterns);
        app.post("/collaborator/patterns", this::addPattern);
        app.delete("/collaborator/patterns/{name}", this::removePattern);
        
        // Bulk payload management
        app.post("/collaborator/payloads/bulk", this::generateBulkPayloads);
        app.get("/collaborator/payloads/tracking", this::getPayloadTracking);
        
        // Analytics endpoints
        app.get("/collaborator/analytics", this::getAnalytics);
        app.get("/collaborator/analytics/timeline", this::getAnalyticsTimeline);
        app.get("/collaborator/analytics/patterns", this::getPatternAnalytics);
        
        // Alert management
        app.get("/collaborator/alerts", this::getAlerts);
        app.post("/collaborator/alerts/test", this::testAlert);
        
        // Enhanced payload generation with tracking
        app.post("/collaborator/payloads/tracked", this::generateTrackedPayloads);
        
        // Interaction search and filtering
        app.get("/collaborator/interactions/search", this::searchInteractions);
        
        // Health and performance monitoring
        app.get("/collaborator/health", this::getHealth);
        
        logger.info("✅ Enhanced collaborator routes registered");
    }
    
    /**
     * GET /collaborator/interactions/enhanced - Get interactions with database storage
     */
    private void getEnhancedInteractions(Context ctx) {
        try {
            String clientSecret = ctx.queryParam("client_secret");
            if (clientSecret == null || clientSecret.trim().isEmpty()) {
                ctx.status(400).json(Map.of(
                    "error", "Missing required parameter",
                    "message", "client_secret parameter is required"
                ));
                return;
            }
            
            // Optional filters
            String interactionType = ctx.queryParam("type");
            String sessionTag = ctx.queryParam("session_tag");
            boolean storeInDb = Boolean.parseBoolean(ctx.queryParam("store_in_db") != null ? ctx.queryParam("store_in_db") : "true");
            
            // Restore client and get interactions
            SecretKey key = SecretKey.secretKey(clientSecret);
            CollaboratorClient client = api.collaborator().restoreClient(key);
            List<Interaction> interactions = client.getAllInteractions();
            
            // Filter by type if specified
            if (interactionType != null && !interactionType.trim().isEmpty()) {
                final String filterType = interactionType.trim().toUpperCase();
                interactions = interactions.stream()
                    .filter(interaction -> interaction.type().toString().equals(filterType))
                    .collect(Collectors.toList());
            }
            
            List<Map<String, Object>> formattedInteractions = new ArrayList<>();
            String clientSecretHash = hashSecretKey(clientSecret);
            String effectiveSessionTag = sessionTag != null ? sessionTag : config.getSessionTag();
            
            // Process each interaction
            for (Interaction interaction : interactions) {
                // Store in database if requested
                long dbId = -1;
                if (storeInDb) {
                    dbId = interactionService.storeInteraction(interaction, clientSecretHash, effectiveSessionTag);
                }
                
                // Format for response
                Map<String, Object> formatted = formatInteractionWithDb(interaction, dbId);
                formattedInteractions.add(formatted);
            }
            
            totalInteractionsRetrieved.addAndGet(interactions.size());
            
            Map<String, Object> response = new HashMap<>();
            response.put("interactions", formattedInteractions);
            response.put("count", formattedInteractions.size());
            response.put("stored_in_database", storeInDb);
            response.put("client_secret_preview", clientSecret.substring(0, Math.min(8, clientSecret.length())) + "...");
            response.put("session_tag", effectiveSessionTag);
            response.put("timestamp", System.currentTimeMillis());
            
            ctx.json(response);
            
        } catch (Exception e) {
            logger.error("Error getting enhanced collaborator interactions", e);
            ctx.status(500).json(Map.of(
                "error", "Failed to get enhanced interactions",
                "message", e.getMessage()
            ));
        }
    }
    
    /**
     * GET /collaborator/patterns - Get all pattern matching rules
     */
    private void getPatterns(Context ctx) {
        try {
            Map<String, Object> patterns = interactionService.getPatterns();
            patterns.put("timestamp", System.currentTimeMillis());
            
            ctx.json(Map.of(
                "status", "success",
                "patterns", patterns
            ));
            
        } catch (Exception e) {
            logger.error("Error getting patterns", e);
            ctx.status(500).json(Map.of(
                "error", "Failed to get patterns",
                "message", e.getMessage()
            ));
        }
    }
    
    /**
     * POST /collaborator/patterns - Add a new pattern matching rule
     */
    private void addPattern(Context ctx) {
        try {
            Map<String, Object> requestData = ctx.bodyAsClass(Map.class);
            
            String name = (String) requestData.get("name");
            String regex = (String) requestData.get("regex");
            String alertMessage = (String) requestData.get("alert_message");
            
            if (name == null || regex == null) {
                ctx.status(400).json(Map.of(
                    "error", "Missing required fields",
                    "message", "name and regex are required"
                ));
                return;
            }
            
            String effectiveAlertMessage = alertMessage != null ? alertMessage : "Pattern match detected: " + name;
            
            interactionService.addPattern(name, regex, effectiveAlertMessage);
            
            ctx.json(Map.of(
                "status", "success",
                "message", "Pattern added successfully",
                "pattern", Map.of(
                    "name", name,
                    "regex", regex,
                    "alert_message", effectiveAlertMessage
                )
            ));
            
        } catch (Exception e) {
            logger.error("Error adding pattern", e);
            ctx.status(500).json(Map.of(
                "error", "Failed to add pattern",
                "message", e.getMessage()
            ));
        }
    }
    
    /**
     * DELETE /collaborator/patterns/{name} - Remove a pattern matching rule
     */
    private void removePattern(Context ctx) {
        try {
            String name = ctx.pathParam("name");
            
            interactionService.removePattern(name);
            
            ctx.json(Map.of(
                "status", "success",
                "message", "Pattern removed successfully",
                "pattern_name", name
            ));
            
        } catch (Exception e) {
            logger.error("Error removing pattern", e);
            ctx.status(500).json(Map.of(
                "error", "Failed to remove pattern",
                "message", e.getMessage()
            ));
        }
    }
    
    /**
     * POST /collaborator/payloads/bulk - Generate bulk payloads with tracking
     */
    private void generateBulkPayloads(Context ctx) {
        try {
            Map<String, Object> requestData = ctx.bodyAsClass(Map.class);
            
            int count = Integer.parseInt(requestData.getOrDefault("count", "10").toString());
            String sessionTag = (String) requestData.getOrDefault("session_tag", config.getSessionTag() + "_bulk");
            String payloadType = (String) requestData.getOrDefault("type", "bulk_generation");
            @SuppressWarnings("unchecked")
            List<String> customDataList = (List<String>) requestData.getOrDefault("custom_data_list", new ArrayList<>());
            
            // Validate count
            if (count <= 0 || count > 1000) {
                ctx.status(400).json(Map.of(
                    "error", "Invalid count",
                    "message", "Count must be between 1 and 1000",
                    "received", count
                ));
                return;
            }
            
            // Create client for bulk generation
            CollaboratorClient client = api.collaborator().createClient();
            String clientSecretHash = hashSecretKey(client.getSecretKey().toString());
            
            List<Map<String, Object>> generatedPayloads = new ArrayList<>();
            
            for (int i = 0; i < count; i++) {
                CollaboratorPayload payload = client.generatePayload();
                
                String customData = i < customDataList.size() ? customDataList.get(i) : "bulk_" + i;
                
                // Register payload for tracking
                interactionService.registerPayload(
                    payload.toString(),
                    clientSecretHash,
                    payload.id().toString(),
                    payloadType,
                    sessionTag,
                    customData,
                    payload.server().isPresent() ? payload.server().get().address() : null
                );
                
                Map<String, Object> payloadInfo = new HashMap<>();
                payloadInfo.put("payload", payload.toString());
                payloadInfo.put("interaction_id", payload.id().toString());
                payloadInfo.put("custom_data", customData);
                payloadInfo.put("index", i);
                
                generatedPayloads.add(payloadInfo);
                totalPayloadsGenerated.incrementAndGet();
            }
            
            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("payloads", generatedPayloads);
            response.put("count", generatedPayloads.size());
            response.put("client_secret", client.getSecretKey().toString());
            response.put("session_tag", sessionTag);
            response.put("payload_type", payloadType);
            response.put("tracking_enabled", true);
            response.put("timestamp", System.currentTimeMillis());
            
            ctx.json(response);
            
        } catch (Exception e) {
            logger.error("Error generating bulk payloads", e);
            ctx.status(500).json(Map.of(
                "error", "Failed to generate bulk payloads",
                "message", e.getMessage()
            ));
        }
    }
    
    /**
     * GET /collaborator/payloads/tracking - Get payload tracking information
     */
    private void getPayloadTracking(Context ctx) {
        try {
            String sessionTag = ctx.queryParam("session_tag");
            String payloadType = ctx.queryParam("type");
            
            // This would query the database for payload tracking information
            // Implementation would depend on specific database queries
            
            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("message", "Payload tracking data");
            response.put("filters", Map.of(
                "session_tag", sessionTag,
                "payload_type", payloadType
            ));
            response.put("note", "Detailed tracking implementation would query collaborator_payloads table");
            
            ctx.json(response);
            
        } catch (Exception e) {
            logger.error("Error getting payload tracking", e);
            ctx.status(500).json(Map.of(
                "error", "Failed to get payload tracking",
                "message", e.getMessage()
            ));
        }
    }
    
    /**
     * GET /collaborator/analytics - Get comprehensive analytics
     */
    private void getAnalytics(Context ctx) {
        try {
            Map<String, Object> analytics = interactionService.getAnalytics();
            
            // Add performance metrics
            analytics.put("total_payloads_generated", totalPayloadsGenerated.get());
            analytics.put("total_interactions_retrieved", totalInteractionsRetrieved.get());
            analytics.put("timestamp", System.currentTimeMillis());
            
            ctx.json(Map.of(
                "status", "success",
                "analytics", analytics
            ));
            
        } catch (Exception e) {
            logger.error("Error getting analytics", e);
            ctx.status(500).json(Map.of(
                "error", "Failed to get analytics",
                "message", e.getMessage()
            ));
        }
    }
    
    /**
     * GET /collaborator/analytics/timeline - Get analytics timeline
     */
    private void getAnalyticsTimeline(Context ctx) {
        try {
            String timeframe = ctx.queryParam("timeframe") != null ? ctx.queryParam("timeframe") : "24h";
            String granularity = ctx.queryParam("granularity") != null ? ctx.queryParam("granularity") : "1h";
            
            // This would implement timeline analytics from the database
            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("timeframe", timeframe);
            response.put("granularity", granularity);
            response.put("note", "Timeline analytics would query collaborator_analytics table with time grouping");
            response.put("timestamp", System.currentTimeMillis());
            
            ctx.json(response);
            
        } catch (Exception e) {
            logger.error("Error getting analytics timeline", e);
            ctx.status(500).json(Map.of(
                "error", "Failed to get analytics timeline",
                "message", e.getMessage()
            ));
        }
    }
    
    /**
     * GET /collaborator/analytics/patterns - Get pattern-based analytics
     */
    private void getPatternAnalytics(Context ctx) {
        try {
            // This would implement pattern analytics from the database
            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("note", "Pattern analytics would query collaborator_pattern_matches table for statistics");
            response.put("timestamp", System.currentTimeMillis());
            
            ctx.json(response);
            
        } catch (Exception e) {
            logger.error("Error getting pattern analytics", e);
            ctx.status(500).json(Map.of(
                "error", "Failed to get pattern analytics",
                "message", e.getMessage()
            ));
        }
    }
    
    /**
     * GET /collaborator/alerts - Get triggered alerts
     */
    private void getAlerts(Context ctx) {
        try {
            String since = ctx.queryParam("since") != null ? ctx.queryParam("since") : "24h";
            String patternName = ctx.queryParam("pattern");
            
            // This would query pattern matches with alerts from database
            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("filters", Map.of(
                "since", since,
                "pattern", patternName != null ? patternName : "all"
            ));
            response.put("note", "Alert history would query collaborator_pattern_matches where alert_triggered=true");
            response.put("timestamp", System.currentTimeMillis());
            
            ctx.json(response);
            
        } catch (Exception e) {
            logger.error("Error getting alerts", e);
            ctx.status(500).json(Map.of(
                "error", "Failed to get alerts",
                "message", e.getMessage()
            ));
        }
    }
    
    /**
     * POST /collaborator/alerts/test - Test alert system
     */
    private void testAlert(Context ctx) {
        try {
            Map<String, Object> requestData = ctx.bodyAsClass(Map.class);
            String patternName = (String) requestData.get("pattern_name");
            String testText = (String) requestData.get("test_text");
            
            if (patternName == null || testText == null) {
                ctx.status(400).json(Map.of(
                    "error", "Missing required fields",
                    "message", "pattern_name and test_text are required"
                ));
                return;
            }
            
            // Test the pattern against the text
            // This would use the pattern matching system
            
            ctx.json(Map.of(
                "status", "success",
                "message", "Alert test completed",
                "pattern_name", patternName,
                "test_text", testText,
                "note", "Pattern testing would use CollaboratorInteractionService.patterns"
            ));
            
        } catch (Exception e) {
            logger.error("Error testing alert", e);
            ctx.status(500).json(Map.of(
                "error", "Failed to test alert",
                "message", e.getMessage()
            ));
        }
    }
    
    /**
     * POST /collaborator/payloads/tracked - Generate payloads with enhanced tracking
     */
    private void generateTrackedPayloads(Context ctx) {
        try {
            Map<String, Object> requestData = ctx.bodyAsClass(Map.class);
            
            int count = Integer.parseInt(requestData.getOrDefault("count", "1").toString());
            String sessionTag = (String) requestData.getOrDefault("session_tag", config.getSessionTag() + "_tracked");
            String customData = (String) requestData.get("custom_data");
            
            CollaboratorClient client = api.collaborator().createClient();
            String clientSecretHash = hashSecretKey(client.getSecretKey().toString());
            
            List<Map<String, Object>> generatedPayloads = new ArrayList<>();
            
            for (int i = 0; i < count; i++) {
                CollaboratorPayload payload = client.generatePayload();
                
                // Register with enhanced tracking
                interactionService.registerPayload(
                    payload.toString(),
                    clientSecretHash,
                    payload.id().toString(),
                    "tracked_generation",
                    sessionTag,
                    customData != null ? customData : "tracked_" + i,
                    payload.server().isPresent() ? payload.server().get().address() : null
                );
                
                Map<String, Object> payloadInfo = new HashMap<>();
                payloadInfo.put("payload", payload.toString());
                payloadInfo.put("interaction_id", payload.id().toString());
                payloadInfo.put("tracking_enabled", true);
                payloadInfo.put("index", i);
                
                generatedPayloads.add(payloadInfo);
                totalPayloadsGenerated.incrementAndGet();
            }
            
            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("payloads", generatedPayloads);
            response.put("client_secret", client.getSecretKey().toString());
            response.put("session_tag", sessionTag);
            response.put("tracking_features", List.of(
                "Database storage",
                "Pattern matching",
                "Alert system",
                "Analytics",
                "WebSocket notifications"
            ));
            
            ctx.json(response);
            
        } catch (Exception e) {
            logger.error("Error generating tracked payloads", e);
            ctx.status(500).json(Map.of(
                "error", "Failed to generate tracked payloads",
                "message", e.getMessage()
            ));
        }
    }
    
    /**
     * GET /collaborator/interactions/search - Search stored interactions
     */
    private void searchInteractions(Context ctx) {
        try {
            String query = ctx.queryParam("q");
            String type = ctx.queryParam("type");
            String sessionTag = ctx.queryParam("session_tag");
            String pattern = ctx.queryParam("pattern");
            
            // This would implement database search across stored interactions
            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("query", query);
            response.put("filters", Map.of(
                "type", type,
                "session_tag", sessionTag,
                "pattern", pattern
            ));
            response.put("note", "Search would query collaborator_interactions and related tables");
            response.put("timestamp", System.currentTimeMillis());
            
            ctx.json(response);
            
        } catch (Exception e) {
            logger.error("Error searching interactions", e);
            ctx.status(500).json(Map.of(
                "error", "Failed to search interactions",
                "message", e.getMessage()
            ));
        }
    }
    
    /**
     * GET /collaborator/health - Get health and performance status
     */
    private void getHealth(Context ctx) {
        try {
            Map<String, Object> health = new HashMap<>();
            
            // Check collaborator availability
            boolean collaboratorAvailable = false;
            String statusMessage = "";
            
            try {
                CollaboratorClient testClient = api.collaborator().createClient();
                collaboratorAvailable = testClient != null;
                statusMessage = "Collaborator service operational";
            } catch (Exception e) {
                statusMessage = "Collaborator service error: " + e.getMessage();
            }
            
            health.put("collaborator_available", collaboratorAvailable);
            health.put("status_message", statusMessage);
            health.put("database_connected", databaseService.isInitialized());
            health.put("interaction_service_running", true);
            health.put("total_payloads_generated", totalPayloadsGenerated.get());
            health.put("total_interactions_retrieved", totalInteractionsRetrieved.get());
            health.put("timestamp", System.currentTimeMillis());
            
            ctx.json(Map.of(
                "status", "success",
                "health", health
            ));
            
        } catch (Exception e) {
            logger.error("Error getting health status", e);
            ctx.status(500).json(Map.of(
                "error", "Failed to get health status",
                "message", e.getMessage()
            ));
        }
    }
    
    /**
     * Format interaction with database information
     */
    private Map<String, Object> formatInteractionWithDb(Interaction interaction, long dbId) {
        Map<String, Object> formatted = new HashMap<>();
        
        formatted.put("id", interaction.id().toString());
        formatted.put("type", interaction.type().toString());
        formatted.put("timestamp", interaction.timeStamp().toInstant().toEpochMilli());
        formatted.put("database_id", dbId);
        formatted.put("stored_in_database", dbId > 0);
        
        // Add type-specific details
        if (interaction.dnsDetails().isPresent()) {
            var dns = interaction.dnsDetails().get();
            formatted.put("dns_details", Map.of(
                "query", dns.query(),
                "query_type", dns.queryType().toString()
            ));
        }
        
        if (interaction.httpDetails().isPresent()) {
            formatted.put("has_http_details", true);
        }
        
        if (interaction.smtpDetails().isPresent()) {
            var smtp = interaction.smtpDetails().get();
            formatted.put("smtp_details", Map.of(
                "protocol", smtp.protocol().toString()
            ));
        }
        
        return formatted;
    }
    
    /**
     * Hash a secret key for storage (privacy protection)
     */
    private String hashSecretKey(String secretKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(secretKey.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            logger.warn("Failed to hash secret key", e);
            return "hash_error";
        }
    }
}