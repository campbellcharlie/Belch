package com.belch.handlers;

import com.belch.services.WebhookService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.Javalin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.CompletableFuture;

/**
 * Webhook API Routes
 * 
 * Provides REST API endpoints for webhook management:
 * - Register/unregister webhooks
 * - List webhooks and statistics
 * - Test webhook endpoints
 * - Manage webhook configurations
 */
public class WebhookRouteRegistrar {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookRouteRegistrar.class);
    
    private final WebhookService webhookService;
    private final ObjectMapper objectMapper;
    
    public WebhookRouteRegistrar(WebhookService webhookService) {
        this.webhookService = webhookService;
        this.objectMapper = new ObjectMapper();
    }
    
    /**
     * Register webhook-related routes.
     */
    public void registerRoutes(Javalin app) {
        
        // GET /webhooks - List all registered webhooks
        app.get("/webhooks", ctx -> {
            Map<String, Object> webhooks = webhookService.getWebhooks();
            ctx.json(webhooks);
        });
        
        // POST /webhooks - Register a new webhook
        app.post("/webhooks", ctx -> {
            try {
                Map<String, Object> requestBody = objectMapper.readValue(ctx.body(), Map.class);
                
                String url = (String) requestBody.get("url");
                if (url == null || url.trim().isEmpty()) {
                    ctx.status(400).json(Map.of(
                        "error", "Missing required field",
                        "message", "url field is required"
                    ));
                    return;
                }
                
                @SuppressWarnings("unchecked")
                List<String> eventTypes = (List<String>) requestBody.getOrDefault("event_types", List.of("*"));
                
                @SuppressWarnings("unchecked")
                Map<String, String> headers = (Map<String, String>) requestBody.getOrDefault("headers", new HashMap<>());
                
                String secret = (String) requestBody.get("secret");
                
                String webhookId = webhookService.registerWebhook(url, eventTypes, headers, secret);
                
                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("webhook_id", webhookId);
                response.put("url", url);
                response.put("event_types", eventTypes);
                response.put("message", "Webhook registered successfully");
                
                ctx.status(201).json(response);
                
            } catch (Exception e) {
                logger.error("Failed to register webhook", e);
                ctx.status(500).json(Map.of(
                    "error", "Internal server error",
                    "message", "Failed to register webhook: " + e.getMessage()
                ));
            }
        });
        
        // DELETE /webhooks/{webhookId} - Unregister a webhook
        app.delete("/webhooks/{webhookId}", ctx -> {
            String webhookId = ctx.pathParam("webhookId");
            
            boolean removed = webhookService.unregisterWebhook(webhookId);
            
            if (removed) {
                ctx.json(Map.of(
                    "success", true,
                    "webhook_id", webhookId,
                    "message", "Webhook unregistered successfully"
                ));
            } else {
                ctx.status(404).json(Map.of(
                    "error", "Not found",
                    "message", "Webhook not found",
                    "webhook_id", webhookId
                ));
            }
        });
        
        // POST /webhooks/{webhookId}/test - Test a webhook endpoint
        app.post("/webhooks/{webhookId}/test", ctx -> {
            String webhookId = ctx.pathParam("webhookId");
            
            try {
                CompletableFuture<Map<String, Object>> testResult = webhookService.testWebhook(webhookId);
                Map<String, Object> result = testResult.get();
                
                if ((Boolean) result.get("success")) {
                    ctx.json(Map.of(
                        "success", true,
                        "webhook_id", webhookId,
                        "status_code", result.get("status_code"),
                        "response_time_ms", result.get("response_time_ms"),
                        "message", "Webhook test successful"
                    ));
                } else {
                    ctx.status(400).json(Map.of(
                        "success", false,
                        "webhook_id", webhookId,
                        "error", result.get("error"),
                        "message", "Webhook test failed"
                    ));
                }
            } catch (Exception e) {
                logger.error("Failed to test webhook {}", webhookId, e);
                ctx.status(500).json(Map.of(
                    "error", "Internal server error",
                    "message", "Failed to test webhook: " + e.getMessage()
                ));
            }
        });
        
        // GET /webhooks/stats - Get webhook delivery statistics
        app.get("/webhooks/stats", ctx -> {
            Map<String, Object> stats = webhookService.getWebhookStats();
            ctx.json(stats);
        });
        
        // POST /webhooks/events/test - Send a test event to all webhooks
        app.post("/webhooks/events/test", ctx -> {
            try {
                Map<String, Object> requestBody = objectMapper.readValue(ctx.body(), Map.class);
                String eventType = (String) requestBody.getOrDefault("event_type", "webhook.manual_test");
                
                Map<String, Object> testData = new HashMap<>();
                testData.put("message", "Manual test event");
                testData.put("test_timestamp", System.currentTimeMillis());
                testData.put("custom_data", requestBody.getOrDefault("data", Map.of()));
                
                webhookService.sendSystemEvent(eventType, testData);
                
                ctx.json(Map.of(
                    "success", true,
                    "event_type", eventType,
                    "message", "Test event sent to all matching webhooks"
                ));
                
            } catch (Exception e) {
                logger.error("Failed to send test event", e);
                ctx.status(500).json(Map.of(
                    "error", "Internal server error",
                    "message", "Failed to send test event: " + e.getMessage()
                ));
            }
        });
        
        // GET /webhooks/events - List available event types
        app.get("/webhooks/events", ctx -> {
            Map<String, Object> events = new HashMap<>();
            
            // Define available event types by category
            Map<String, List<String>> eventsByCategory = new HashMap<>();
            
            eventsByCategory.put("Scanner Events", List.of(
                "scanner.scan.started",
                "scanner.scan.completed", 
                "scanner.scan.failed",
                "scanner.issue.found",
                "scanner.audit.started",
                "scanner.crawl.started"
            ));
            
            eventsByCategory.put("Collaborator Events", List.of(
                "collaborator.interaction.detected",
                "collaborator.pattern.matched",
                "collaborator.alert.triggered",
                "collaborator.payload.generated"
            ));
            
            eventsByCategory.put("Proxy Events", List.of(
                "proxy.traffic.captured",
                "proxy.traffic.tagged",
                "proxy.traffic.commented",
                "proxy.bulk.operation"
            ));
            
            eventsByCategory.put("System Events", List.of(
                "system.startup",
                "system.shutdown",
                "system.error",
                "system.warning",
                "system.performance.alert"
            ));
            
            eventsByCategory.put("Configuration Events", List.of(
                "config.updated",
                "config.reloaded",
                "config.validation.failed"
            ));
            
            events.put("event_types", eventsByCategory);
            events.put("wildcard_support", "Use '*' to receive all events or patterns like 'scanner.*' for category-specific events");
            events.put("custom_events", "You can also send custom events using the test endpoint");
            
            ctx.json(events);
        });
        
        // POST /webhooks/events/{eventType} - Manually trigger a specific event type
        app.post("/webhooks/events/{eventType}", ctx -> {
            String eventType = ctx.pathParam("eventType");
            
            try {
                Map<String, Object> requestBody = objectMapper.readValue(ctx.body(), Map.class);
                Map<String, Object> eventData = new HashMap<>();
                eventData.put("manual_trigger", true);
                eventData.put("triggered_at", System.currentTimeMillis());
                eventData.putAll(requestBody);
                
                // Determine event category and send appropriate webhook
                if (eventType.startsWith("scanner.")) {
                    webhookService.sendScannerEvent(eventType, eventData);
                } else if (eventType.startsWith("collaborator.")) {
                    webhookService.sendCollaboratorEvent(eventType, eventData);
                } else if (eventType.startsWith("proxy.")) {
                    webhookService.sendProxyEvent(eventType, eventData);
                } else if (eventType.startsWith("config.")) {
                    webhookService.sendConfigurationEvent(eventType, eventData);
                } else {
                    webhookService.sendSystemEvent(eventType, eventData);
                }
                
                ctx.json(Map.of(
                    "success", true,
                    "event_type", eventType,
                    "message", "Event triggered successfully"
                ));
                
            } catch (Exception e) {
                logger.error("Failed to trigger event {}", eventType, e);
                ctx.status(500).json(Map.of(
                    "error", "Internal server error", 
                    "message", "Failed to trigger event: " + e.getMessage()
                ));
            }
        });
        
        logger.info("Webhook routes registered successfully");
    }
}