package com.belch.services;

import com.belch.config.ApiConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Phase 3 Task 13: Webhook Support for Events
 * 
 * Provides HTTP webhook notifications for API events including:
 * - Scanner scan completion
 * - Collaborator interactions  
 * - Proxy traffic events
 * - System status changes
 * - Configuration updates
 */
public class WebhookService {
    
    private static final Logger logger = LoggerFactory.getLogger(WebhookService.class);
    
    private final ApiConfig config;
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient;
    private final ExecutorService webhookExecutor;
    private final Map<String, WebhookConfiguration> webhooks;
    private final AtomicLong deliveryCounter = new AtomicLong(0);
    private final Map<String, AtomicLong> deliveryStats = new ConcurrentHashMap<>();
    
    // Webhook retry configuration
    private static final int MAX_RETRIES = 3;
    private static final Duration INITIAL_RETRY_DELAY = Duration.ofSeconds(1);
    private static final Duration MAX_RETRY_DELAY = Duration.ofMinutes(5);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);
    
    public WebhookService(ApiConfig config) {
        this.config = config;
        this.objectMapper = new ObjectMapper();
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(REQUEST_TIMEOUT)
            .build();
        this.webhookExecutor = Executors.newFixedThreadPool(5, r -> {
            Thread t = new Thread(r, "webhook-delivery-" + System.currentTimeMillis());
            t.setDaemon(true);
            return t;
        });
        this.webhooks = new ConcurrentHashMap<>();
        
        logger.info("[*] Webhook Service initialized");
    }
    
    /**
     * Register a webhook endpoint for specific event types.
     */
    public String registerWebhook(String url, List<String> eventTypes, Map<String, String> headers, String secret) {
        String webhookId = generateWebhookId();
        
        WebhookConfiguration webhook = new WebhookConfiguration(
            webhookId, url, eventTypes, headers, secret, true
        );
        
        webhooks.put(webhookId, webhook);
        deliveryStats.put(webhookId, new AtomicLong(0));
        
        logger.info("Registered webhook {} for events: {} -> {}", webhookId, eventTypes, url);
        return webhookId;
    }
    
    /**
     * Unregister a webhook.
     */
    public boolean unregisterWebhook(String webhookId) {
        WebhookConfiguration removed = webhooks.remove(webhookId);
        if (removed != null) {
            deliveryStats.remove(webhookId);
            logger.info("Unregistered webhook {}", webhookId);
            return true;
        }
        return false;
    }
    
    /**
     * Get all registered webhooks.
     */
    public Map<String, Object> getWebhooks() {
        Map<String, Object> result = new HashMap<>();
        
        List<Map<String, Object>> webhookList = new ArrayList<>();
        for (WebhookConfiguration webhook : webhooks.values()) {
            Map<String, Object> webhookInfo = new HashMap<>();
            webhookInfo.put("id", webhook.getId());
            webhookInfo.put("url", webhook.getUrl());
            webhookInfo.put("event_types", webhook.getEventTypes());
            webhookInfo.put("enabled", webhook.isEnabled());
            webhookInfo.put("created_at", webhook.getCreatedAt());
            webhookInfo.put("deliveries", deliveryStats.get(webhook.getId()).get());
            webhookList.add(webhookInfo);
        }
        
        result.put("webhooks", webhookList);
        result.put("total_webhooks", webhooks.size());
        result.put("total_deliveries", deliveryCounter.get());
        
        return result;
    }
    
    /**
     * Send webhook notification for scanner events.
     */
    public void sendScannerEvent(String eventType, Map<String, Object> scanData) {
        Map<String, Object> payload = createBasePayload(eventType);
        payload.put("scan_data", scanData);
        payload.put("category", "scanner");
        
        sendWebhookEvent(eventType, payload);
    }
    
    /**
     * Send webhook notification for collaborator events.
     */
    public void sendCollaboratorEvent(String eventType, Map<String, Object> interactionData) {
        Map<String, Object> payload = createBasePayload(eventType);
        payload.put("interaction_data", interactionData);
        payload.put("category", "collaborator");
        
        sendWebhookEvent(eventType, payload);
    }
    
    /**
     * Send webhook notification for proxy traffic events.
     */
    public void sendProxyEvent(String eventType, Map<String, Object> trafficData) {
        Map<String, Object> payload = createBasePayload(eventType);
        payload.put("traffic_data", trafficData);
        payload.put("category", "proxy");
        
        sendWebhookEvent(eventType, payload);
    }
    
    /**
     * Send webhook notification for system events.
     */
    public void sendSystemEvent(String eventType, Map<String, Object> systemData) {
        Map<String, Object> payload = createBasePayload(eventType);
        payload.put("system_data", systemData);
        payload.put("category", "system");
        
        sendWebhookEvent(eventType, payload);
    }
    
    /**
     * Send webhook notification for configuration events.
     */
    public void sendConfigurationEvent(String eventType, Map<String, Object> configData) {
        Map<String, Object> payload = createBasePayload(eventType);
        payload.put("config_data", configData);
        payload.put("category", "configuration");
        
        sendWebhookEvent(eventType, payload);
    }
    
    /**
     * Test a webhook endpoint.
     */
    public CompletableFuture<Map<String, Object>> testWebhook(String webhookId) {
        WebhookConfiguration webhook = webhooks.get(webhookId);
        if (webhook == null) {
            return CompletableFuture.completedFuture(Map.of(
                "success", false,
                "error", "Webhook not found"
            ));
        }
        
        Map<String, Object> testPayload = createBasePayload("webhook.test");
        testPayload.put("message", "This is a test webhook delivery");
        testPayload.put("webhook_id", webhookId);
        
        return deliverWebhook(webhook, testPayload)
            .thenApply(result -> {
                Map<String, Object> response = new HashMap<>();
                response.put("success", result.isSuccess());
                response.put("status_code", result.getStatusCode());
                response.put("response_time_ms", result.getResponseTimeMs());
                if (!result.isSuccess()) {
                    response.put("error", result.getError());
                }
                return response;
            });
    }
    
    /**
     * Get webhook delivery statistics.
     */
    public Map<String, Object> getWebhookStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("total_deliveries", deliveryCounter.get());
        stats.put("active_webhooks", webhooks.size());
        
        Map<String, Object> webhookStats = new HashMap<>();
        for (Map.Entry<String, AtomicLong> entry : deliveryStats.entrySet()) {
            webhookStats.put(entry.getKey(), entry.getValue().get());
        }
        stats.put("webhook_deliveries", webhookStats);
        
        // Executor statistics
        if (webhookExecutor instanceof ThreadPoolExecutor) {
            ThreadPoolExecutor tpe = (ThreadPoolExecutor) webhookExecutor;
            stats.put("executor_stats", Map.of(
                "active_threads", tpe.getActiveCount(),
                "completed_tasks", tpe.getCompletedTaskCount(),
                "queue_size", tpe.getQueue().size()
            ));
        }
        
        return stats;
    }
    
    private void sendWebhookEvent(String eventType, Map<String, Object> payload) {
        List<WebhookConfiguration> matchingWebhooks = new ArrayList<>();
        
        for (WebhookConfiguration webhook : webhooks.values()) {
            if (webhook.isEnabled() && webhook.shouldReceiveEvent(eventType)) {
                matchingWebhooks.add(webhook);
            }
        }
        
        if (matchingWebhooks.isEmpty()) {
            logger.debug("No webhooks registered for event type: {}", eventType);
            return;
        }
        
        logger.debug("Delivering event {} to {} webhooks", eventType, matchingWebhooks.size());
        
        for (WebhookConfiguration webhook : matchingWebhooks) {
            webhookExecutor.submit(() -> {
                try {
                    DeliveryResult result = deliverWebhook(webhook, payload).get();
                    deliveryCounter.incrementAndGet();
                    deliveryStats.get(webhook.getId()).incrementAndGet();
                    
                    if (result.isSuccess()) {
                        logger.debug("Successfully delivered {} to webhook {}", eventType, webhook.getId());
                    } else {
                        logger.warn("Failed to deliver {} to webhook {}: {}", eventType, webhook.getId(), result.getError());
                    }
                } catch (Exception e) {
                    logger.error("Error delivering webhook for event {}: {}", eventType, e.getMessage(), e);
                }
            });
        }
    }
    
    private CompletableFuture<DeliveryResult> deliverWebhook(WebhookConfiguration webhook, Map<String, Object> payload) {
        return CompletableFuture.supplyAsync(() -> {
            long startTime = System.currentTimeMillis();
            
            for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
                try {
                    // Add webhook metadata
                    Map<String, Object> fullPayload = new HashMap<>(payload);
                    fullPayload.put("webhook_id", webhook.getId());
                    fullPayload.put("delivery_attempt", attempt + 1);
                    
                    String jsonPayload = objectMapper.writeValueAsString(fullPayload);
                    
                    // Build request
                    HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                        .uri(URI.create(webhook.getUrl()))
                        .timeout(REQUEST_TIMEOUT)
                        .header("Content-Type", "application/json")
                        .header("User-Agent", "Belch-Webhook/1.0")
                        .POST(HttpRequest.BodyPublishers.ofString(jsonPayload));
                    
                    // Add custom headers
                    for (Map.Entry<String, String> header : webhook.getHeaders().entrySet()) {
                        requestBuilder.header(header.getKey(), header.getValue());
                    }
                    
                    // Add signature if secret is provided
                    if (webhook.getSecret() != null && !webhook.getSecret().isEmpty()) {
                        String signature = generateSignature(jsonPayload, webhook.getSecret());
                        requestBuilder.header("X-Webhook-Signature", signature);
                    }
                    
                    HttpRequest request = requestBuilder.build();
                    
                    // Send request
                    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                    long responseTime = System.currentTimeMillis() - startTime;
                    
                    if (response.statusCode() >= 200 && response.statusCode() < 300) {
                        return new DeliveryResult(true, response.statusCode(), responseTime, null);
                    } else {
                        String error = "HTTP " + response.statusCode() + ": " + response.body();
                        if (attempt == MAX_RETRIES - 1) {
                            return new DeliveryResult(false, response.statusCode(), responseTime, error);
                        }
                        logger.warn("Webhook delivery attempt {} failed for {}: {}", attempt + 1, webhook.getId(), error);
                    }
                    
                } catch (Exception e) {
                    long responseTime = System.currentTimeMillis() - startTime;
                    String error = e.getMessage();
                    
                    if (attempt == MAX_RETRIES - 1) {
                        return new DeliveryResult(false, 0, responseTime, error);
                    }
                    logger.warn("Webhook delivery attempt {} failed for {}: {}", attempt + 1, webhook.getId(), error);
                }
                
                // Wait before retry with exponential backoff
                if (attempt < MAX_RETRIES - 1) {
                    try {
                        long delay = Math.min(
                            INITIAL_RETRY_DELAY.toMillis() * (1L << attempt),
                            MAX_RETRY_DELAY.toMillis()
                        );
                        Thread.sleep(delay);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
            
            long responseTime = System.currentTimeMillis() - startTime;
            return new DeliveryResult(false, 0, responseTime, "Max retries exceeded");
        }, webhookExecutor);
    }
    
    private Map<String, Object> createBasePayload(String eventType) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("event_type", eventType);
        payload.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        payload.put("source", "belch-api");
        payload.put("api_version", "1.0");
        payload.put("session_tag", config.getSessionTag());
        return payload;
    }
    
    private String generateWebhookId() {
        return "webhook_" + System.currentTimeMillis() + "_" + (int)(Math.random() * 1000);
    }
    
    private String generateSignature(String payload, String secret) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(secret.getBytes(), "HmacSHA256");
            mac.init(secretKey);
            byte[] hash = mac.doFinal(payload.getBytes());
            return "sha256=" + bytesToHex(hash);
        } catch (Exception e) {
            logger.error("Failed to generate webhook signature", e);
            return "";
        }
    }
    
    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
    
    /**
     * Shutdown the webhook service.
     */
    public void shutdown() {
        logger.info("Shutting down webhook service...");
        webhookExecutor.shutdown();
        try {
            if (!webhookExecutor.awaitTermination(10, TimeUnit.SECONDS)) {
                webhookExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            webhookExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        logger.info("Webhook service shutdown complete. Total deliveries: {}", deliveryCounter.get());
    }
    
    /**
     * Webhook configuration class.
     */
    private static class WebhookConfiguration {
        private final String id;
        private final String url;
        private final List<String> eventTypes;
        private final Map<String, String> headers;
        private final String secret;
        private final boolean enabled;
        private final String createdAt;
        
        public WebhookConfiguration(String id, String url, List<String> eventTypes, 
                                  Map<String, String> headers, String secret, boolean enabled) {
            this.id = id;
            this.url = url;
            this.eventTypes = new ArrayList<>(eventTypes);
            this.headers = headers != null ? new HashMap<>(headers) : new HashMap<>();
            this.secret = secret;
            this.enabled = enabled;
            this.createdAt = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        }
        
        public boolean shouldReceiveEvent(String eventType) {
            return eventTypes.contains("*") || eventTypes.contains(eventType) || 
                   eventTypes.stream().anyMatch(pattern -> eventType.matches(pattern.replace("*", ".*")));
        }
        
        // Getters
        public String getId() { return id; }
        public String getUrl() { return url; }
        public List<String> getEventTypes() { return eventTypes; }
        public Map<String, String> getHeaders() { return headers; }
        public String getSecret() { return secret; }
        public boolean isEnabled() { return enabled; }
        public String getCreatedAt() { return createdAt; }
    }
    
    /**
     * Webhook delivery result class.
     */
    private static class DeliveryResult {
        private final boolean success;
        private final int statusCode;
        private final long responseTimeMs;
        private final String error;
        
        public DeliveryResult(boolean success, int statusCode, long responseTimeMs, String error) {
            this.success = success;
            this.statusCode = statusCode;
            this.responseTimeMs = responseTimeMs;
            this.error = error;
        }
        
        // Getters
        public boolean isSuccess() { return success; }
        public int getStatusCode() { return statusCode; }
        public long getResponseTimeMs() { return responseTimeMs; }
        public String getError() { return error; }
    }
}