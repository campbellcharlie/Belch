package com.belch.websocket;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.javalin.websocket.WsContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.zip.GZIPOutputStream;

/**
 * Manages WebSocket connections and event broadcasting for real-time traffic streaming.
 * 
 * Features:
 * - Connection lifecycle management
 * - Event filtering and subscription
 * - Heartbeat monitoring
 * - Performance metrics
 * - Session-based filtering
 */
public class WebSocketManager {
    
    private static final Logger logger = LoggerFactory.getLogger(WebSocketManager.class);
    
    // Connection management
    private final Map<String, WebSocketConnection> connections = new ConcurrentHashMap<>();
    private final Map<String, Set<String>> sessionSubscriptions = new ConcurrentHashMap<>();
    private final ObjectMapper objectMapper;
    
    // Performance tracking
    private final AtomicLong totalConnections = new AtomicLong(0);
    private final AtomicLong activeConnections = new AtomicLong(0);
    private final AtomicLong eventsSent = new AtomicLong(0);
    private final AtomicLong eventsFailed = new AtomicLong(0);
    private final AtomicLong lastActivity = new AtomicLong(System.currentTimeMillis());
    private final AtomicLong totalEventsSent = new AtomicLong(0);
    private final long startTime = System.currentTimeMillis();
    
    // Heartbeat system
    private final ScheduledExecutorService heartbeatExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "WebSocket-Heartbeat");
        t.setDaemon(true);
        return t;
    });
    
    private static final int HEARTBEAT_INTERVAL_SECONDS = 30;
    private static final int CONNECTION_TIMEOUT_SECONDS = 90;
    
    public WebSocketManager() {
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
        
        // Start heartbeat monitoring
        startHeartbeatMonitoring();
        
        logger.info("[*] WebSocket Manager initialized");
    }
    
    /**
     * Handle new WebSocket connection.
     */
    public void handleConnect(WsContext ctx) {
        try {
            String connectionId = generateConnectionId();
            String sessionTag = extractSessionTag(ctx);
            
            WebSocketConnection connection = new WebSocketConnection(connectionId, ctx, sessionTag);
            connections.put(connectionId, connection);
            
            // Subscribe to session if specified
            if (sessionTag != null) {
                sessionSubscriptions.computeIfAbsent(sessionTag, k -> new CopyOnWriteArraySet<>()).add(connectionId);
            }
            
            totalConnections.incrementAndGet();
            activeConnections.incrementAndGet();
            
            // Send welcome message
            Map<String, Object> connectionInfo = Map.of(
                "connection_id", connectionId,
                "total_connections", totalConnections.get(),
                "server_version", "2.1.0",
                "capabilities", java.util.List.of(
                    "live_traffic", 
                    "statistics", 
                    "search", 
                    "heartbeat",
                    "selective_subscription",
                    "rate_limiting",
                    "compression",
                    "replay_buffer",
                    "advanced_filtering"
                )
            );
            
            sendToConnection(connectionId, WebSocketEvent.welcome(sessionTag, connectionInfo));
            
            logger.info("[+] WebSocket connection established: {} (session: {})", connectionId, sessionTag);
            
        } catch (Exception e) {
            logger.error("[!] Failed to handle WebSocket connection", e);
            ctx.closeSession(1011, "Server error during connection setup");
        }
    }
    
    /**
     * Handle WebSocket disconnection.
     */
    public void handleDisconnect(WsContext ctx) {
        String connectionId = findConnectionId(ctx);
        if (connectionId != null) {
            WebSocketConnection connection = connections.remove(connectionId);
            if (connection != null) {
                // Remove from session subscriptions
                String sessionTag = connection.getSessionTag();
                if (sessionTag != null) {
                    Set<String> sessionConnections = sessionSubscriptions.get(sessionTag);
                    if (sessionConnections != null) {
                        sessionConnections.remove(connectionId);
                        if (sessionConnections.isEmpty()) {
                            sessionSubscriptions.remove(sessionTag);
                        }
                    }
                }
                
                activeConnections.decrementAndGet();
                logger.info("[-] WebSocket connection closed: {} (session: {})", connectionId, sessionTag);
            }
        }
    }
    
    /**
     * Handle incoming WebSocket message.
     */
    public void handleMessage(WsContext ctx, String message) {
        String connectionId = findConnectionId(ctx);
        if (connectionId == null) {
            logger.warn("[!] Received message from unknown connection");
            return;
        }
        
        try {
            // Parse incoming message as a subscription request or command
            Map<String, Object> request = objectMapper.readValue(message, Map.class);
            handleClientRequest(connectionId, request);
            
        } catch (Exception e) {
            logger.error("[!] Failed to process WebSocket message from {}: {}", connectionId, e.getMessage());
            sendToConnection(connectionId, WebSocketEvent.error(null, "Invalid message format", e.getMessage()));
        }
    }
    
    /**
     * Broadcast event to all connections.
     */
    public void broadcast(WebSocketEvent event) {
        broadcastToSession(event, null);
    }
    
    /**
     * Broadcast event to connections subscribed to a specific session.
     */
    public void broadcastToSession(WebSocketEvent event, String sessionTag) {
        Set<String> targetConnections;
        
        if (sessionTag != null) {
            targetConnections = sessionSubscriptions.get(sessionTag);
            if (targetConnections == null || targetConnections.isEmpty()) {
                return; // No subscribers for this session
            }
        } else {
            targetConnections = connections.keySet();
        }
        
        String eventJson;
        try {
            eventJson = objectMapper.writeValueAsString(event);
        } catch (Exception e) {
            logger.error("[!] Failed to serialize WebSocket event: {}", e.getMessage());
            return;
        }
        
        int successCount = 0;
        int failureCount = 0;
        int rateLimitedCount = 0;
        int filteredCount = 0;
        
        for (String connectionId : targetConnections) {
            try {
                WebSocketConnection connection = connections.get(connectionId);
                if (connection == null || !connection.isOpen()) {
                    // Clean up stale connection
                    connections.remove(connectionId);
                    failureCount++;
                    continue;
                }
                
                // Check event type subscription
                WebSocketEventType eventType = WebSocketEventType.fromString(event.getEventType());
                if (eventType != null && !connection.isSubscribedTo(eventType)) {
                    filteredCount++;
                    continue;
                }
                
                // Check custom filters
                if (!connection.matchesFilters(eventJson)) {
                    filteredCount++;
                    continue;
                }
                
                // Check rate limiting
                if (!connection.canSendMessage()) {
                    rateLimitedCount++;
                    continue;
                }
                
                // Add to replay buffer before sending
                connection.addToReplayBuffer(eventJson);
                
                // Send message (with compression if enabled)
                String messageToSend = eventJson;
                if (connection.isCompressionEnabled()) {
                    messageToSend = compressMessage(eventJson);
                }
                
                connection.getContext().send(messageToSend);
                connection.updateLastActivity();
                successCount++;
                
            } catch (Exception e) {
                logger.debug("Failed to send event to connection {}: {}", connectionId, e.getMessage());
                failureCount++;
            }
        }
        
        eventsSent.addAndGet(successCount);
        eventsFailed.addAndGet(failureCount);
        
        if (logger.isDebugEnabled()) {
            logger.debug("Broadcast event {} to {} connections (success: {}, failed: {}, rate-limited: {}, filtered: {})", 
                        event.getEventType(), targetConnections.size(), successCount, failureCount, rateLimitedCount, filteredCount);
        }
    }
    
    /**
     * Send event to specific connection.
     */
    public boolean sendToConnection(String connectionId, WebSocketEvent event) {
        WebSocketConnection connection = connections.get(connectionId);
        if (connection == null || !connection.isOpen()) {
            return false;
        }
        
        try {
            String eventJson = objectMapper.writeValueAsString(event);
            connection.getContext().send(eventJson);
            connection.updateLastActivity();
            eventsSent.incrementAndGet();
            return true;
        } catch (Exception e) {
            logger.debug("Failed to send event to connection {}: {}", connectionId, e.getMessage());
            eventsFailed.incrementAndGet();
            return false;
        }
    }
    
    /**
     * Get performance statistics.
     */
    public Map<String, Object> getStatistics() {
        return Map.of(
            "total_connections", totalConnections.get(),
            "active_connections", activeConnections.get(),
            "events_sent", eventsSent.get(),
            "events_failed", eventsFailed.get(),
            "session_subscriptions", sessionSubscriptions.size(),
            "heartbeat_interval_seconds", HEARTBEAT_INTERVAL_SECONDS
        );
    }
    
    /**
     * Shutdown the WebSocket manager.
     */
    public void shutdown() {
        logger.info("[*] Shutting down WebSocket manager...");
        
        // Send goodbye message to all connections
        WebSocketEvent goodbyeEvent = new WebSocketEvent(WebSocketEventType.SYSTEM_STATUS, null);
        goodbyeEvent.addData("message", "Server shutting down");
        goodbyeEvent.addData("code", 1001);
        broadcast(goodbyeEvent);
        
        // Close all connections
        for (WebSocketConnection connection : connections.values()) {
            try {
                if (connection.isOpen()) {
                    connection.getContext().closeSession(1001, "Server shutdown");
                }
            } catch (Exception e) {
                logger.debug("Error closing WebSocket connection: {}", e.getMessage());
            }
        }
        
        connections.clear();
        sessionSubscriptions.clear();
        
        heartbeatExecutor.shutdown();
        try {
            if (!heartbeatExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                heartbeatExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            heartbeatExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        
        logger.info("[+] WebSocket manager shutdown complete");
    }
    
    // Private helper methods
    
    private void startHeartbeatMonitoring() {
        heartbeatExecutor.scheduleAtFixedRate(() -> {
            try {
                long currentTime = System.currentTimeMillis();
                
                for (Map.Entry<String, WebSocketConnection> entry : connections.entrySet()) {
                    WebSocketConnection connection = entry.getValue();
                    
                    // Check for stale connections
                    if (currentTime - connection.getLastActivity() > CONNECTION_TIMEOUT_SECONDS * 1000) {
                        logger.debug("Removing stale WebSocket connection: {}", entry.getKey());
                        connections.remove(entry.getKey());
                        activeConnections.decrementAndGet();
                        continue;
                    }
                    
                    // Send heartbeat
                    if (connection.isOpen()) {
                        sendToConnection(entry.getKey(), WebSocketEvent.heartbeat(connection.getSessionTag()));
                    }
                }
                
            } catch (Exception e) {
                logger.error("[!] Error during heartbeat monitoring", e);
            }
        }, HEARTBEAT_INTERVAL_SECONDS, HEARTBEAT_INTERVAL_SECONDS, TimeUnit.SECONDS);
    }
    
    private String generateConnectionId() {
        return "ws_" + System.currentTimeMillis() + "_" + (int)(Math.random() * 10000);
    }
    
    private String extractSessionTag(WsContext ctx) {
        // No session tag filtering - broadcast all traffic
        return null;
    }
    
    private String findConnectionId(WsContext ctx) {
        for (Map.Entry<String, WebSocketConnection> entry : connections.entrySet()) {
            if (entry.getValue().getContext() == ctx) {
                return entry.getKey();
            }
        }
        return null;
    }
    
    private void handleClientRequest(String connectionId, Map<String, Object> request) {
        String action = (String) request.get("action");
        if (action == null) {
            return;
        }
        
        WebSocketConnection connection = connections.get(connectionId);
        if (connection == null) {
            return;
        }
        
        switch (action) {
            case "subscribe_session":
                String sessionTag = (String) request.get("session_tag");
                if (sessionTag != null) {
                    sessionSubscriptions.computeIfAbsent(sessionTag, k -> new CopyOnWriteArraySet<>()).add(connectionId);
                    connection.setSessionTag(sessionTag);
                    logger.debug("Connection {} subscribed to session: {}", connectionId, sessionTag);
                }
                break;
                
            case "subscribe_events":
                handleEventSubscription(connectionId, connection, request);
                break;
                
            case "set_filters":
                handleFilterConfiguration(connectionId, connection, request);
                break;
                
            case "set_rate_limit":
                Integer rateLimit = (Integer) request.get("rate_limit");
                if (rateLimit != null && rateLimit > 0) {
                    connection.setRateLimit(rateLimit);
                    sendToConnection(connectionId, WebSocketEvent.ack(connection.getSessionTag(), 
                        "Rate limit set to " + rateLimit + " messages/second"));
                }
                break;
                
            case "enable_compression":
                Boolean compression = (Boolean) request.get("enabled");
                if (compression != null) {
                    connection.setCompressionEnabled(compression);
                    sendToConnection(connectionId, WebSocketEvent.ack(connection.getSessionTag(), 
                        "Compression " + (compression ? "enabled" : "disabled")));
                }
                break;
                
            case "set_replay_buffer_size":
                Integer bufferSize = (Integer) request.get("buffer_size");
                if (bufferSize != null && bufferSize >= 0) {
                    connection.setReplayBufferSize(bufferSize);
                    sendToConnection(connectionId, WebSocketEvent.ack(connection.getSessionTag(), 
                        "Replay buffer size set to " + bufferSize));
                }
                break;
                
            case "get_replay_buffer":
                handleReplayBufferRequest(connectionId, connection);
                break;
                
            case "ping":
                sendToConnection(connectionId, WebSocketEvent.heartbeat(connection.getSessionTag()));
                break;
                
            default:
                logger.debug("Unknown WebSocket action: {}", action);
                sendToConnection(connectionId, WebSocketEvent.error(connection.getSessionTag(), 
                    "Unknown action", "Action '" + action + "' is not supported"));
                break;
        }
    }
    
    /**
     * Handle event subscription configuration
     */
    private void handleEventSubscription(String connectionId, WebSocketConnection connection, Map<String, Object> request) {
        List<String> eventTypes = (List<String>) request.get("event_types");
        Boolean subscribeAll = (Boolean) request.get("subscribe_all");
        
        if (subscribeAll != null && subscribeAll) {
            connection.subscribeToAllEvents();
            sendToConnection(connectionId, WebSocketEvent.ack(connection.getSessionTag(), 
                "Subscribed to all event types"));
        } else if (eventTypes != null && !eventTypes.isEmpty()) {
            Set<WebSocketEventType> eventTypeSet = new HashSet<>();
            for (String eventType : eventTypes) {
                WebSocketEventType type = WebSocketEventType.fromString(eventType);
                if (type != null) {
                    eventTypeSet.add(type);
                }
            }
            
            connection.subscribeToEventTypes(eventTypeSet);
            sendToConnection(connectionId, WebSocketEvent.ack(connection.getSessionTag(), 
                "Subscribed to " + eventTypeSet.size() + " event types"));
        }
    }
    
    /**
     * Handle filter configuration
     */
    private void handleFilterConfiguration(String connectionId, WebSocketConnection connection, Map<String, Object> request) {
        String severityFilter = (String) request.get("severity_filter");
        String hostFilter = (String) request.get("host_filter");
        String methodFilter = (String) request.get("method_filter");
        List<String> customFilters = (List<String>) request.get("custom_filters");
        
        if (severityFilter != null) {
            connection.setSeverityFilter(severityFilter);
        }
        
        if (hostFilter != null) {
            connection.setHostFilter(hostFilter);
        }
        
        if (methodFilter != null) {
            connection.setMethodFilter(methodFilter);
        }
        
        if (customFilters != null) {
            // Clear existing filters and add new ones
            connection.getEventFilters().clear();
            for (String filter : customFilters) {
                connection.addEventFilter(filter);
            }
        }
        
        sendToConnection(connectionId, WebSocketEvent.ack(connection.getSessionTag(), "Filters updated"));
    }
    
    /**
     * Handle replay buffer request
     */
    private void handleReplayBufferRequest(String connectionId, WebSocketConnection connection) {
        Queue<String> replayBuffer = connection.getReplayBuffer();
        
        WebSocketEvent replayEvent = new WebSocketEvent(WebSocketEventType.SYSTEM_STATUS, connection.getSessionTag());
        replayEvent.addData("replay_buffer_size", replayBuffer.size());
        replayEvent.addData("replay_events", replayBuffer.toArray());
        
        sendToConnection(connectionId, replayEvent);
    }
    
    /**
     * Get WebSocket connection statistics
     */
    public Map<String, Object> getConnectionStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("total_connections", connections.size());
        stats.put("active_connections", connections.values().stream()
            .mapToLong(conn -> conn.isOpen() ? 1 : 0)
            .sum());
        
        Map<String, Long> sessionCounts = new HashMap<>();
        for (WebSocketConnection conn : connections.values()) {
            String sessionTag = conn.getSessionTag();
            // Handle null session tags properly for JSON serialization
            String sessionKey = (sessionTag != null) ? sessionTag : "no_session";
            sessionCounts.put(sessionKey, sessionCounts.getOrDefault(sessionKey, 0L) + 1);
        }
        stats.put("connections_by_session", sessionCounts);
        stats.put("last_activity", lastActivity.get());
        stats.put("total_events_sent", totalEventsSent.get());
        stats.put("uptime_ms", System.currentTimeMillis() - startTime);
        
        return stats;
    }
    
    /**
     * Compress message using GZIP
     */
    private String compressMessage(String message) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (GZIPOutputStream gzipOut = new GZIPOutputStream(baos)) {
                gzipOut.write(message.getBytes("UTF-8"));
            }
            return java.util.Base64.getEncoder().encodeToString(baos.toByteArray());
        } catch (IOException e) {
            logger.warn("Failed to compress message: {}", e.getMessage());
            return message; // Return original if compression fails
        }
    }
} 