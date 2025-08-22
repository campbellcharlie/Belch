package com.belch.websocket;

/**
 * Defines the types of events that can be streamed via WebSocket
 * 
 *  Real-time WebSocket Traffic Streaming
 * - Live traffic monitoring
 * - Real-time statistics updates
 * - Event-driven notifications
 */
public enum WebSocketEventType {
    
    // Traffic Events
    TRAFFIC_NEW("traffic.new", "New traffic record captured"),
    TRAFFIC_UPDATED("traffic.updated", "Existing traffic record updated"),
    TRAFFIC_TAGGED("traffic.tagged", "Traffic record tagged"),
    TRAFFIC_COMMENTED("traffic.commented", "Comment added to traffic record"),
    
    // Scanner Events  
    SCANNER_ISSUE_FOUND("scanner.issue.found", "New vulnerability discovered"),
    SCANNER_SCAN_STARTED("scanner.scan.started", "Scan initiated"),
    SCANNER_SCAN_COMPLETED("scanner.scan.completed", "Scan completed"),
    SCAN_PROGRESS("scan.progress", "Real-time scan progress update"),
    
    // Session Events
    SESSION_CHANGED("session.changed", "Session tag updated"),
    SESSION_STATS_UPDATED("session.stats.updated", "Session statistics updated"),
    
    // Performance Events
    PERFORMANCE_ALERT("performance.alert", "Performance threshold exceeded"),
    MEMORY_WARNING("memory.warning", "Memory usage warning"),
    
    // Statistics Events
    STATS_UPDATED("stats.updated", "Real-time statistics updated"),
    STATS_HOST_NEW("stats.host.new", "New host detected"),
    STATS_STATUS_ALERT("stats.status.alert", "Status code alert triggered"),
    
    // Search Events
    SEARCH_RESULT_LIVE("search.result.live", "Live search result update"),
    SEARCH_QUERY_SAVED("search.query.saved", "Search query saved"),
    
    // System Events
    SYSTEM_STATUS("system.status", "System status update"),
    CONNECTION_STATUS("connection.status", "Connection status change"),
    
    // Replay Events
    REPLAY_STARTED("replay.started", "Request replay initiated"),
    REPLAY_COMPLETED("replay.completed", "Request replay completed"),
    
    // Collaborator Events 
    COLLABORATOR_INTERACTION("collaborator.interaction", "Collaborator interaction detected"),
    COLLABORATOR_ALERT("collaborator.alert", "Collaborator security alert triggered"),
    
    // Enhanced Queue Events 
    QUEUE_METRICS("queue.metrics", "Enhanced traffic queue metrics update"),
    
    // Generic Events
    ERROR("error", "Error notification"),
    HEARTBEAT("heartbeat", "Connection heartbeat"),
    WELCOME("welcome", "Connection established");
    
    private final String eventType;
    private final String description;
    
    WebSocketEventType(String eventType, String description) {
        this.eventType = eventType;
        this.description = description;
    }
    
    public String getEventType() {
        return eventType;
    }
    
    public String getDescription() {
        return description;
    }
    
    /**
     * Get event type from string representation.
     */
    public static WebSocketEventType fromString(String eventType) {
        for (WebSocketEventType type : values()) {
            if (type.eventType.equals(eventType)) {
                return type;
            }
        }
        return null;
    }
    
    @Override
    public String toString() {
        return eventType;
    }
} 