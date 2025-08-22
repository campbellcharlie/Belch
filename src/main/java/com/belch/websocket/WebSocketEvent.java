package com.belch.websocket;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Map;
import java.util.HashMap;

/**
 * Represents a WebSocket event
 * 
 * This class encapsulates all data sent through WebSocket connections,
 * providing a standardized format for real-time updates.
 */
public class WebSocketEvent {
    
    @JsonProperty("event_type")
    private String eventType;
    
    @JsonProperty("timestamp")
    @JsonFormat(shape = JsonFormat.Shape.NUMBER)
    private Instant timestamp;
    
    @JsonProperty("session_tag")
    private String sessionTag;
    
    @JsonProperty("data")
    private Map<String, Object> data;
    
    @JsonProperty("metadata")
    private Map<String, Object> metadata;
    
    /**
     * Default constructor for JSON deserialization.
     */
    public WebSocketEvent() {
        this.timestamp = Instant.now();
        this.data = new HashMap<>();
        this.metadata = new HashMap<>();
    }
    
    /**
     * Create a WebSocket event with type and session.
     */
    public WebSocketEvent(WebSocketEventType eventType, String sessionTag) {
        this();
        this.eventType = eventType.getEventType();
        this.sessionTag = sessionTag;
    }
    
    /**
     * Create a WebSocket event with type, session, and data.
     */
    public WebSocketEvent(WebSocketEventType eventType, String sessionTag, Map<String, Object> data) {
        this(eventType, sessionTag);
        if (data != null) {
            this.data = new HashMap<>(data);
        }
    }
    
    // Getters and setters
    public String getEventType() {
        return eventType;
    }
    
    public void setEventType(String eventType) {
        this.eventType = eventType;
    }
    
    public Instant getTimestamp() {
        return timestamp;
    }
    
    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }
    
    public String getSessionTag() {
        return sessionTag;
    }
    
    public void setSessionTag(String sessionTag) {
        this.sessionTag = sessionTag;
    }
    
    public Map<String, Object> getData() {
        return data;
    }
    
    public void setData(Map<String, Object> data) {
        this.data = data != null ? data : new HashMap<>();
    }
    
    public Map<String, Object> getMetadata() {
        return metadata;
    }
    
    public void setMetadata(Map<String, Object> metadata) {
        this.metadata = metadata != null ? metadata : new HashMap<>();
    }
    
    // Convenience methods for data manipulation
    public WebSocketEvent addData(String key, Object value) {
        this.data.put(key, value);
        return this;
    }
    
    public WebSocketEvent addMetadata(String key, Object value) {
        this.metadata.put(key, value);
        return this;
    }
    
    public Object getData(String key) {
        return this.data.get(key);
    }
    
    public Object getMetadata(String key) {
        return this.metadata.get(key);
    }
    
    /**
     * Create a heartbeat event.
     */
    public static WebSocketEvent heartbeat(String sessionTag) {
        WebSocketEvent event = new WebSocketEvent(WebSocketEventType.HEARTBEAT, sessionTag);
        event.addData("alive", true);
        event.addMetadata("server_time", System.currentTimeMillis());
        return event;
    }
    
    /**
     * Create a welcome event for new connections.
     */
    public static WebSocketEvent welcome(String sessionTag, Map<String, Object> connectionInfo) {
        WebSocketEvent event = new WebSocketEvent(WebSocketEventType.WELCOME, sessionTag);
        event.addData("message", "WebSocket connection established");
        event.addData("phase", "Real-time Streaming");
        if (connectionInfo != null) {
            event.data.putAll(connectionInfo);
        }
        return event;
    }
    
    /**
     * Create an error event.
     */
    public static WebSocketEvent error(String sessionTag, String message, String details) {
        WebSocketEvent event = new WebSocketEvent(WebSocketEventType.ERROR, sessionTag);
        event.addData("message", message);
        if (details != null) {
            event.addData("details", details);
        }
        event.addMetadata("severity", "error");
        return event;
    }
    
    /**
     * Create a traffic event for new requests.
     */
    public static WebSocketEvent newTraffic(String sessionTag, Map<String, Object> trafficData) {
        WebSocketEvent event = new WebSocketEvent(WebSocketEventType.TRAFFIC_NEW, sessionTag);
        if (trafficData != null) {
            event.data.putAll(trafficData);
        }
        event.addMetadata("category", "traffic");
        return event;
    }
    
    /**
     * Create a statistics update event.
     */
    public static WebSocketEvent statsUpdate(String sessionTag, Map<String, Object> statsData) {
        WebSocketEvent event = new WebSocketEvent(WebSocketEventType.STATS_UPDATED, sessionTag);
        if (statsData != null) {
            event.data.putAll(statsData);
        }
        event.addMetadata("category", "statistics");
        return event;
    }
    
    /**
     * Create an acknowledgment event.
     */
    public static WebSocketEvent ack(String sessionTag, String message) {
        WebSocketEvent event = new WebSocketEvent(WebSocketEventType.SYSTEM_STATUS, sessionTag);
        event.addData("message", message);
        event.addData("status", "acknowledged");
        event.addMetadata("category", "acknowledgment");
        return event;
    }
    
    @Override
    public String toString() {
        return String.format("WebSocketEvent{type='%s', session='%s', timestamp=%s}", 
                           eventType, sessionTag, timestamp);
    }
} 