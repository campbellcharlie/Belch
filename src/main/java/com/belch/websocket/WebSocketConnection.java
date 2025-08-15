package com.belch.websocket;

import io.javalin.websocket.WsContext;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.LinkedList;
import java.util.Queue;

/**
 * Represents an individual WebSocket connection with enhanced streaming capabilities.
 * 
 * Features:
 * - Selective event type subscription
 * - Per-connection rate limiting
 * - Event replay buffer
 * - Complex filtering support
 * - Connection compression settings
 */
public class WebSocketConnection {
    
    private final String connectionId;
    private final WsContext context;
    private String sessionTag;
    private final long connectedAt;
    private volatile long lastActivity;
    
    // Enhanced subscription management
    private final Set<WebSocketEventType> subscribedEventTypes = ConcurrentHashMap.newKeySet();
    private final Set<String> eventFilters = ConcurrentHashMap.newKeySet();
    private boolean subscribeToAll = true; // Default: all events
    
    // Rate limiting
    private final AtomicLong messagesThisSecond = new AtomicLong(0);
    private volatile long currentSecond = System.currentTimeMillis() / 1000;
    private int maxMessagesPerSecond = 100; // Default rate limit
    
    // Event replay buffer
    private final Queue<String> replayBuffer = new LinkedList<>();
    private final AtomicInteger replayBufferSize = new AtomicInteger(50); // Default buffer size
    private final Object replayLock = new Object();
    
    // Compression and filtering settings
    private boolean compressionEnabled = false;
    private String severityFilter = null; // HIGH, MEDIUM, LOW, INFO
    private String hostFilter = null;
    private String methodFilter = null;
    
    public WebSocketConnection(String connectionId, WsContext context, String sessionTag) {
        this.connectionId = connectionId;
        this.context = context;
        this.sessionTag = sessionTag;
        this.connectedAt = System.currentTimeMillis();
        this.lastActivity = this.connectedAt;
    }
    
    public String getConnectionId() {
        return connectionId;
    }
    
    public WsContext getContext() {
        return context;
    }
    
    public String getSessionTag() {
        return sessionTag;
    }
    
    public void setSessionTag(String sessionTag) {
        this.sessionTag = sessionTag;
    }
    
    public long getConnectedAt() {
        return connectedAt;
    }
    
    public long getLastActivity() {
        return lastActivity;
    }
    
    public void updateLastActivity() {
        this.lastActivity = System.currentTimeMillis();
    }
    
    public boolean isOpen() {
        try {
            return context != null && context.session.isOpen();
        } catch (Exception e) {
            return false;
        }
    }
    
    // Event subscription methods
    
    /**
     * Subscribe to specific event types
     */
    public void subscribeToEventTypes(Set<WebSocketEventType> eventTypes) {
        this.subscribeToAll = false;
        this.subscribedEventTypes.clear();
        this.subscribedEventTypes.addAll(eventTypes);
    }
    
    /**
     * Subscribe to all event types
     */
    public void subscribeToAllEvents() {
        this.subscribeToAll = true;
        this.subscribedEventTypes.clear();
    }
    
    /**
     * Check if connection is subscribed to a specific event type
     */
    public boolean isSubscribedTo(WebSocketEventType eventType) {
        return subscribeToAll || subscribedEventTypes.contains(eventType);
    }
    
    /**
     * Add event filter (e.g., hostname, method, etc.)
     */
    public void addEventFilter(String filter) {
        this.eventFilters.add(filter);
    }
    
    /**
     * Remove event filter
     */
    public void removeEventFilter(String filter) {
        this.eventFilters.remove(filter);
    }
    
    /**
     * Check if event matches connection filters
     */
    public boolean matchesFilters(String eventData) {
        if (eventFilters.isEmpty()) {
            return true;
        }
        
        // Apply severity filter
        if (severityFilter != null && !eventData.contains(severityFilter)) {
            return false;
        }
        
        // Apply host filter
        if (hostFilter != null && !eventData.contains(hostFilter)) {
            return false;
        }
        
        // Apply method filter
        if (methodFilter != null && !eventData.contains(methodFilter)) {
            return false;
        }
        
        // Check custom filters
        for (String filter : eventFilters) {
            if (!eventData.contains(filter)) {
                return false;
            }
        }
        
        return true;
    }
    
    // Rate limiting methods
    
    /**
     * Check if connection can send a message (rate limiting)
     */
    public boolean canSendMessage() {
        long currentSec = System.currentTimeMillis() / 1000;
        
        if (currentSec != this.currentSecond) {
            // Reset counter for new second
            this.currentSecond = currentSec;
            messagesThisSecond.set(0);
        }
        
        return messagesThisSecond.incrementAndGet() <= maxMessagesPerSecond;
    }
    
    /**
     * Set rate limit for this connection
     */
    public void setRateLimit(int messagesPerSecond) {
        this.maxMessagesPerSecond = messagesPerSecond;
    }
    
    /**
     * Get current rate limit
     */
    public int getRateLimit() {
        return maxMessagesPerSecond;
    }
    
    // Replay buffer methods
    
    /**
     * Add event to replay buffer
     */
    public void addToReplayBuffer(String eventJson) {
        synchronized (replayLock) {
            replayBuffer.offer(eventJson);
            
            // Maintain buffer size limit
            while (replayBuffer.size() > replayBufferSize.get()) {
                replayBuffer.poll();
            }
        }
    }
    
    /**
     * Get replay buffer contents
     */
    public Queue<String> getReplayBuffer() {
        synchronized (replayLock) {
            return new LinkedList<>(replayBuffer);
        }
    }
    
    /**
     * Set replay buffer size
     */
    public void setReplayBufferSize(int size) {
        this.replayBufferSize.set(size);
        
        // Trim buffer if needed
        synchronized (replayLock) {
            while (replayBuffer.size() > size) {
                replayBuffer.poll();
            }
        }
    }
    
    /**
     * Clear replay buffer
     */
    public void clearReplayBuffer() {
        synchronized (replayLock) {
            replayBuffer.clear();
        }
    }
    
    // Compression and filtering setters/getters
    
    public boolean isCompressionEnabled() {
        return compressionEnabled;
    }
    
    public void setCompressionEnabled(boolean compressionEnabled) {
        this.compressionEnabled = compressionEnabled;
    }
    
    public String getSeverityFilter() {
        return severityFilter;
    }
    
    public void setSeverityFilter(String severityFilter) {
        this.severityFilter = severityFilter;
    }
    
    public String getHostFilter() {
        return hostFilter;
    }
    
    public void setHostFilter(String hostFilter) {
        this.hostFilter = hostFilter;
    }
    
    public String getMethodFilter() {
        return methodFilter;
    }
    
    public void setMethodFilter(String methodFilter) {
        this.methodFilter = methodFilter;
    }
    
    public Set<WebSocketEventType> getSubscribedEventTypes() {
        return subscribedEventTypes;
    }
    
    public boolean isSubscribedToAll() {
        return subscribeToAll;
    }
    
    public Set<String> getEventFilters() {
        return eventFilters;
    }
    
    @Override
    public String toString() {
        return String.format("WebSocketConnection{id='%s', session='%s', connected=%d, events=%s, filters=%d, rateLimit=%d}", 
                           connectionId, sessionTag, connectedAt, 
                           subscribeToAll ? "ALL" : subscribedEventTypes.size(), 
                           eventFilters.size(), maxMessagesPerSecond);
    }
} 