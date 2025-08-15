package com.belch.websocket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Coordinates event broadcasting for Phase 12 WebSocket streaming.
 * 
 * Integrates with existing systems to provide real-time event streaming:
 * - Traffic capture events
 * - Statistics updates
 * - Performance alerts
 * - Session changes
 */
public class EventBroadcaster {
    
    private static final Logger logger = LoggerFactory.getLogger(EventBroadcaster.class);
    
    private final WebSocketManager webSocketManager;
    private final AtomicLong eventCounter = new AtomicLong(0);
    
    // Event throttling to prevent spam
    private static final long MIN_STATS_INTERVAL_MS = 5000; // 5 seconds
    private volatile long lastStatsUpdate = 0;
    
    public EventBroadcaster(WebSocketManager webSocketManager) {
        this.webSocketManager = webSocketManager;
        logger.info("[*] Phase 12 Event Broadcaster initialized");
    }
    
    /**
     * Broadcast new traffic capture event.
     */
    public void broadcastTrafficCapture(Map<String, Object> trafficData, String sessionTag) {
        try {
            // Phase 12: Broadcast to all connected clients regardless of session tag
            Map<String, Object> eventData = new HashMap<>();
            eventData.put("id", trafficData.get("id"));
            eventData.put("method", trafficData.get("method"));
            eventData.put("url", trafficData.get("url"));
            eventData.put("host", trafficData.get("host"));
            eventData.put("status_code", trafficData.get("status_code"));
            eventData.put("timestamp", trafficData.get("timestamp"));
            eventData.put("tool_source", trafficData.get("tool_source"));
            
            // Add content length if available
            if (trafficData.containsKey("body_size")) {
                eventData.put("content_length", trafficData.get("body_size"));
            }
            
            WebSocketEvent event = WebSocketEvent.newTraffic(null, eventData);
            webSocketManager.broadcast(event);
            
            eventCounter.incrementAndGet();
            
        } catch (Exception e) {
            logger.error("[!] Failed to broadcast traffic capture event", e);
        }
    }
    
    /**
     * Broadcast traffic tagging event (Phase 10 integration).
     */
    public void broadcastTrafficTagged(long requestId, String tags, String sessionTag) {
        try {
            WebSocketEvent event = new WebSocketEvent(WebSocketEventType.TRAFFIC_TAGGED, sessionTag);
            event.addData("request_id", requestId);
            event.addData("tags", tags);
            event.addMetadata("action", "tagged");
            
            webSocketManager.broadcastToSession(event, sessionTag);
            eventCounter.incrementAndGet();
            
        } catch (Exception e) {
            logger.error("[!] Failed to broadcast traffic tagging event", e);
        }
    }
    
    /**
     * Broadcast traffic comment event (Phase 10 integration).
     */
    public void broadcastTrafficCommented(long requestId, String comment, String sessionTag) {
        try {
            WebSocketEvent event = new WebSocketEvent(WebSocketEventType.TRAFFIC_COMMENTED, sessionTag);
            event.addData("request_id", requestId);
            event.addData("comment", comment);
            event.addMetadata("action", "commented");
            
            webSocketManager.broadcastToSession(event, sessionTag);
            eventCounter.incrementAndGet();
            
        } catch (Exception e) {
            logger.error("[!] Failed to broadcast traffic comment event", e);
        }
    }
    
    /**
     * Broadcast replay started event (Phase 10 integration).
     */
    public void broadcastReplayStarted(java.util.List<Long> requestIds, String sessionTag) {
        try {
            WebSocketEvent event = new WebSocketEvent(WebSocketEventType.REPLAY_STARTED, sessionTag);
            event.addData("request_ids", requestIds);
            event.addData("count", requestIds.size());
            event.addMetadata("action", "replay_initiated");
            
            webSocketManager.broadcastToSession(event, sessionTag);
            eventCounter.incrementAndGet();
            
        } catch (Exception e) {
            logger.error("[!] Failed to broadcast replay started event", e);
        }
    }
    
    /**
     * Broadcast replay completed event.
     */
    public void broadcastReplayCompleted(java.util.List<Long> originalRequestIds, java.util.List<Long> newRequestIds, String sessionTag) {
        try {
            WebSocketEvent event = new WebSocketEvent(WebSocketEventType.REPLAY_COMPLETED, sessionTag);
            event.addData("original_request_ids", originalRequestIds);
            event.addData("new_request_ids", newRequestIds);
            event.addData("original_count", originalRequestIds.size());
            event.addData("replayed_count", newRequestIds.size());
            event.addMetadata("action", "replay_completed");
            
            webSocketManager.broadcastToSession(event, sessionTag);
            eventCounter.incrementAndGet();
            
        } catch (Exception e) {
            logger.error("[!] Failed to broadcast replay completed event", e);
        }
    }
    
    /**
     * Broadcast statistics update (throttled to prevent spam).
     */
    public void broadcastStatisticsUpdate(Map<String, Object> statsData, String sessionTag) {
        try {
            long currentTime = System.currentTimeMillis();
            if (currentTime - lastStatsUpdate < MIN_STATS_INTERVAL_MS) {
                return; // Throttle frequent updates
            }
            lastStatsUpdate = currentTime;
            
            WebSocketEvent event = WebSocketEvent.statsUpdate(sessionTag, statsData);
            webSocketManager.broadcastToSession(event, sessionTag);
            
            eventCounter.incrementAndGet();
            
        } catch (Exception e) {
            logger.error("[!] Failed to broadcast statistics update", e);
        }
    }
    
    /**
     * Broadcast session change event.
     */
    public void broadcastSessionChanged(String oldSessionTag, String newSessionTag) {
        try {
            WebSocketEvent event = new WebSocketEvent(WebSocketEventType.SESSION_CHANGED, newSessionTag);
            event.addData("old_session_tag", oldSessionTag);
            event.addData("new_session_tag", newSessionTag);
            event.addMetadata("action", "session_updated");
            
            // Broadcast to both old and new sessions
            webSocketManager.broadcastToSession(event, oldSessionTag);
            webSocketManager.broadcastToSession(event, newSessionTag);
            
            eventCounter.incrementAndGet();
            
        } catch (Exception e) {
            logger.error("[!] Failed to broadcast session change event", e);
        }
    }
    
    /**
     * Broadcast scanner issue found event.
     */
    public void broadcastScannerIssue(Map<String, Object> issueData, String sessionTag) {
        try {
            WebSocketEvent event = new WebSocketEvent(WebSocketEventType.SCANNER_ISSUE_FOUND, sessionTag);
            if (issueData != null) {
                event.getData().putAll(issueData);
            }
            event.addMetadata("category", "security");
            event.addMetadata("severity", issueData != null ? issueData.get("severity") : "unknown");
            
            webSocketManager.broadcastToSession(event, sessionTag);
            eventCounter.incrementAndGet();
            
        } catch (Exception e) {
            logger.error("[!] Failed to broadcast scanner issue event", e);
        }
    }
    
    /**
     * Broadcast performance alert.
     */
    public void broadcastPerformanceAlert(String alertType, Map<String, Object> alertData, String sessionTag) {
        try {
            WebSocketEvent event = new WebSocketEvent(WebSocketEventType.PERFORMANCE_ALERT, sessionTag);
            event.addData("alert_type", alertType);
            if (alertData != null) {
                event.getData().putAll(alertData);
            }
            event.addMetadata("category", "performance");
            event.addMetadata("priority", "high");
            
            webSocketManager.broadcastToSession(event, sessionTag);
            eventCounter.incrementAndGet();
            
        } catch (Exception e) {
            logger.error("[!] Failed to broadcast performance alert", e);
        }
    }
    
    /**
     * Broadcast memory warning.
     */
    public void broadcastMemoryWarning(long usedMemory, long maxMemory, double percentage, String sessionTag) {
        try {
            WebSocketEvent event = new WebSocketEvent(WebSocketEventType.MEMORY_WARNING, sessionTag);
            event.addData("used_memory_mb", usedMemory / (1024 * 1024));
            event.addData("max_memory_mb", maxMemory / (1024 * 1024));
            event.addData("usage_percentage", percentage);
            event.addData("threshold_exceeded", percentage > 80.0);
            event.addMetadata("category", "system");
            event.addMetadata("severity", percentage > 90.0 ? "critical" : "warning");
            
            webSocketManager.broadcast(event); // Broadcast to all connections
            eventCounter.incrementAndGet();
            
        } catch (Exception e) {
            logger.error("[!] Failed to broadcast memory warning", e);
        }
    }
    
    /**
     * Broadcast search query saved event (Phase 10 integration).
     */
    public void broadcastQuerySaved(String queryName, Map<String, Object> queryParams, String sessionTag) {
        try {
            WebSocketEvent event = new WebSocketEvent(WebSocketEventType.SEARCH_QUERY_SAVED, sessionTag);
            event.addData("query_name", queryName);
            event.addData("query_params", queryParams);
            event.addMetadata("action", "query_saved");
            
            webSocketManager.broadcastToSession(event, sessionTag);
            eventCounter.incrementAndGet();
            
        } catch (Exception e) {
            logger.error("[!] Failed to broadcast query saved event", e);
        }
    }
    
    /**
     * Broadcast system status change.
     */
    public void broadcastSystemStatus(String status, String message) {
        try {
            WebSocketEvent event = new WebSocketEvent(WebSocketEventType.SYSTEM_STATUS, null);
            event.addData("status", status);
            event.addData("message", message);
            event.addData("timestamp", System.currentTimeMillis());
            event.addMetadata("category", "system");
            
            webSocketManager.broadcast(event); // Broadcast to all connections
            eventCounter.incrementAndGet();
            
        } catch (Exception e) {
            logger.error("[!] Failed to broadcast system status", e);
        }
    }
    
    /**
     * Broadcast error event.
     */
    public void broadcastError(String errorMessage, String details, String sessionTag) {
        try {
            WebSocketEvent event = WebSocketEvent.error(sessionTag, errorMessage, details);
            webSocketManager.broadcastToSession(event, sessionTag);
            eventCounter.incrementAndGet();
            
        } catch (Exception e) {
            logger.error("[!] Failed to broadcast error event", e);
        }
    }
    
    /**
     * Get event broadcasting statistics.
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> wsStats = webSocketManager.getStatistics();
        Map<String, Object> stats = new HashMap<>(wsStats);
        stats.put("events_broadcasted", eventCounter.get());
        stats.put("last_stats_update", lastStatsUpdate);
        stats.put("min_stats_interval_ms", MIN_STATS_INTERVAL_MS);
        return stats;
    }
    
    /**
     * Async broadcast for performance-critical operations.
     */
    public CompletableFuture<Void> broadcastAsync(WebSocketEvent event, String sessionTag) {
        return CompletableFuture.runAsync(() -> {
            webSocketManager.broadcastToSession(event, sessionTag);
            eventCounter.incrementAndGet();
        });
    }
    
    /**
     * Broadcast collaborator interaction event (Phase 2 Task 11).
     */
    public void broadcastCollaboratorInteraction(Map<String, Object> interactionData, String sessionTag) {
        try {
            WebSocketEvent event = new WebSocketEvent(WebSocketEventType.COLLABORATOR_INTERACTION, sessionTag);
            if (interactionData != null) {
                event.getData().putAll(interactionData);
            }
            event.addMetadata("category", "collaborator");
            event.addMetadata("source", "interaction_detected");
            
            webSocketManager.broadcastToSession(event, sessionTag);
            eventCounter.incrementAndGet();
            
        } catch (Exception e) {
            logger.error("[!] Failed to broadcast collaborator interaction event", e);
        }
    }
    
    /**
     * Broadcast collaborator alert event (Phase 2 Task 11).
     */
    public void broadcastAlert(Map<String, Object> alertData, String sessionTag) {
        try {
            WebSocketEvent event = new WebSocketEvent(WebSocketEventType.COLLABORATOR_ALERT, sessionTag);
            if (alertData != null) {
                event.getData().putAll(alertData);
            }
            event.addMetadata("category", "security_alert");
            event.addMetadata("priority", "high");
            
            // Broadcast alerts to all connections for visibility
            webSocketManager.broadcast(event);
            eventCounter.incrementAndGet();
            
        } catch (Exception e) {
            logger.error("[!] Failed to broadcast collaborator alert event", e);
        }
    }
    
    /**
     * Broadcast queue metrics event (Phase 2 Task 10).
     */
    public void broadcastQueueMetrics(Map<String, Object> metricsData, String sessionTag) {
        try {
            long currentTime = System.currentTimeMillis();
            if (currentTime - lastStatsUpdate < MIN_STATS_INTERVAL_MS) {
                return; // Throttle frequent updates
            }
            lastStatsUpdate = currentTime;
            
            WebSocketEvent event = new WebSocketEvent(WebSocketEventType.QUEUE_METRICS, sessionTag);
            if (metricsData != null) {
                event.getData().putAll(metricsData);
            }
            event.addMetadata("category", "performance");
            event.addMetadata("source", "enhanced_traffic_queue");
            
            webSocketManager.broadcastToSession(event, sessionTag);
            eventCounter.incrementAndGet();
            
        } catch (Exception e) {
            logger.error("[!] Failed to broadcast queue metrics event", e);
        }
    }

    /**
     * Shutdown the event broadcaster.
     */
    public void shutdown() {
        logger.info("[*] Event Broadcaster shutting down... (events broadcasted: {})", eventCounter.get());
    }
} 