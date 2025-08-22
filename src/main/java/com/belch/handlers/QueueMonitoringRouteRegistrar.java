package com.belch.handlers;

import com.belch.database.EnhancedTrafficQueue;
import com.belch.services.QueueMetricsCollectionService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.Javalin;
import io.javalin.http.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.List;
import java.util.ArrayList;

/**
 * REST API endpoints for real-time queue monitoring and management.
 * 
 * Provides comprehensive monitoring capabilities for the enhanced traffic queue
 * including metrics, health status, and administrative controls.
 */
public class QueueMonitoringRouteRegistrar {
    
    private static final Logger logger = LoggerFactory.getLogger(QueueMonitoringRouteRegistrar.class);
    
    private final EnhancedTrafficQueue trafficQueue;
    private final QueueMetricsCollectionService metricsCollectionService;
    private final ObjectMapper objectMapper;
    
    public QueueMonitoringRouteRegistrar(EnhancedTrafficQueue trafficQueue, 
                                       QueueMetricsCollectionService metricsCollectionService) {
        this.trafficQueue = trafficQueue;
        this.metricsCollectionService = metricsCollectionService;
        this.objectMapper = new ObjectMapper();
    }
    
    /**
     * Register all queue monitoring routes
     */
    public void registerRoutes(Javalin app) {
        
        // Queue metrics and status
        app.get("/queue/metrics", this::getQueueMetrics);
        app.get("/queue/health", this::getQueueHealth);
        
        
        // Historical metrics (if available)
        app.get("/queue/metrics/history", this::getMetricsHistory);
        
        logger.info("Queue monitoring routes registered");
    }
    
    /**
     * GET /queue/metrics - Get comprehensive queue metrics
     */
    private void getQueueMetrics(Context ctx) {
        try {
            Map<String, Object> metrics = trafficQueue.getEnhancedMetrics();
            
            ctx.status(200)
               .contentType("application/json")
               .result(objectMapper.writeValueAsString(Map.of(
                   "status", "success",
                   "metrics", metrics,
                   "timestamp", System.currentTimeMillis()
               )));
               
        } catch (Exception e) {
            logger.error("Error getting queue metrics", e);
            ctx.status(500)
               .contentType("application/json")
               .result("{\"status\":\"error\",\"message\":\"Failed to get queue metrics\"}");
        }
    }
    
    /**
     * GET /queue/health - Get queue health status
     */
    private void getQueueHealth(Context ctx) {
        try {
            Map<String, Object> health = trafficQueue.getHealthStatus();
            boolean isHealthy = (Boolean) health.get("healthy");
            
            ctx.status(isHealthy ? 200 : 503)
               .contentType("application/json")
               .result(objectMapper.writeValueAsString(Map.of(
                   "status", isHealthy ? "healthy" : "unhealthy",
                   "health", health,
                   "timestamp", System.currentTimeMillis()
               )));
               
        } catch (Exception e) {
            logger.error("Error getting queue health", e);
            ctx.status(500)
               .contentType("application/json")
               .result("{\"status\":\"error\",\"message\":\"Failed to get queue health\"}");
        }
    }
    
    
    
    /**
     * GET /queue/dead-letter - Get dead letter queue status
     */
    private void getDeadLetterQueueStatus(Context ctx) {
        try {
            Map<String, Object> metrics = trafficQueue.getEnhancedMetrics();
            
            Map<String, Object> deadLetter = Map.of(
                "size", metrics.get("dead_letter_queue_size"),
                "capacity", metrics.get("dead_letter_capacity"),
                "utilization_percent", metrics.get("dead_letter_utilization_percent"),
                "total_dead_lettered", metrics.get("total_dead_lettered"),
                "total_retries", metrics.get("total_retries"),
                "retry_success_rate", calculateRetrySuccessRate(metrics),
                "configuration", Map.of(
                    "max_retry_attempts", 3,
                    "retry_delay_ms", 5000
                )
            );
            
            ctx.status(200)
               .contentType("application/json")
               .result(objectMapper.writeValueAsString(Map.of(
                   "status", "success",
                   "dead_letter_queue", deadLetter,
                   "timestamp", System.currentTimeMillis()
               )));
               
        } catch (Exception e) {
            logger.error("Error getting dead letter queue status", e);
            ctx.status(500)
               .contentType("application/json")
               .result("{\"status\":\"error\",\"message\":\"Failed to get dead letter queue status\"}");
        }
    }
    
    /**
     * POST /queue/reset-circuit-breaker - Reset circuit breaker (admin function)
     */
    private void resetCircuitBreaker(Context ctx) {
        try {
            // This would require adding a method to EnhancedTrafficQueue
            // For now, we'll return a response indicating the action
            
            ctx.status(200)
               .contentType("application/json")
               .result(objectMapper.writeValueAsString(Map.of(
                   "status", "success",
                   "message", "Circuit breaker reset requested",
                   "note", "Circuit breaker will automatically reset after timeout",
                   "timestamp", System.currentTimeMillis()
               )));
               
        } catch (Exception e) {
            logger.error("Error resetting circuit breaker", e);
            ctx.status(500)
               .contentType("application/json")
               .result("{\"status\":\"error\",\"message\":\"Failed to reset circuit breaker\"}");
        }
    }
    
    /**
     * POST /queue/clear-dead-letter - Clear dead letter queue (admin function)
     */
    private void clearDeadLetterQueue(Context ctx) {
        try {
            // This would require adding a method to EnhancedTrafficQueue
            
            ctx.status(200)
               .contentType("application/json")
               .result(objectMapper.writeValueAsString(Map.of(
                   "status", "success",
                   "message", "Dead letter queue clear requested",
                   "warning", "This will permanently discard failed items",
                   "timestamp", System.currentTimeMillis()
               )));
               
        } catch (Exception e) {
            logger.error("Error clearing dead letter queue", e);
            ctx.status(500)
               .contentType("application/json")
               .result("{\"status\":\"error\",\"message\":\"Failed to clear dead letter queue\"}");
        }
    }
    
    /**
     * GET /queue/priority-distribution - Get priority distribution of queued items
     */
    private void getPriorityDistribution(Context ctx) {
        try {
            // This would require enhancing EnhancedTrafficQueue to track priority distribution
            
            Map<String, Object> distribution = Map.of(
                "critical", 0,
                "high", 0,
                "normal", 0,
                "low", 0,
                "bulk", 0,
                "note", "Priority distribution tracking not yet implemented"
            );
            
            ctx.status(200)
               .contentType("application/json")
               .result(objectMapper.writeValueAsString(Map.of(
                   "status", "success",
                   "priority_distribution", distribution,
                   "timestamp", System.currentTimeMillis()
               )));
               
        } catch (Exception e) {
            logger.error("Error getting priority distribution", e);
            ctx.status(500)
               .contentType("application/json")
               .result("{\"status\":\"error\",\"message\":\"Failed to get priority distribution\"}");
        }
    }
    
    /**
     * GET /queue/metrics/history - Get historical metrics with real data
     */
    private void getMetricsHistory(Context ctx) {
        try {
            String timeframe = ctx.queryParam("timeframe"); // e.g., "1h", "24h", "7d"
            String granularity = ctx.queryParam("granularity"); // e.g., "1m", "5m", "1h"
            
            // Set defaults if not provided
            if (timeframe == null) timeframe = "1h";
            if (granularity == null) granularity = "5m";
            
            // Get historical metrics from the collection service
            Map<String, Object> historicalData = metricsCollectionService.getHistoricalMetrics(timeframe, granularity);
            
            // Add collection status information
            Map<String, Object> collectionStatus = metricsCollectionService.getCollectionStatus();
            
            ctx.status(200)
               .contentType("application/json")
               .result(objectMapper.writeValueAsString(Map.of(
                   "status", "success",
                   "history", historicalData,
                   "collection_status", collectionStatus,
                   "timestamp", System.currentTimeMillis(),
                   "available_granularities", List.of("1m", "5m", "15m", "1h", "1d"),
                   "supported_timeframes", List.of("5m", "15m", "30m", "1h", "2h", "6h", "12h", "24h", "2d", "7d", "30d")
               )));
               
        } catch (Exception e) {
            logger.error("Error getting metrics history", e);
            ctx.status(500)
               .contentType("application/json")
               .result("{\"status\":\"error\",\"message\":\"Failed to get metrics history\"}");
        }
    }
    
    // Helper methods for calculations
    
    
    private double calculateRetrySuccessRate(Map<String, Object> metrics) {
        try {
            long totalRetries = ((Number) metrics.get("total_retries")).longValue();
            long totalDeadLettered = ((Number) metrics.get("total_dead_lettered")).longValue();
            
            if (totalDeadLettered == 0) return 100.0;
            return (totalRetries * 100.0) / (totalRetries + totalDeadLettered);
            
        } catch (Exception e) {
            return 0.0;
        }
    }
    
    private List<String> generateBackpressureRecommendations(String level, double utilization) {
        List<String> recommendations = new ArrayList<>();
        
        switch (level) {
            case "CRITICAL":
                recommendations.add("Queue is under critical pressure - only high priority items are being accepted");
                recommendations.add("Consider scaling database performance or increasing queue capacity");
                recommendations.add("Review and optimize slow database queries");
                break;
                
            case "HIGH":
                recommendations.add("Queue pressure is high - low priority items may be dropped");
                recommendations.add("Monitor database performance and consider optimization");
                recommendations.add("Consider implementing request throttling at the source");
                break;
                
            case "CIRCUIT_OPEN":
                recommendations.add("Circuit breaker is open due to consecutive failures");
                recommendations.add("Check database connectivity and performance");
                recommendations.add("Review error logs for underlying issues");
                break;
                
            default:
                if (utilization > 50) {
                    recommendations.add("Queue utilization is moderate - monitor for increases");
                } else {
                    recommendations.add("Queue is operating normally");
                }
                break;
        }
        
        return recommendations;
    }
}