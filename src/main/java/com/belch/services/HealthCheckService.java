package com.belch.services;

import com.belch.database.DatabaseService;
import com.belch.database.TrafficQueue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Comprehensive health check service for monitoring system components.
 * Performs deep health checks on database integrity, queue health, and service availability.
 */
public class HealthCheckService {
    
    private static final Logger logger = LoggerFactory.getLogger(HealthCheckService.class);
    
    private final DatabaseService databaseService;
    private final TrafficQueue trafficQueue;
    
    // Health check timeouts
    private static final Duration DATABASE_CHECK_TIMEOUT = Duration.ofSeconds(5);
    private static final Duration QUEUE_CHECK_TIMEOUT = Duration.ofSeconds(3);
    private static final Duration INTEGRITY_CHECK_TIMEOUT = Duration.ofSeconds(10);
    
    public HealthCheckService(DatabaseService databaseService, TrafficQueue trafficQueue) {
        this.databaseService = databaseService;
        this.trafficQueue = trafficQueue;
    }
    
    /**
     * Health check status
     */
    public enum HealthStatus {
        HEALTHY, DEGRADED, UNHEALTHY, UNKNOWN
    }
    
    /**
     * Health check result
     */
    public static class HealthCheckResult {
        private final String component;
        private final HealthStatus status;
        private final String message;
        private final long responseTimeMs;
        private final Map<String, Object> details;
        private final Instant timestamp;
        
        public HealthCheckResult(String component, HealthStatus status, String message, 
                               long responseTimeMs, Map<String, Object> details) {
            this.component = component;
            this.status = status;
            this.message = message;
            this.responseTimeMs = responseTimeMs;
            this.details = details != null ? new HashMap<>(details) : new HashMap<>();
            this.timestamp = Instant.now();
        }
        
        // Getters
        public String getComponent() { return component; }
        public HealthStatus getStatus() { return status; }
        public String getMessage() { return message; }
        public long getResponseTimeMs() { return responseTimeMs; }
        public Map<String, Object> getDetails() { return details; }
        public Instant getTimestamp() { return timestamp; }
        
        public Map<String, Object> toMap() {
            Map<String, Object> result = new HashMap<>();
            result.put("component", component);
            result.put("status", status.toString().toLowerCase());
            result.put("message", message);
            result.put("response_time_ms", responseTimeMs);
            result.put("timestamp", timestamp.toEpochMilli());
            result.put("details", details);
            return result;
        }
    }
    
    /**
     * Perform comprehensive health check of all components
     */
    public Map<String, Object> performHealthCheck() {
        Instant startTime = Instant.now();
        List<HealthCheckResult> results = new ArrayList<>();
        
        // Run health checks in parallel
        CompletableFuture<HealthCheckResult> databaseCheck = CompletableFuture.supplyAsync(this::checkDatabaseHealth);
        CompletableFuture<HealthCheckResult> queueCheck = CompletableFuture.supplyAsync(this::checkQueueHealth);
        CompletableFuture<HealthCheckResult> integrityCheck = CompletableFuture.supplyAsync(this::checkDatabaseIntegrity);
        
        try {
            // Wait for all checks to complete
            results.add(databaseCheck.get(DATABASE_CHECK_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS));
            results.add(queueCheck.get(QUEUE_CHECK_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS));
            results.add(integrityCheck.get(INTEGRITY_CHECK_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS));
            
        } catch (Exception e) {
            logger.error("Health check failed", e);
            results.add(new HealthCheckResult("system", HealthStatus.UNHEALTHY, 
                "Health check execution failed: " + e.getMessage(), 0, null));
        }
        
        // Calculate overall health
        HealthStatus overallStatus = calculateOverallHealth(results);
        long totalTime = Duration.between(startTime, Instant.now()).toMillis();
        
        // Build response
        Map<String, Object> healthReport = new HashMap<>();
        healthReport.put("overall_status", overallStatus.toString().toLowerCase());
        healthReport.put("total_check_time_ms", totalTime);
        healthReport.put("timestamp", Instant.now().toEpochMilli());
        healthReport.put("checks", results.stream().map(HealthCheckResult::toMap).toList());
        
        // Add summary stats
        Map<String, Long> statusCounts = new HashMap<>();
        results.forEach(result -> {
            String status = result.getStatus().toString().toLowerCase();
            statusCounts.put(status, statusCounts.getOrDefault(status, 0L) + 1);
        });
        healthReport.put("status_summary", statusCounts);
        
        logger.debug("Health check completed in {}ms with overall status: {}", totalTime, overallStatus);
        return healthReport;
    }
    
    /**
     * Check database health and connectivity
     */
    public HealthCheckResult checkDatabaseHealth() {
        Instant startTime = Instant.now();
        Map<String, Object> details = new HashMap<>();
        
        try {
            if (!databaseService.isInitialized()) {
                return new HealthCheckResult("database", HealthStatus.UNHEALTHY, 
                    "Database service not initialized", 0, details);
            }
            
            // Test basic connectivity
            try (Connection conn = databaseService.getConnection()) {
                if (conn == null) {
                    return new HealthCheckResult("database", HealthStatus.UNHEALTHY, 
                        "Cannot obtain database connection", 0, details);
                }
                
                // Test query execution
                try (PreparedStatement stmt = conn.prepareStatement("SELECT 1")) {
                    try (ResultSet rs = stmt.executeQuery()) {
                        if (rs.next() && rs.getInt(1) == 1) {
                            details.put("connection_test", "passed");
                        } else {
                            return new HealthCheckResult("database", HealthStatus.DEGRADED, 
                                "Database query returned unexpected result", 
                                Duration.between(startTime, Instant.now()).toMillis(), details);
                        }
                    }
                }
                
                // Check database metadata
                details.put("database_product", conn.getMetaData().getDatabaseProductName());
                details.put("database_version", conn.getMetaData().getDatabaseProductVersion());
                details.put("autocommit", conn.getAutoCommit());
                
                long responseTime = Duration.between(startTime, Instant.now()).toMillis();
                
                // Determine status based on response time
                HealthStatus status = responseTime < 100 ? HealthStatus.HEALTHY : 
                                    responseTime < 1000 ? HealthStatus.DEGRADED : HealthStatus.UNHEALTHY;
                
                details.put("response_time_category", responseTime < 100 ? "fast" : 
                                                     responseTime < 1000 ? "slow" : "very_slow");
                
                return new HealthCheckResult("database", status, 
                    "Database connection healthy", responseTime, details);
            }
            
        } catch (SQLException e) {
            long responseTime = Duration.between(startTime, Instant.now()).toMillis();
            details.put("error_type", e.getClass().getSimpleName());
            details.put("sql_state", e.getSQLState());
            details.put("error_code", e.getErrorCode());
            
            return new HealthCheckResult("database", HealthStatus.UNHEALTHY, 
                "Database connection failed: " + e.getMessage(), responseTime, details);
        } catch (Exception e) {
            long responseTime = Duration.between(startTime, Instant.now()).toMillis();
            details.put("error_type", e.getClass().getSimpleName());
            
            return new HealthCheckResult("database", HealthStatus.UNHEALTHY, 
                "Database health check failed: " + e.getMessage(), responseTime, details);
        }
    }
    
    /**
     * Check queue health and performance
     */
    public HealthCheckResult checkQueueHealth() {
        Instant startTime = Instant.now();
        Map<String, Object> details = new HashMap<>();
        
        try {
            if (trafficQueue == null) {
                return new HealthCheckResult("queue", HealthStatus.UNHEALTHY, 
                    "Traffic queue not available", 0, details);
            }
            
            // Get queue metrics
            Map<String, Object> queueMetrics = trafficQueue.getMetrics();
            Map<String, Object> queueHealthStatus = trafficQueue.getHealthStatus();
            boolean isHealthy = trafficQueue.isHealthy();
            
            details.putAll(queueMetrics);
            details.put("queue_health_status", queueHealthStatus);
            details.put("is_healthy", isHealthy);
            
            long responseTime = Duration.between(startTime, Instant.now()).toMillis();
            
            // Determine health status based on queue health
            HealthStatus status;
            String message;
            
            if (!isHealthy) {
                status = HealthStatus.UNHEALTHY;
                message = "Queue reported unhealthy status";
            } else {
                // Extract queue size from metrics if available
                Object queueSizeObj = queueMetrics.get("queue_size");
                if (queueSizeObj instanceof Number) {
                    int queueSize = ((Number) queueSizeObj).intValue();
                    if (queueSize > 10000) {
                        status = HealthStatus.DEGRADED;
                        message = "Queue size high (" + queueSize + ")";
                    } else {
                        status = HealthStatus.HEALTHY;
                        message = "Queue operating normally";
                    }
                } else {
                    status = HealthStatus.HEALTHY;
                    message = "Queue health verified";
                }
            }
            
            return new HealthCheckResult("queue", status, message, responseTime, details);
            
        } catch (Exception e) {
            long responseTime = Duration.between(startTime, Instant.now()).toMillis();
            details.put("error_type", e.getClass().getSimpleName());
            
            return new HealthCheckResult("queue", HealthStatus.UNHEALTHY, 
                "Queue health check failed: " + e.getMessage(), responseTime, details);
        }
    }
    
    /**
     * Check database integrity
     */
    public HealthCheckResult checkDatabaseIntegrity() {
        Instant startTime = Instant.now();
        Map<String, Object> details = new HashMap<>();
        
        try {
            if (!databaseService.isInitialized()) {
                return new HealthCheckResult("database_integrity", HealthStatus.UNHEALTHY, 
                    "Database not available for integrity check", 0, details);
            }
            
            try (Connection conn = databaseService.getConnection()) {
                
                // Check table existence
                int tableCount = checkRequiredTables(conn, details);
                details.put("tables_found", tableCount);
                
                // Check data consistency
                Map<String, Long> recordCounts = getRecordCounts(conn);
                details.put("record_counts", recordCounts);
                
                // Check for orphaned records (basic integrity)
                List<String> integrityIssues = checkDataIntegrity(conn);
                if (!integrityIssues.isEmpty()) {
                    details.put("integrity_issues", integrityIssues);
                }
                
                long responseTime = Duration.between(startTime, Instant.now()).toMillis();
                
                // Determine status
                HealthStatus status;
                String message;
                
                if (tableCount < 5) { // Expecting at least 5 core tables
                    status = HealthStatus.UNHEALTHY;
                    message = "Missing required database tables";
                } else if (!integrityIssues.isEmpty()) {
                    status = HealthStatus.DEGRADED;
                    message = "Data integrity issues detected: " + integrityIssues.size() + " issues";
                } else {
                    status = HealthStatus.HEALTHY;
                    message = "Database integrity verified";
                }
                
                return new HealthCheckResult("database_integrity", status, message, responseTime, details);
            }
            
        } catch (SQLException e) {
            long responseTime = Duration.between(startTime, Instant.now()).toMillis();
            details.put("error_type", e.getClass().getSimpleName());
            details.put("sql_state", e.getSQLState());
            
            return new HealthCheckResult("database_integrity", HealthStatus.UNHEALTHY, 
                "Database integrity check failed: " + e.getMessage(), responseTime, details);
        } catch (Exception e) {
            long responseTime = Duration.between(startTime, Instant.now()).toMillis();
            details.put("error_type", e.getClass().getSimpleName());
            
            return new HealthCheckResult("database_integrity", HealthStatus.UNHEALTHY, 
                "Integrity check failed: " + e.getMessage(), responseTime, details);
        }
    }
    
    /**
     * Check if required tables exist
     */
    private int checkRequiredTables(Connection conn, Map<String, Object> details) throws SQLException {
        String[] requiredTables = {"traffic_meta", "traffic_requests", "traffic_responses", "scan_tasks", "scan_metrics"};
        int foundCount = 0;
        List<String> missingTables = new ArrayList<>();
        
        for (String table : requiredTables) {
            try (PreparedStatement stmt = conn.prepareStatement(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?")) {
                stmt.setString(1, table);
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next() && rs.getInt(1) > 0) {
                        foundCount++;
                    } else {
                        missingTables.add(table);
                    }
                }
            }
        }
        
        if (!missingTables.isEmpty()) {
            details.put("missing_tables", missingTables);
        }
        
        return foundCount;
    }
    
    /**
     * Get record counts for main tables
     */
    private Map<String, Long> getRecordCounts(Connection conn) throws SQLException {
        Map<String, Long> counts = new HashMap<>();
        String[] tables = {"traffic_meta", "scan_tasks", "scan_metrics"};
        
        for (String table : tables) {
            try (PreparedStatement stmt = conn.prepareStatement("SELECT COUNT(*) FROM " + table)) {
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        counts.put(table, rs.getLong(1));
                    }
                }
            } catch (SQLException e) {
                // Table might not exist
                counts.put(table, -1L);
            }
        }
        
        return counts;
    }
    
    /**
     * Check basic data integrity
     */
    private List<String> checkDataIntegrity(Connection conn) {
        List<String> issues = new ArrayList<>();
        
        try {
            // Check for orphaned scan metrics (scan_metrics without corresponding scan_tasks)
            try (PreparedStatement stmt = conn.prepareStatement(
                "SELECT COUNT(*) FROM scan_metrics WHERE scan_task_id NOT IN (SELECT id FROM scan_tasks)")) {
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next() && rs.getLong(1) > 0) {
                        issues.add("Orphaned scan metrics found: " + rs.getLong(1) + " records");
                    }
                }
            }
            
            // Add more integrity checks as needed
            
        } catch (SQLException e) {
            logger.debug("Could not perform some integrity checks: {}", e.getMessage());
        }
        
        return issues;
    }
    
    /**
     * Calculate overall health status from individual check results
     */
    private HealthStatus calculateOverallHealth(List<HealthCheckResult> results) {
        boolean hasUnhealthy = results.stream().anyMatch(r -> r.getStatus() == HealthStatus.UNHEALTHY);
        boolean hasDegraded = results.stream().anyMatch(r -> r.getStatus() == HealthStatus.DEGRADED);
        
        if (hasUnhealthy) {
            return HealthStatus.UNHEALTHY;
        } else if (hasDegraded) {
            return HealthStatus.DEGRADED;
        } else {
            return HealthStatus.HEALTHY;
        }
    }
}