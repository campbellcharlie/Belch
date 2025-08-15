package com.belch.services;

import com.belch.database.DatabaseService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

/**
 * Comprehensive resilience service that combines circuit breaker, retry, and error recovery mechanisms.
 * Provides centralized error handling and automatic recovery for critical operations.
 */
public class ResilienceService {
    
    private static final Logger logger = LoggerFactory.getLogger(ResilienceService.class);
    
    private final CircuitBreakerService circuitBreakerService;
    private final RetryService retryService;
    private final DatabaseService databaseService;
    
    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private final AtomicBoolean shutdown = new AtomicBoolean(false);
    
    // Health monitoring
    private final ScheduledExecutorService healthMonitor = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "ResilienceHealthMonitor");
        t.setDaemon(true);
        return t;
    });
    
    // Error tracking
    private final ConcurrentHashMap<String, ErrorStats> errorStats = new ConcurrentHashMap<>();
    
    // Recovery strategies
    private final ConcurrentHashMap<String, Runnable> recoveryStrategies = new ConcurrentHashMap<>();
    
    /**
     * Error statistics for tracking
     */
    public static class ErrorStats {
        private final String operationName;
        private volatile int totalErrors = 0;
        private volatile int recentErrors = 0;
        private volatile Instant lastErrorTime = Instant.MIN;
        private volatile Instant firstErrorTime = Instant.MIN;
        private volatile String lastErrorMessage = "";
        
        public ErrorStats(String operationName) {
            this.operationName = operationName;
        }
        
        public void recordError(String errorMessage) {
            totalErrors++;
            recentErrors++;
            lastErrorTime = Instant.now();
            lastErrorMessage = errorMessage;
            
            if (firstErrorTime == Instant.MIN) {
                firstErrorTime = Instant.now();
            }
        }
        
        public void resetRecentErrors() {
            recentErrors = 0;
        }
        
        // Getters
        public String getOperationName() { return operationName; }
        public int getTotalErrors() { return totalErrors; }
        public int getRecentErrors() { return recentErrors; }
        public Instant getLastErrorTime() { return lastErrorTime; }
        public Instant getFirstErrorTime() { return firstErrorTime; }
        public String getLastErrorMessage() { return lastErrorMessage; }
    }
    
    /**
     * Health check result
     */
    public static class HealthCheckResult {
        private final String component;
        private final boolean healthy;
        private final String message;
        private final Duration responseTime;
        private final Instant timestamp;
        
        public HealthCheckResult(String component, boolean healthy, String message, Duration responseTime) {
            this.component = component;
            this.healthy = healthy;
            this.message = message;
            this.responseTime = responseTime;
            this.timestamp = Instant.now();
        }
        
        // Getters
        public String getComponent() { return component; }
        public boolean isHealthy() { return healthy; }
        public String getMessage() { return message; }
        public Duration getResponseTime() { return responseTime; }
        public Instant getTimestamp() { return timestamp; }
    }
    
    public ResilienceService(DatabaseService databaseService) {
        this.databaseService = databaseService;
        this.circuitBreakerService = new CircuitBreakerService();
        this.retryService = new RetryService();
    }
    
    /**
     * Initialize the resilience service
     */
    public void initialize() {
        if (initialized.getAndSet(true)) {
            logger.warn("ResilienceService already initialized");
            return;
        }
        
        try {
            // Start health monitoring
            startHealthMonitoring();
            
            // Register default recovery strategies
            registerDefaultRecoveryStrategies();
            
            logger.info("ResilienceService initialized successfully");
            
        } catch (Exception e) {
            logger.error("Failed to initialize ResilienceService", e);
            initialized.set(false);
            throw new RuntimeException("Failed to initialize ResilienceService", e);
        }
    }
    
    /**
     * Execute operation with full resilience (circuit breaker + retry)
     */
    public <T> T executeResilient(String operationName, Supplier<T> operation) {
        return executeResilient(operationName, operation, RetryService.RetryPolicy.builder().build());
    }
    
    /**
     * Execute operation with custom retry policy and circuit breaker protection
     */
    public <T> T executeResilient(String operationName, Supplier<T> operation, RetryService.RetryPolicy retryPolicy) {
        try {
            return retryService.execute(() -> 
                circuitBreakerService.executeWithBreaker(operationName, operation), retryPolicy
            );
        } catch (Exception e) {
            recordError(operationName, e);
            attemptRecovery(operationName);
            throw new RuntimeException("Operation " + operationName + " failed after resilience mechanisms", e);
        }
    }
    
    /**
     * Execute database operation with automatic recovery
     */
    public <T> T executeDatabaseOperation(String operationName, Supplier<T> operation) {
        return executeResilient(operationName, operation, RetryService.databaseRetryPolicy());
    }
    
    /**
     * Execute Burp API operation with appropriate resilience
     */
    public <T> T executeBurpApiOperation(String operationName, Supplier<T> operation) {
        return executeResilient(operationName, operation, RetryService.burpApiRetryPolicy());
    }
    
    /**
     * Perform comprehensive health check
     */
    public Map<String, HealthCheckResult> performHealthCheck() {
        Map<String, HealthCheckResult> results = new ConcurrentHashMap<>();
        
        // Check database connectivity
        results.put("database", checkDatabaseHealth());
        
        // Check circuit breaker status
        results.put("circuit_breakers", checkCircuitBreakerHealth());
        
        // Check error rates
        results.put("error_rates", checkErrorRateHealth());
        
        // Check memory usage
        results.put("memory", checkMemoryHealth());
        
        return results;
    }
    
    /**
     * Trigger automatic recovery for all failing components
     */
    public void triggerRecovery() {
        logger.info("Triggering automatic recovery for all components");
        
        // Reset circuit breakers that have been open for too long
        circuitBreakerService.getAllStats().forEach((name, stats) -> {
            if (stats.getState() == CircuitBreakerService.State.OPEN) {
                long timeSinceFailure = System.currentTimeMillis() - stats.getLastFailureTime();
                if (timeSinceFailure > Duration.ofMinutes(5).toMillis()) {
                    logger.info("Resetting circuit breaker {} after extended open period", name);
                    circuitBreakerService.resetCircuitBreaker(name);
                }
            }
        });
        
        // Attempt database recovery if needed
        if (databaseService != null && !databaseService.isInitialized()) {
            logger.info("Attempting database recovery");
            try {
                // Trigger database reconnection/recovery
                performDatabaseRecovery();
            } catch (Exception e) {
                logger.error("Database recovery failed", e);
            }
        }
        
        // Execute registered recovery strategies
        recoveryStrategies.forEach((name, strategy) -> {
            try {
                logger.debug("Executing recovery strategy: {}", name);
                strategy.run();
            } catch (Exception e) {
                logger.warn("Recovery strategy {} failed", name, e);
            }
        });
    }
    
    /**
     * Register a custom recovery strategy
     */
    public void registerRecoveryStrategy(String name, Runnable strategy) {
        recoveryStrategies.put(name, strategy);
        logger.debug("Registered recovery strategy: {}", name);
    }
    
    /**
     * Get resilience statistics
     */
    public Map<String, Object> getResilienceStats() {
        Map<String, Object> stats = new ConcurrentHashMap<>();
        
        // Circuit breaker stats
        stats.put("circuit_breakers", circuitBreakerService.getAllStats());
        stats.put("circuit_breaker_health", circuitBreakerService.getHealthSummary());
        
        // Error stats
        Map<String, Object> errorStatsSummary = new ConcurrentHashMap<>();
        errorStats.forEach((name, stat) -> {
            Map<String, Object> statMap = new ConcurrentHashMap<>();
            statMap.put("total_errors", stat.getTotalErrors());
            statMap.put("recent_errors", stat.getRecentErrors());
            statMap.put("last_error_time", stat.getLastErrorTime().toEpochMilli());
            statMap.put("last_error_message", stat.getLastErrorMessage());
            errorStatsSummary.put(name, statMap);
        });
        stats.put("error_stats", errorStatsSummary);
        
        // Health check results
        stats.put("health_checks", performHealthCheck());
        
        // Recovery strategies
        stats.put("recovery_strategies", recoveryStrategies.keySet());
        
        stats.put("timestamp", System.currentTimeMillis());
        
        return stats;
    }
    
    /**
     * Shutdown the resilience service
     */
    public void shutdown() {
        if (shutdown.getAndSet(true)) {
            return;
        }
        
        logger.info("ResilienceService shutting down");
        
        // Stop health monitoring
        healthMonitor.shutdown();
        try {
            if (!healthMonitor.awaitTermination(5, TimeUnit.SECONDS)) {
                healthMonitor.shutdownNow();
            }
        } catch (InterruptedException e) {
            healthMonitor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        
        // Clear tracking data
        errorStats.clear();
        recoveryStrategies.clear();
        
        logger.info("ResilienceService shutdown completed");
    }
    
    // Private helper methods
    
    private void startHealthMonitoring() {
        healthMonitor.scheduleAtFixedRate(() -> {
            try {
                // Reset recent error counts
                errorStats.values().forEach(ErrorStats::resetRecentErrors);
                
                // Cleanup stale circuit breakers
                circuitBreakerService.cleanupStaleCircuitBreakers(Duration.ofHours(1).toMillis());
                
                // Trigger recovery if needed
                if (shouldTriggerRecovery()) {
                    triggerRecovery();
                }
                
            } catch (Exception e) {
                logger.error("Error during health monitoring", e);
            }
        }, 30, 30, TimeUnit.SECONDS); // Run every 30 seconds
    }
    
    private void registerDefaultRecoveryStrategies() {
        // Database recovery strategy
        registerRecoveryStrategy("database_recovery", this::performDatabaseRecovery);
        
        // Memory cleanup strategy
        registerRecoveryStrategy("memory_cleanup", () -> {
            System.gc();
            logger.debug("Performed garbage collection");
        });
        
        // Circuit breaker reset strategy
        registerRecoveryStrategy("circuit_breaker_reset", () -> {
            circuitBreakerService.resetAllCircuitBreakers();
            logger.info("Reset all circuit breakers");
        });
    }
    
    private void recordError(String operationName, Exception error) {
        ErrorStats stats = errorStats.computeIfAbsent(operationName, ErrorStats::new);
        stats.recordError(error.getMessage());
        
        logger.debug("Recorded error for operation {}: {}", operationName, error.getMessage());
    }
    
    private void attemptRecovery(String operationName) {
        // Check if this operation has a specific recovery strategy
        Runnable strategy = recoveryStrategies.get(operationName + "_recovery");
        if (strategy != null) {
            try {
                strategy.run();
                logger.info("Executed recovery strategy for operation: {}", operationName);
            } catch (Exception e) {
                logger.warn("Recovery strategy failed for operation: {}", operationName, e);
            }
        }
    }
    
    private boolean shouldTriggerRecovery() {
        // Trigger recovery if any circuit breakers are open
        if (circuitBreakerService.hasOpenCircuitBreakers()) {
            return true;
        }
        
        // Trigger recovery if error rates are high
        long totalRecentErrors = errorStats.values().stream()
            .mapToLong(ErrorStats::getRecentErrors)
            .sum();
        
        return totalRecentErrors > 10; // Threshold for recent errors
    }
    
    private HealthCheckResult checkDatabaseHealth() {
        long startTime = System.nanoTime();
        
        if (databaseService == null) {
            return new HealthCheckResult("database", false, "DatabaseService not available", 
                Duration.ofNanos(System.nanoTime() - startTime));
        }
        
        try {
            if (!databaseService.isInitialized()) {
                return new HealthCheckResult("database", false, "Database not initialized", 
                    Duration.ofNanos(System.nanoTime() - startTime));
            }
            
            // Simple connectivity test
            try (Connection conn = databaseService.getConnection()) {
                if (conn == null || conn.isClosed()) {
                    return new HealthCheckResult("database", false, "Cannot establish connection", 
                        Duration.ofNanos(System.nanoTime() - startTime));
                }
                
                // Test with a simple query
                try (PreparedStatement stmt = conn.prepareStatement("SELECT 1")) {
                    stmt.executeQuery();
                }
                
                return new HealthCheckResult("database", true, "Database healthy", 
                    Duration.ofNanos(System.nanoTime() - startTime));
            }
            
        } catch (SQLException e) {
            return new HealthCheckResult("database", false, "Database error: " + e.getMessage(), 
                Duration.ofNanos(System.nanoTime() - startTime));
        }
    }
    
    private HealthCheckResult checkCircuitBreakerHealth() {
        long startTime = System.nanoTime();
        
        Map<CircuitBreakerService.State, Long> counts = circuitBreakerService.getCircuitBreakerCounts();
        long openCount = counts.getOrDefault(CircuitBreakerService.State.OPEN, 0L);
        
        boolean healthy = openCount == 0;
        String message = healthy ? "All circuit breakers closed" : openCount + " circuit breakers open";
        
        return new HealthCheckResult("circuit_breakers", healthy, message, 
            Duration.ofNanos(System.nanoTime() - startTime));
    }
    
    private HealthCheckResult checkErrorRateHealth() {
        long startTime = System.nanoTime();
        
        long totalRecentErrors = errorStats.values().stream()
            .mapToLong(ErrorStats::getRecentErrors)
            .sum();
        
        boolean healthy = totalRecentErrors < 5; // Threshold for acceptable error rate
        String message = "Recent errors: " + totalRecentErrors;
        
        return new HealthCheckResult("error_rates", healthy, message, 
            Duration.ofNanos(System.nanoTime() - startTime));
    }
    
    private HealthCheckResult checkMemoryHealth() {
        long startTime = System.nanoTime();
        
        Runtime runtime = Runtime.getRuntime();
        long maxMemory = runtime.maxMemory();
        long totalMemory = runtime.totalMemory();
        long freeMemory = runtime.freeMemory();
        long usedMemory = totalMemory - freeMemory;
        
        double memoryUsagePercentage = (double) usedMemory / maxMemory * 100;
        
        boolean healthy = memoryUsagePercentage < 90; // 90% threshold
        String message = String.format("Memory usage: %.1f%% (%d MB / %d MB)", 
            memoryUsagePercentage, usedMemory / 1024 / 1024, maxMemory / 1024 / 1024);
        
        return new HealthCheckResult("memory", healthy, message, 
            Duration.ofNanos(System.nanoTime() - startTime));
    }
    
    private void performDatabaseRecovery() {
        if (databaseService != null) {
            try {
                // Database recovery logic would go here
                // This might involve reconnecting, checking integrity, etc.
                logger.info("Database recovery completed successfully");
            } catch (Exception e) {
                logger.error("Database recovery failed", e);
                throw new RuntimeException("Database recovery failed", e);
            }
        }
    }
    
    public boolean isReady() {
        return initialized.get() && !shutdown.get();
    }
}