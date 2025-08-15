package com.belch.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * Circuit Breaker implementation for protecting against cascade failures.
 * Monitors operations and opens the circuit when failure thresholds are exceeded.
 */
public class CircuitBreakerService {
    
    private static final Logger logger = LoggerFactory.getLogger(CircuitBreakerService.class);
    
    // Circuit breaker instances for different operations
    private final ConcurrentHashMap<String, CircuitBreaker> circuitBreakers = new ConcurrentHashMap<>();
    
    // Default configuration
    private static final int DEFAULT_FAILURE_THRESHOLD = 5;
    private static final long DEFAULT_TIMEOUT_MILLIS = 60000; // 1 minute
    private static final int DEFAULT_SUCCESS_THRESHOLD = 3;
    
    /**
     * Circuit breaker states
     */
    public enum State {
        CLOSED,    // Normal operation
        OPEN,      // Circuit is open, calls fail fast
        HALF_OPEN  // Testing if service has recovered
    }
    
    /**
     * Individual circuit breaker for a specific operation
     */
    public static class CircuitBreaker {
        private final String name;
        private final int failureThreshold;
        private final long timeoutMillis;
        private final int successThreshold;
        
        private final AtomicReference<State> state = new AtomicReference<>(State.CLOSED);
        private final AtomicInteger failureCount = new AtomicInteger(0);
        private final AtomicInteger successCount = new AtomicInteger(0);
        private final AtomicLong lastFailureTime = new AtomicLong(0);
        private final AtomicLong lastAttemptTime = new AtomicLong(0);
        
        public CircuitBreaker(String name, int failureThreshold, long timeoutMillis, int successThreshold) {
            this.name = name;
            this.failureThreshold = failureThreshold;
            this.timeoutMillis = timeoutMillis;
            this.successThreshold = successThreshold;
        }
        
        /**
         * Execute an operation with circuit breaker protection
         */
        public <T> T execute(Supplier<T> operation) throws CircuitBreakerOpenException {
            lastAttemptTime.set(System.currentTimeMillis());
            
            if (state.get() == State.OPEN) {
                if (shouldAttemptReset()) {
                    state.set(State.HALF_OPEN);
                    successCount.set(0);
                    logger.info("Circuit breaker {} transitioning to HALF_OPEN state", name);
                } else {
                    throw new CircuitBreakerOpenException("Circuit breaker " + name + " is OPEN");
                }
            }
            
            try {
                T result = operation.get();
                onSuccess();
                return result;
            } catch (Exception e) {
                onFailure();
                throw e;
            }
        }
        
        /**
         * Check if circuit breaker is in a healthy state
         */
        public boolean isHealthy() {
            return state.get() == State.CLOSED;
        }
        
        /**
         * Get current circuit breaker statistics
         */
        public CircuitBreakerStats getStats() {
            return new CircuitBreakerStats(
                name,
                state.get(),
                failureCount.get(),
                successCount.get(),
                lastFailureTime.get(),
                lastAttemptTime.get(),
                failureThreshold,
                successThreshold
            );
        }
        
        /**
         * Reset circuit breaker to closed state
         */
        public void reset() {
            state.set(State.CLOSED);
            failureCount.set(0);
            successCount.set(0);
            logger.info("Circuit breaker {} manually reset to CLOSED state", name);
        }
        
        private void onSuccess() {
            failureCount.set(0);
            
            if (state.get() == State.HALF_OPEN) {
                int currentSuccessCount = successCount.incrementAndGet();
                if (currentSuccessCount >= successThreshold) {
                    state.set(State.CLOSED);
                    successCount.set(0);
                    logger.info("Circuit breaker {} recovered, transitioning to CLOSED state", name);
                }
            }
        }
        
        private void onFailure() {
            int currentFailureCount = failureCount.incrementAndGet();
            lastFailureTime.set(System.currentTimeMillis());
            
            if (state.get() == State.HALF_OPEN) {
                state.set(State.OPEN);
                logger.warn("Circuit breaker {} failed during HALF_OPEN, transitioning back to OPEN", name);
            } else if (currentFailureCount >= failureThreshold && state.get() == State.CLOSED) {
                state.set(State.OPEN);
                logger.error("Circuit breaker {} opened due to {} failures", name, currentFailureCount);
            }
        }
        
        private boolean shouldAttemptReset() {
            return System.currentTimeMillis() - lastFailureTime.get() >= timeoutMillis;
        }
    }
    
    /**
     * Circuit breaker statistics
     */
    public static class CircuitBreakerStats {
        private final String name;
        private final State state;
        private final int failureCount;
        private final int successCount;
        private final long lastFailureTime;
        private final long lastAttemptTime;
        private final int failureThreshold;
        private final int successThreshold;
        
        public CircuitBreakerStats(String name, State state, int failureCount, int successCount,
                                 long lastFailureTime, long lastAttemptTime, int failureThreshold, int successThreshold) {
            this.name = name;
            this.state = state;
            this.failureCount = failureCount;
            this.successCount = successCount;
            this.lastFailureTime = lastFailureTime;
            this.lastAttemptTime = lastAttemptTime;
            this.failureThreshold = failureThreshold;
            this.successThreshold = successThreshold;
        }
        
        // Getters
        public String getName() { return name; }
        public State getState() { return state; }
        public int getFailureCount() { return failureCount; }
        public int getSuccessCount() { return successCount; }
        public long getLastFailureTime() { return lastFailureTime; }
        public long getLastAttemptTime() { return lastAttemptTime; }
        public int getFailureThreshold() { return failureThreshold; }
        public int getSuccessThreshold() { return successThreshold; }
    }
    
    /**
     * Exception thrown when circuit breaker is open
     */
    public static class CircuitBreakerOpenException extends RuntimeException {
        public CircuitBreakerOpenException(String message) {
            super(message);
        }
    }
    
    /**
     * Get or create a circuit breaker for the specified operation
     */
    public CircuitBreaker getCircuitBreaker(String operationName) {
        return circuitBreakers.computeIfAbsent(operationName, name -> 
            new CircuitBreaker(name, DEFAULT_FAILURE_THRESHOLD, DEFAULT_TIMEOUT_MILLIS, DEFAULT_SUCCESS_THRESHOLD)
        );
    }
    
    /**
     * Get or create a circuit breaker with custom configuration
     */
    public CircuitBreaker getCircuitBreaker(String operationName, int failureThreshold, long timeoutMillis, int successThreshold) {
        return circuitBreakers.computeIfAbsent(operationName, name -> 
            new CircuitBreaker(name, failureThreshold, timeoutMillis, successThreshold)
        );
    }
    
    /**
     * Execute an operation with circuit breaker protection
     */
    public <T> T executeWithBreaker(String operationName, Supplier<T> operation) {
        return getCircuitBreaker(operationName).execute(operation);
    }
    
    /**
     * Execute an operation with custom circuit breaker configuration
     */
    public <T> T executeWithBreaker(String operationName, Supplier<T> operation, 
                                   int failureThreshold, long timeoutMillis, int successThreshold) {
        return getCircuitBreaker(operationName, failureThreshold, timeoutMillis, successThreshold).execute(operation);
    }
    
    /**
     * Get statistics for all circuit breakers
     */
    public java.util.Map<String, CircuitBreakerStats> getAllStats() {
        java.util.Map<String, CircuitBreakerStats> stats = new java.util.HashMap<>();
        circuitBreakers.forEach((name, breaker) -> stats.put(name, breaker.getStats()));
        return stats;
    }
    
    /**
     * Get statistics for a specific circuit breaker
     */
    public CircuitBreakerStats getStats(String operationName) {
        CircuitBreaker breaker = circuitBreakers.get(operationName);
        return breaker != null ? breaker.getStats() : null;
    }
    
    /**
     * Reset a specific circuit breaker
     */
    public boolean resetCircuitBreaker(String operationName) {
        CircuitBreaker breaker = circuitBreakers.get(operationName);
        if (breaker != null) {
            breaker.reset();
            return true;
        }
        return false;
    }
    
    /**
     * Reset all circuit breakers
     */
    public void resetAllCircuitBreakers() {
        circuitBreakers.values().forEach(CircuitBreaker::reset);
        logger.info("All circuit breakers reset");
    }
    
    /**
     * Check if any circuit breakers are currently open
     */
    public boolean hasOpenCircuitBreakers() {
        return circuitBreakers.values().stream()
            .anyMatch(breaker -> breaker.getStats().getState() == State.OPEN);
    }
    
    /**
     * Get count of circuit breakers by state
     */
    public java.util.Map<State, Long> getCircuitBreakerCounts() {
        return circuitBreakers.values().stream()
            .collect(java.util.stream.Collectors.groupingBy(
                breaker -> breaker.getStats().getState(),
                java.util.stream.Collectors.counting()
            ));
    }
    
    /**
     * Remove unused circuit breakers (older than specified time)
     */
    public void cleanupStaleCircuitBreakers(long maxIdleTimeMillis) {
        long currentTime = System.currentTimeMillis();
        circuitBreakers.entrySet().removeIf(entry -> {
            CircuitBreaker breaker = entry.getValue();
            long lastAttempt = breaker.getStats().getLastAttemptTime();
            boolean isStale = lastAttempt > 0 && (currentTime - lastAttempt) > maxIdleTimeMillis;
            
            if (isStale) {
                logger.debug("Removing stale circuit breaker: {}", entry.getKey());
            }
            
            return isStale;
        });
    }
    
    /**
     * Get health status summary
     */
    public java.util.Map<String, Object> getHealthSummary() {
        java.util.Map<State, Long> counts = getCircuitBreakerCounts();
        boolean isHealthy = !hasOpenCircuitBreakers();
        
        java.util.Map<String, Object> summary = new java.util.HashMap<>();
        summary.put("healthy", isHealthy);
        summary.put("total_circuit_breakers", circuitBreakers.size());
        summary.put("closed_count", counts.getOrDefault(State.CLOSED, 0L));
        summary.put("open_count", counts.getOrDefault(State.OPEN, 0L));
        summary.put("half_open_count", counts.getOrDefault(State.HALF_OPEN, 0L));
        summary.put("timestamp", System.currentTimeMillis());
        
        return summary;
    }
}