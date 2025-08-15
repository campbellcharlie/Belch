package com.belch.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Predicate;
import java.util.function.Supplier;

/**
 * Retry service with exponential backoff and jitter for resilient operations.
 * Provides configurable retry policies for different types of operations.
 */
public class RetryService {
    
    private static final Logger logger = LoggerFactory.getLogger(RetryService.class);
    
    // Default retry configuration
    private static final int DEFAULT_MAX_ATTEMPTS = 3;
    private static final Duration DEFAULT_INITIAL_DELAY = Duration.ofMillis(100);
    private static final double DEFAULT_BACKOFF_MULTIPLIER = 2.0;
    private static final Duration DEFAULT_MAX_DELAY = Duration.ofSeconds(30);
    private static final double DEFAULT_JITTER_FACTOR = 0.1;
    
    /**
     * Retry policy configuration
     */
    public static class RetryPolicy {
        private final int maxAttempts;
        private final Duration initialDelay;
        private final double backoffMultiplier;
        private final Duration maxDelay;
        private final double jitterFactor;
        private final Predicate<Exception> retryCondition;
        
        private RetryPolicy(Builder builder) {
            this.maxAttempts = builder.maxAttempts;
            this.initialDelay = builder.initialDelay;
            this.backoffMultiplier = builder.backoffMultiplier;
            this.maxDelay = builder.maxDelay;
            this.jitterFactor = builder.jitterFactor;
            this.retryCondition = builder.retryCondition;
        }
        
        public static Builder builder() {
            return new Builder();
        }
        
        public static class Builder {
            private int maxAttempts = DEFAULT_MAX_ATTEMPTS;
            private Duration initialDelay = DEFAULT_INITIAL_DELAY;
            private double backoffMultiplier = DEFAULT_BACKOFF_MULTIPLIER;
            private Duration maxDelay = DEFAULT_MAX_DELAY;
            private double jitterFactor = DEFAULT_JITTER_FACTOR;
            private Predicate<Exception> retryCondition = exception -> true; // Retry all exceptions by default
            
            public Builder maxAttempts(int maxAttempts) {
                this.maxAttempts = Math.max(1, maxAttempts);
                return this;
            }
            
            public Builder initialDelay(Duration initialDelay) {
                this.initialDelay = initialDelay;
                return this;
            }
            
            public Builder backoffMultiplier(double backoffMultiplier) {
                this.backoffMultiplier = Math.max(1.0, backoffMultiplier);
                return this;
            }
            
            public Builder maxDelay(Duration maxDelay) {
                this.maxDelay = maxDelay;
                return this;
            }
            
            public Builder jitterFactor(double jitterFactor) {
                this.jitterFactor = Math.max(0.0, Math.min(1.0, jitterFactor));
                return this;
            }
            
            public Builder retryOn(Class<? extends Exception> exceptionClass) {
                this.retryCondition = exceptionClass::isInstance;
                return this;
            }
            
            public Builder retryOn(Predicate<Exception> condition) {
                this.retryCondition = condition;
                return this;
            }
            
            public Builder retryOnAny() {
                this.retryCondition = exception -> true;
                return this;
            }
            
            public RetryPolicy build() {
                return new RetryPolicy(this);
            }
        }
        
        // Getters
        public int getMaxAttempts() { return maxAttempts; }
        public Duration getInitialDelay() { return initialDelay; }
        public double getBackoffMultiplier() { return backoffMultiplier; }
        public Duration getMaxDelay() { return maxDelay; }
        public double getJitterFactor() { return jitterFactor; }
        public Predicate<Exception> getRetryCondition() { return retryCondition; }
    }
    
    /**
     * Result of a retry operation
     */
    public static class RetryResult<T> {
        private final T result;
        private final int attemptsMade;
        private final Duration totalDuration;
        private final Exception lastException;
        private final boolean succeeded;
        
        private RetryResult(T result, int attemptsMade, Duration totalDuration, Exception lastException, boolean succeeded) {
            this.result = result;
            this.attemptsMade = attemptsMade;
            this.totalDuration = totalDuration;
            this.lastException = lastException;
            this.succeeded = succeeded;
        }
        
        public static <T> RetryResult<T> success(T result, int attemptsMade, Duration totalDuration) {
            return new RetryResult<>(result, attemptsMade, totalDuration, null, true);
        }
        
        public static <T> RetryResult<T> failure(Exception lastException, int attemptsMade, Duration totalDuration) {
            return new RetryResult<>(null, attemptsMade, totalDuration, lastException, false);
        }
        
        // Getters
        public T getResult() { return result; }
        public int getAttemptsMade() { return attemptsMade; }
        public Duration getTotalDuration() { return totalDuration; }
        public Exception getLastException() { return lastException; }
        public boolean isSucceeded() { return succeeded; }
    }
    
    /**
     * Execute operation with default retry policy
     */
    public <T> T execute(Supplier<T> operation) throws Exception {
        return execute(operation, RetryPolicy.builder().build());
    }
    
    /**
     * Execute operation with custom retry policy
     */
    public <T> T execute(Supplier<T> operation, RetryPolicy policy) throws Exception {
        RetryResult<T> result = executeWithResult(operation, policy);
        
        if (result.isSucceeded()) {
            return result.getResult();
        } else {
            throw result.getLastException();
        }
    }
    
    /**
     * Execute operation and return detailed result including retry metadata
     */
    public <T> RetryResult<T> executeWithResult(Supplier<T> operation, RetryPolicy policy) {
        long startTime = System.nanoTime();
        Exception lastException = null;
        
        for (int attempt = 1; attempt <= policy.getMaxAttempts(); attempt++) {
            try {
                T result = operation.get();
                Duration totalDuration = Duration.ofNanos(System.nanoTime() - startTime);
                
                if (attempt > 1) {
                    logger.debug("Operation succeeded on attempt {} after {}", attempt, totalDuration);
                }
                
                return RetryResult.success(result, attempt, totalDuration);
                
            } catch (Exception e) {
                lastException = e;
                
                // Check if we should retry this exception
                if (!policy.getRetryCondition().test(e)) {
                    logger.debug("Exception {} is not retryable, failing immediately", e.getClass().getSimpleName());
                    Duration totalDuration = Duration.ofNanos(System.nanoTime() - startTime);
                    return RetryResult.failure(e, attempt, totalDuration);
                }
                
                // If this is the last attempt, don't wait
                if (attempt == policy.getMaxAttempts()) {
                    logger.warn("Operation failed after {} attempts. Last exception: {}", attempt, e.getMessage());
                    Duration totalDuration = Duration.ofNanos(System.nanoTime() - startTime);
                    return RetryResult.failure(e, attempt, totalDuration);
                }
                
                // Calculate delay for next attempt
                Duration delay = calculateDelay(attempt - 1, policy);
                
                logger.debug("Operation failed on attempt {} ({}), retrying in {}ms", 
                           attempt, e.getMessage(), delay.toMillis());
                
                try {
                    Thread.sleep(delay.toMillis());
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    logger.warn("Retry interrupted");
                    Duration totalDuration = Duration.ofNanos(System.nanoTime() - startTime);
                    return RetryResult.failure(new InterruptedException("Retry interrupted"), attempt, totalDuration);
                }
            }
        }
        
        // This should never be reached due to the loop logic above
        Duration totalDuration = Duration.ofNanos(System.nanoTime() - startTime);
        return RetryResult.failure(lastException, policy.getMaxAttempts(), totalDuration);
    }
    
    /**
     * Execute operation asynchronously with retry policy
     */
    public <T> java.util.concurrent.CompletableFuture<T> executeAsync(Supplier<T> operation, RetryPolicy policy) {
        return java.util.concurrent.CompletableFuture.supplyAsync(() -> {
            try {
                return execute(operation, policy);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }
    
    /**
     * Create a retry policy for database operations
     */
    public static RetryPolicy databaseRetryPolicy() {
        return RetryPolicy.builder()
            .maxAttempts(5)
            .initialDelay(Duration.ofMillis(200))
            .backoffMultiplier(2.0)
            .maxDelay(Duration.ofSeconds(10))
            .retryOn(exception -> 
                exception instanceof java.sql.SQLException ||
                exception instanceof java.sql.SQLTransientException ||
                exception.getMessage().contains("database") ||
                exception.getMessage().contains("connection")
            )
            .build();
    }
    
    /**
     * Create a retry policy for HTTP operations
     */
    public static RetryPolicy httpRetryPolicy() {
        return RetryPolicy.builder()
            .maxAttempts(3)
            .initialDelay(Duration.ofMillis(500))
            .backoffMultiplier(2.0)
            .maxDelay(Duration.ofSeconds(15))
            .retryOn(exception -> 
                exception instanceof java.net.SocketTimeoutException ||
                exception instanceof java.net.ConnectException ||
                exception.getMessage().contains("timeout") ||
                exception.getMessage().contains("connection reset")
            )
            .build();
    }
    
    /**
     * Create a retry policy for Burp API operations
     */
    public static RetryPolicy burpApiRetryPolicy() {
        return RetryPolicy.builder()
            .maxAttempts(4)
            .initialDelay(Duration.ofMillis(100))
            .backoffMultiplier(1.5)
            .maxDelay(Duration.ofSeconds(5))
            .retryOn(exception -> 
                exception instanceof IllegalStateException ||
                exception.getMessage().contains("not available") ||
                exception.getMessage().contains("temporarily unavailable")
            )
            .build();
    }
    
    /**
     * Create a minimal retry policy for critical operations
     */
    public static RetryPolicy criticalOperationPolicy() {
        return RetryPolicy.builder()
            .maxAttempts(2)
            .initialDelay(Duration.ofMillis(50))
            .backoffMultiplier(1.0) // No exponential backoff
            .jitterFactor(0.0) // No jitter
            .retryOnAny()
            .build();
    }
    
    private Duration calculateDelay(int attemptNumber, RetryPolicy policy) {
        // Calculate exponential backoff
        double delayMillis = policy.getInitialDelay().toMillis() * 
                           Math.pow(policy.getBackoffMultiplier(), attemptNumber);
        
        // Apply maximum delay limit
        delayMillis = Math.min(delayMillis, policy.getMaxDelay().toMillis());
        
        // Add jitter to prevent thundering herd
        if (policy.getJitterFactor() > 0) {
            double jitterRange = delayMillis * policy.getJitterFactor();
            double jitter = ThreadLocalRandom.current().nextDouble(-jitterRange, jitterRange);
            delayMillis += jitter;
        }
        
        // Ensure delay is non-negative
        delayMillis = Math.max(0, delayMillis);
        
        return Duration.ofMillis((long) delayMillis);
    }
}