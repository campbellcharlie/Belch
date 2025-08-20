package com.belch.database;

import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import com.belch.config.ApiConfig;
import com.belch.logging.TrafficSource;
import com.belch.websocket.EventBroadcaster;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.Comparator;

/**
 * Enhanced asynchronous traffic queue system with priority queuing, dead letter handling,
 * backpressure management, and dynamic batch sizing for optimal performance under load.
 * 
 * Features:
 * - Priority-based message processing
 * - Dead letter queue for failed messages
 * - Adaptive batch sizing based on load
 * - Backpressure handling with circuit breaker
 * - Real-time monitoring and metrics
 * - Message loss prevention
 */
public class EnhancedTrafficQueue {
    
    private static final Logger logger = LoggerFactory.getLogger(EnhancedTrafficQueue.class);
    
    // Queue configuration
    private static final int DEFAULT_QUEUE_SIZE = 100000; // Increased capacity
    private static final int DEFAULT_BATCH_SIZE = 100;
    private static final int MIN_BATCH_SIZE = 10;
    private static final int MAX_BATCH_SIZE = 500;
    private static final int PROCESSING_INTERVAL_MS = 100; // Faster processing
    private static final int MAX_PROCESSING_TIME_MS = 500; // Increased timeout
    
    // Dead letter queue configuration
    private static final int DEAD_LETTER_QUEUE_SIZE = 10000;
    private static final int MAX_RETRY_ATTEMPTS = 3;
    private static final long RETRY_DELAY_MS = 5000;
    
    // Backpressure configuration
    private static final double HIGH_PRESSURE_THRESHOLD = 0.8; // 80% queue utilization
    private static final double CRITICAL_PRESSURE_THRESHOLD = 0.95; // 95% queue utilization
    private static final int CIRCUIT_BREAKER_FAILURE_THRESHOLD = 10;
    private static final long CIRCUIT_BREAKER_TIMEOUT_MS = 30000; // 30 seconds
    
    private final DatabaseService databaseService;
    private final ApiConfig config;
    private EventBroadcaster eventBroadcaster;
    
    // Enhanced priority queue system
    private final PriorityBlockingQueue<PriorityTrafficItem> priorityQueue;
    private final BlockingQueue<FailedTrafficItem> deadLetterQueue;
    
    // Background processing
    private final ExecutorService processingExecutor;
    private final ExecutorService deadLetterExecutor;
    private final ScheduledExecutorService monitoringExecutor;
    
    // State management
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean shutdown = new AtomicBoolean(false);
    
    // Enhanced metrics
    private final AtomicLong totalQueued = new AtomicLong(0);
    private final AtomicLong totalProcessed = new AtomicLong(0);
    private final AtomicLong totalDropped = new AtomicLong(0);
    private final AtomicLong totalErrors = new AtomicLong(0);
    private final AtomicLong totalRetries = new AtomicLong(0);
    private final AtomicLong totalDeadLettered = new AtomicLong(0);
    
    // Adaptive batch sizing
    private final AtomicInteger currentBatchSize = new AtomicInteger(DEFAULT_BATCH_SIZE);
    private volatile long lastProcessingTime = 0;
    private volatile double averageProcessingTime = 0;
    
    // Backpressure and circuit breaker
    private volatile BackpressureLevel backpressureLevel = BackpressureLevel.NORMAL;
    private final AtomicInteger consecutiveFailures = new AtomicInteger(0);
    private volatile long circuitBreakerOpenTime = 0;
    private volatile boolean circuitBreakerOpen = false;
    
    // Project change detection
    private volatile long lastProjectCheckTime = 0;
    private static final long PROJECT_CHECK_INTERVAL_MS = 2000; // Check every 2 seconds for faster detection
    
    private final Lock queueLock = new ReentrantLock();
    
    /**
     * Priority levels for traffic items
     */
    public enum Priority {
        CRITICAL(1),    // Scanner-generated traffic, security testing
        HIGH(2),        // User-initiated requests, important APIs
        NORMAL(3),      // Regular proxy traffic
        LOW(4),         // Background traffic, bulk imports
        BULK(5);        // Large batch imports
        
        public final int value;
        
        Priority(int value) {
            this.value = value;
        }
    }
    
    /**
     * Backpressure levels for queue management
     */
    public enum BackpressureLevel {
        NORMAL,         // Queue operating normally
        HIGH,           // Queue under pressure, reduce batch sizes
        CRITICAL,       // Queue critically full, drop low priority items
        CIRCUIT_OPEN    // Circuit breaker open, reject new items
    }
    
    /**
     * Enhanced traffic item with priority support
     */
    public static class PriorityTrafficItem implements Comparable<PriorityTrafficItem> {
        public final TrafficQueue.TrafficItem item;
        public final Priority priority;
        public final long queueTime;
        public final String traceId;
        
        public PriorityTrafficItem(TrafficQueue.TrafficItem item, Priority priority) {
            this.item = item;
            this.priority = priority;
            this.queueTime = System.currentTimeMillis();
            this.traceId = generateTraceId();
        }
        
        @Override
        public int compareTo(PriorityTrafficItem other) {
            int priorityComparison = Integer.compare(this.priority.value, other.priority.value);
            if (priorityComparison != 0) {
                return priorityComparison;
            }
            // Same priority: FIFO order
            return Long.compare(this.queueTime, other.queueTime);
        }
        
        private String generateTraceId() {
            return "trace_" + System.currentTimeMillis() + "_" + (int)(Math.random() * 10000);
        }
    }
    
    /**
     * Failed traffic item for dead letter queue
     */
    public static class FailedTrafficItem {
        public final PriorityTrafficItem originalItem;
        public final Exception lastError;
        public final int attemptCount;
        public final long firstFailureTime;
        public final long lastAttemptTime;
        
        public FailedTrafficItem(PriorityTrafficItem item, Exception error, int attempts) {
            this.originalItem = item;
            this.lastError = error;
            this.attemptCount = attempts;
            this.firstFailureTime = attempts == 1 ? System.currentTimeMillis() : item.queueTime;
            this.lastAttemptTime = System.currentTimeMillis();
        }
    }
    
    /**
     * Constructor for EnhancedTrafficQueue
     */
    public EnhancedTrafficQueue(DatabaseService databaseService, ApiConfig config) {
        this.databaseService = databaseService;
        this.config = config;
        
        // Initialize priority queue with custom comparator
        this.priorityQueue = new PriorityBlockingQueue<>(DEFAULT_QUEUE_SIZE);
        this.deadLetterQueue = new ArrayBlockingQueue<>(DEAD_LETTER_QUEUE_SIZE);
        
        // Initialize executors
        this.processingExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "EnhancedTrafficQueue-Processor");
            t.setDaemon(true);
            t.setPriority(Thread.NORM_PRIORITY);
            return t;
        });
        
        this.deadLetterExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "EnhancedTrafficQueue-DeadLetter");
            t.setDaemon(true);
            t.setPriority(Thread.NORM_PRIORITY - 1);
            return t;
        });
        
        this.monitoringExecutor = Executors.newScheduledThreadPool(1, r -> {
            Thread t = new Thread(r, "EnhancedTrafficQueue-Monitor");
            t.setDaemon(true);
            t.setPriority(Thread.NORM_PRIORITY - 1);
            return t;
        });
    }
    
    /**
     * Starts the enhanced traffic queue processing
     */
    public void start() {
        if (running.getAndSet(true)) {
            logger.warn("EnhancedTrafficQueue already running");
            return;
        }
        
        logger.info("🚀 Starting EnhancedTrafficQueue with priority support");
        logger.info("📊 Queue capacity: {}, batch size: {}-{}, dead letter capacity: {}", 
                   DEFAULT_QUEUE_SIZE, MIN_BATCH_SIZE, MAX_BATCH_SIZE, DEAD_LETTER_QUEUE_SIZE);
        
        // Start processing threads
        processingExecutor.submit(this::processQueue);
        deadLetterExecutor.submit(this::processDeadLetterQueue);
        
        // Start monitoring
        monitoringExecutor.scheduleAtFixedRate(this::monitorQueueHealth, 
                                             10, 10, TimeUnit.SECONDS);
        monitoringExecutor.scheduleAtFixedRate(this::adjustBatchSize, 
                                             5, 5, TimeUnit.SECONDS);
        
        logger.info("✅ EnhancedTrafficQueue started successfully");
    }
    
    /**
     * Set the event broadcaster for real-time WebSocket updates
     */
    public void setEventBroadcaster(EventBroadcaster eventBroadcaster) {
        this.eventBroadcaster = eventBroadcaster;
        logger.info("[*] EnhancedTrafficQueue WebSocket broadcasting enabled");
    }
    
    /**
     * Stops the enhanced traffic queue
     */
    public void stop() {
        if (shutdown.getAndSet(true)) {
            return;
        }
        
        logger.info("🛑 Stopping EnhancedTrafficQueue...");
        running.set(false);
        
        // Process remaining items
        processRemainingItems();
        
        // Shutdown executors
        shutdownExecutors();
        
        logger.info("✅ EnhancedTrafficQueue stopped. Final stats: queued={}, processed={}, dropped={}, errors={}, dead_lettered={}", 
                   totalQueued.get(), totalProcessed.get(), totalDropped.get(), totalErrors.get(), totalDeadLettered.get());
    }
    
    /**
     * Queue a request with specified priority
     */
    public void queueRequest(InterceptedRequest request, Priority priority) {
        if (shouldRejectItem(priority)) {
            totalDropped.incrementAndGet();
            return;
        }
        
        TrafficQueue.TrafficItem item = new TrafficQueue.TrafficItem(request, config.getSessionTag());
        PriorityTrafficItem priorityItem = new PriorityTrafficItem(item, priority);
        queuePriorityItem(priorityItem);
    }
    
    /**
     * Queue a response with specified priority
     */
    public void queueResponse(InterceptedResponse response, Priority priority) {
        if (shouldRejectItem(priority)) {
            totalDropped.incrementAndGet();
            return;
        }
        
        TrafficQueue.TrafficItem item = new TrafficQueue.TrafficItem(response, config.getSessionTag());
        PriorityTrafficItem priorityItem = new PriorityTrafficItem(item, priority);
        queuePriorityItem(priorityItem);
    }
    
    /**
     * Queue raw traffic with specified priority
     */
    public void queueRawTraffic(String method, String url, String host, String headers, String body,
                               String responseHeaders, String responseBody, Integer statusCode, 
                               String sessionTag, TrafficSource source, Priority priority) {
        if (shouldRejectItem(priority)) {
            totalDropped.incrementAndGet();
            return;
        }
        
        TrafficQueue.TrafficItem item = new TrafficQueue.TrafficItem(method, url, host, headers, body, 
                                       responseHeaders, responseBody, statusCode, sessionTag, source);
        PriorityTrafficItem priorityItem = new PriorityTrafficItem(item, priority);
        queuePriorityItem(priorityItem);
    }
    
    /**
     * Convenience methods with default priorities
     */
    public void queueRequest(InterceptedRequest request) {
        queueRequest(request, Priority.NORMAL);
    }
    
    public void queueResponse(InterceptedResponse response) {
        queueResponse(response, Priority.NORMAL);
    }
    
    public void queueRawTraffic(String method, String url, String host, String headers, String body,
                               String responseHeaders, String responseBody, Integer statusCode, 
                               String sessionTag, TrafficSource source) {
        queueRawTraffic(method, url, host, headers, body, responseHeaders, responseBody, 
                       statusCode, sessionTag, source, Priority.NORMAL);
    }
    
    /**
     * Internal method to queue priority item with backpressure handling
     */
    private void queuePriorityItem(PriorityTrafficItem item) {
        totalQueued.incrementAndGet();
        
        try {
            queueLock.lock();
            
            // Update backpressure level
            updateBackpressureLevel();
            
            // Check if we should accept this item
            if (shouldRejectItem(item.priority)) {
                totalDropped.incrementAndGet();
                logDroppedItem(item);
                return;
            }
            
            // Add to priority queue
            boolean queued = priorityQueue.offer(item);
            
            if (!queued) {
                // Queue is full, move to dead letter queue if high priority
                if (item.priority.value <= Priority.HIGH.value) {
                    moveToDeadLetterQueue(item, new RuntimeException("Queue overflow"), 0);
                } else {
                    totalDropped.incrementAndGet();
                    logDroppedItem(item);
                }
            }
            
        } finally {
            queueLock.unlock();
        }
    }
    
    /**
     * Check if item should be rejected based on backpressure and priority
     */
    private boolean shouldRejectItem(Priority priority) {
        if (shutdown.get()) {
            return true;
        }
        
        if (circuitBreakerOpen) {
            // Check if circuit breaker should close
            if (System.currentTimeMillis() - circuitBreakerOpenTime > CIRCUIT_BREAKER_TIMEOUT_MS) {
                circuitBreakerOpen = false;
                consecutiveFailures.set(0);
                logger.info("🔄 Circuit breaker closed, resuming normal operation");
            } else {
                return true; // Circuit breaker still open
            }
        }
        
        // Apply backpressure based on priority
        switch (backpressureLevel) {
            case CRITICAL:
                return priority.value > Priority.HIGH.value; // Only accept CRITICAL and HIGH
            case HIGH:
                return priority.value > Priority.NORMAL.value; // Reject LOW and BULK
            case CIRCUIT_OPEN:
                return true; // Reject all
            default:
                return false; // Accept all
        }
    }
    
    /**
     * Update backpressure level based on queue utilization
     */
    private void updateBackpressureLevel() {
        double utilization = (double) priorityQueue.size() / DEFAULT_QUEUE_SIZE;
        
        BackpressureLevel newLevel;
        if (utilization >= CRITICAL_PRESSURE_THRESHOLD) {
            newLevel = BackpressureLevel.CRITICAL;
        } else if (utilization >= HIGH_PRESSURE_THRESHOLD) {
            newLevel = BackpressureLevel.HIGH;
        } else {
            newLevel = BackpressureLevel.NORMAL;
        }
        
        if (newLevel != backpressureLevel) {
            logger.info("🔀 Backpressure level changed: {} -> {} (utilization: {:.1f}%)", 
                       backpressureLevel, newLevel, utilization * 100);
            backpressureLevel = newLevel;
        }
    }
    
    /**
     * Main processing loop for priority queue
     */
    private void processQueue() {
        logger.info("✅ Enhanced traffic queue processing started");
        
        while (running.get() && !Thread.currentThread().isInterrupted()) {
            try {
                long processingStartTime = System.currentTimeMillis();
                
                // Check for project changes
                checkForProjectChange();
                
                // Process batch with current batch size
                List<PriorityTrafficItem> batch = collectBatch();
                
                if (!batch.isEmpty()) {
                    processPriorityBatch(batch);
                }
                
                // Update processing metrics
                lastProcessingTime = System.currentTimeMillis() - processingStartTime;
                updateAverageProcessingTime();
                
                // Control processing rate
                if (lastProcessingTime < PROCESSING_INTERVAL_MS) {
                    Thread.sleep(PROCESSING_INTERVAL_MS - lastProcessingTime);
                }
                
            } catch (InterruptedException e) {
                logger.info("Enhanced traffic queue processing interrupted");
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                logger.error("Error in enhanced traffic queue processing", e);
                totalErrors.incrementAndGet();
                handleConsecutiveFailure();
                
                try {
                    Thread.sleep(1000); // Brief pause on error
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        
        logger.info("Enhanced traffic queue processing stopped");
    }
    
    /**
     * Collect batch of items with current batch size
     */
    private List<PriorityTrafficItem> collectBatch() {
        List<PriorityTrafficItem> batch = new ArrayList<>();
        int batchSize = currentBatchSize.get();
        
        // Collect items up to batch size
        for (int i = 0; i < batchSize; i++) {
            PriorityTrafficItem item = priorityQueue.poll();
            if (item == null) {
                break; // No more items
            }
            batch.add(item);
        }
        
        return batch;
    }
    
    /**
     * Process batch of priority items
     */
    private void processPriorityBatch(List<PriorityTrafficItem> batch) {
        if (batch.isEmpty() || shutdown.get() || !databaseService.isInitialized()) {
            return;
        }
        
        long startTime = System.currentTimeMillis();
        int processed = 0;
        int errors = 0;
        
        for (PriorityTrafficItem priorityItem : batch) {
            try {
                boolean success = processSingleItem(priorityItem);
                if (success) {
                    processed++;
                    consecutiveFailures.set(0); // Reset on success
                } else {
                    errors++;
                    handleItemFailure(priorityItem, new RuntimeException("Processing failed"));
                }
                
                // Don't spend too much time in one batch
                if (System.currentTimeMillis() - startTime > MAX_PROCESSING_TIME_MS) {
                    break;
                }
                
            } catch (Exception e) {
                errors++;
                handleItemFailure(priorityItem, e);
            }
        }
        
        // Update metrics
        totalProcessed.addAndGet(processed);
        if (errors > 0) {
            totalErrors.addAndGet(errors);
        }
        
        // Log statistics
        if (processed > 0 && logger.isDebugEnabled()) {
            long processingTime = System.currentTimeMillis() - startTime;
            logger.debug("📊 Processed batch: size={}, processed={}, errors={}, time={}ms, avg_priority={}", 
                       batch.size(), processed, errors, processingTime, 
                       batch.stream().mapToInt(item -> item.priority.value).average().orElse(0));
        }
    }
    
    /**
     * Process single traffic item
     */
    private boolean processSingleItem(PriorityTrafficItem priorityItem) {
        TrafficQueue.TrafficItem item = priorityItem.item;
        
        try {
            switch (item.type) {
                case REQUEST:
                    databaseService.storeRequest(item.request);
                    return true;
                    
                case RESPONSE:
                    databaseService.storeResponse(item.response);
                    return true;
                    
                case RAW_TRAFFIC:
                    long result = databaseService.storeTrafficNormalized(
                        item.method, item.url, item.host, item.headers, item.body,
                        item.responseHeaders, item.responseBody, item.statusCode, 
                        item.sessionTag, item.source, item.requestHttpVersion, item.responseHttpVersion
                    );
                    
                    if (result > 0) {
                        // Broadcast event if configured
                        broadcastTrafficEvent(item, result, priorityItem.traceId);
                        return true;
                    } else if (result == -2) {
                        return true; // Duplicate, still success
                    } else {
                        return false; // Storage failed
                    }
                    
                default:
                    return false;
            }
        } catch (Exception e) {
            logger.debug("Error processing item {}: {}", priorityItem.traceId, e.getMessage());
            return false;
        }
    }
    
    /**
     * Handle item processing failure
     */
    private void handleItemFailure(PriorityTrafficItem item, Exception error) {
        // High priority items go to dead letter queue for retry
        if (item.priority.value <= Priority.HIGH.value) {
            moveToDeadLetterQueue(item, error, 1);
        }
        
        handleConsecutiveFailure();
    }
    
    /**
     * Handle consecutive failures for circuit breaker
     */
    private void handleConsecutiveFailure() {
        int failures = consecutiveFailures.incrementAndGet();
        
        if (failures >= CIRCUIT_BREAKER_FAILURE_THRESHOLD && !circuitBreakerOpen) {
            circuitBreakerOpen = true;
            circuitBreakerOpenTime = System.currentTimeMillis();
            backpressureLevel = BackpressureLevel.CIRCUIT_OPEN;
            
            logger.warn("🔴 Circuit breaker opened due to {} consecutive failures", failures);
        }
    }
    
    /**
     * Move item to dead letter queue
     */
    private void moveToDeadLetterQueue(PriorityTrafficItem item, Exception error, int attemptCount) {
        FailedTrafficItem failedItem = new FailedTrafficItem(item, error, attemptCount);
        
        boolean queued = deadLetterQueue.offer(failedItem);
        if (queued) {
            totalDeadLettered.incrementAndGet();
            logger.debug("💀 Moved item {} to dead letter queue (attempt {})", item.traceId, attemptCount);
        } else {
            totalDropped.incrementAndGet();
            logger.warn("💀 Dead letter queue full, dropping item {}", item.traceId);
        }
    }
    
    /**
     * Process dead letter queue for retries
     */
    private void processDeadLetterQueue() {
        logger.info("💀 Dead letter queue processor started");
        
        while (running.get() && !Thread.currentThread().isInterrupted()) {
            try {
                FailedTrafficItem failedItem = deadLetterQueue.poll(5, TimeUnit.SECONDS);
                
                if (failedItem != null) {
                    processDeadLetterItem(failedItem);
                }
                
            } catch (InterruptedException e) {
                logger.info("Dead letter queue processing interrupted");
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                logger.error("Error in dead letter queue processing", e);
                
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        
        logger.info("Dead letter queue processor stopped");
    }
    
    /**
     * Process individual dead letter item
     */
    private void processDeadLetterItem(FailedTrafficItem failedItem) {
        // Check if enough time has passed since last attempt
        if (System.currentTimeMillis() - failedItem.lastAttemptTime < RETRY_DELAY_MS) {
            // Put back in queue for later retry
            deadLetterQueue.offer(failedItem);
            return;
        }
        
        // Check retry limit
        if (failedItem.attemptCount >= MAX_RETRY_ATTEMPTS) {
            logger.warn("💀 Item {} exceeded max retry attempts ({}), permanently dropping", 
                       failedItem.originalItem.traceId, MAX_RETRY_ATTEMPTS);
            totalDropped.incrementAndGet();
            return;
        }
        
        // Attempt retry
        logger.debug("🔄 Retrying dead letter item {} (attempt {})", 
                    failedItem.originalItem.traceId, failedItem.attemptCount + 1);
        
        boolean success = processSingleItem(failedItem.originalItem);
        
        if (success) {
            totalProcessed.incrementAndGet();
            totalRetries.incrementAndGet();
            logger.debug("✅ Dead letter item {} successfully processed on retry", failedItem.originalItem.traceId);
        } else {
            // Failed again, increment attempt count and requeue
            FailedTrafficItem retryItem = new FailedTrafficItem(failedItem.originalItem, 
                                                              failedItem.lastError, 
                                                              failedItem.attemptCount + 1);
            deadLetterQueue.offer(retryItem);
        }
    }
    
    /**
     * Monitor queue health and adjust parameters
     */
    private void monitorQueueHealth() {
        try {
            Map<String, Object> metrics = getEnhancedMetrics();
            
            double utilization = (Double) metrics.get("queue_utilization_percent");
            double deadLetterUtilization = (Double) metrics.get("dead_letter_utilization_percent");
            
            // Log health status
            if (utilization > 90 || deadLetterUtilization > 80) {
                logger.warn("⚠️ Queue health warning: utilization={:.1f}%, dead_letter={:.1f}%, backpressure={}", 
                           utilization, deadLetterUtilization, backpressureLevel);
            }
            
            // Broadcast health metrics if configured
            if (eventBroadcaster != null) {
                eventBroadcaster.broadcastQueueMetrics(metrics, config.getSessionTag());
            }
            
        } catch (Exception e) {
            logger.error("Error monitoring queue health", e);
        }
    }
    
    /**
     * Dynamically adjust batch size based on performance
     */
    private void adjustBatchSize() {
        try {
            int currentSize = currentBatchSize.get();
            
            // Increase batch size if processing is fast and queue has items
            if (averageProcessingTime < MAX_PROCESSING_TIME_MS * 0.5 && 
                priorityQueue.size() > currentSize * 2 && 
                currentSize < MAX_BATCH_SIZE) {
                
                int newSize = Math.min(currentSize + 10, MAX_BATCH_SIZE);
                currentBatchSize.set(newSize);
                logger.debug("📈 Increased batch size: {} -> {}", currentSize, newSize);
            }
            // Decrease batch size if processing is slow
            else if (averageProcessingTime > MAX_PROCESSING_TIME_MS * 0.8 && 
                     currentSize > MIN_BATCH_SIZE) {
                
                int newSize = Math.max(currentSize - 10, MIN_BATCH_SIZE);
                currentBatchSize.set(newSize);
                logger.debug("📉 Decreased batch size: {} -> {}", currentSize, newSize);
            }
            
        } catch (Exception e) {
            logger.error("Error adjusting batch size", e);
        }
    }
    
    /**
     * Update rolling average of processing time
     */
    private void updateAverageProcessingTime() {
        if (averageProcessingTime == 0) {
            averageProcessingTime = lastProcessingTime;
        } else {
            // Exponential moving average
            averageProcessingTime = (averageProcessingTime * 0.9) + (lastProcessingTime * 0.1);
        }
    }
    
    /**
     * Broadcast traffic event via WebSocket
     */
    private void broadcastTrafficEvent(TrafficQueue.TrafficItem item, long id, String traceId) {
        if (eventBroadcaster != null) {
            Map<String, Object> trafficData = new HashMap<>();
            trafficData.put("id", id);
            trafficData.put("trace_id", traceId);
            trafficData.put("method", item.method);
            trafficData.put("url", item.url);
            trafficData.put("host", item.host);
            trafficData.put("status_code", item.statusCode);
            trafficData.put("timestamp", item.timestamp);
            trafficData.put("tool_source", item.source.toString());
            trafficData.put("body_size", item.body != null ? item.body.length() : 0);
            
            eventBroadcaster.broadcastTrafficCapture(trafficData, item.sessionTag);
        }
    }
    
    /**
     * Check for project changes
     */
    private void checkForProjectChange() {
        long currentTime = System.currentTimeMillis();
        
        if (currentTime - lastProjectCheckTime < PROJECT_CHECK_INTERVAL_MS) {
            return;
        }
        
        lastProjectCheckTime = currentTime;
        
        try {
            if (databaseService.checkForProjectChangeAndReinitialize()) {
                logger.info("🔄 Database switched to new project, clearing queues");
                
                int cleared = priorityQueue.size() + deadLetterQueue.size();
                priorityQueue.clear();
                deadLetterQueue.clear();
                totalDropped.addAndGet(cleared);
                
                // Reset circuit breaker
                circuitBreakerOpen = false;
                consecutiveFailures.set(0);
                backpressureLevel = BackpressureLevel.NORMAL;
                
                if (cleared > 0) {
                    logger.info("🗑️ Cleared {} queued items from previous project", cleared);
                }
            }
        } catch (Exception e) {
            logger.error("Failed to check for project change", e);
        }
    }
    
    /**
     * Process remaining items during shutdown
     */
    private void processRemainingItems() {
        int totalRemaining = priorityQueue.size() + deadLetterQueue.size();
        if (totalRemaining == 0) {
            return;
        }
        
        logger.info("📋 Processing {} remaining items...", totalRemaining);
        
        long startTime = System.currentTimeMillis();
        int processed = 0;
        
        // Process priority queue items
        while (!priorityQueue.isEmpty() && System.currentTimeMillis() - startTime < 10000) {
            List<PriorityTrafficItem> batch = collectBatch();
            if (!batch.isEmpty()) {
                processPriorityBatch(batch);
                processed += batch.size();
            }
        }
        
        logger.info("📋 Processed {} remaining items in {}ms", processed, System.currentTimeMillis() - startTime);
        
        int stillRemaining = priorityQueue.size() + deadLetterQueue.size();
        if (stillRemaining > 0) {
            logger.warn("⚠️ {} items were not processed during shutdown (timeout)", stillRemaining);
        }
    }
    
    /**
     * Shutdown all executors
     */
    private void shutdownExecutors() {
        List<ExecutorService> executors = List.of(processingExecutor, deadLetterExecutor, monitoringExecutor);
        
        for (ExecutorService executor : executors) {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }
    
    /**
     * Log dropped item for debugging
     */
    private void logDroppedItem(PriorityTrafficItem item) {
        if (totalDropped.get() % 100 == 1) { // Log every 100th drop
            logger.warn("⚠️ Dropped {} priority item {} (total dropped: {})", 
                       item.priority, item.traceId, totalDropped.get());
        }
    }
    
    /**
     * Get enhanced metrics including priority and dead letter queue stats
     */
    public Map<String, Object> getEnhancedMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        
        // Basic metrics
        metrics.put("running", running.get());
        metrics.put("total_queued", totalQueued.get());
        metrics.put("total_processed", totalProcessed.get());
        metrics.put("total_dropped", totalDropped.get());
        metrics.put("total_errors", totalErrors.get());
        metrics.put("total_retries", totalRetries.get());
        metrics.put("total_dead_lettered", totalDeadLettered.get());
        
        // Queue status
        int currentQueueSize = priorityQueue.size();
        int deadLetterSize = deadLetterQueue.size();
        
        metrics.put("current_queue_size", currentQueueSize);
        metrics.put("dead_letter_queue_size", deadLetterSize);
        metrics.put("queue_capacity", DEFAULT_QUEUE_SIZE);
        metrics.put("dead_letter_capacity", DEAD_LETTER_QUEUE_SIZE);
        metrics.put("queue_utilization_percent", (currentQueueSize * 100.0) / DEFAULT_QUEUE_SIZE);
        metrics.put("dead_letter_utilization_percent", (deadLetterSize * 100.0) / DEAD_LETTER_QUEUE_SIZE);
        
        // Performance metrics
        metrics.put("current_batch_size", currentBatchSize.get());
        metrics.put("last_processing_time_ms", lastProcessingTime);
        metrics.put("average_processing_time_ms", averageProcessingTime);
        metrics.put("backpressure_level", backpressureLevel.toString());
        metrics.put("circuit_breaker_open", circuitBreakerOpen);
        metrics.put("consecutive_failures", consecutiveFailures.get());
        
        // Success rates
        long processed = totalProcessed.get();
        long queued = totalQueued.get();
        if (queued > 0) {
            metrics.put("processing_success_rate_percent", (processed * 100.0) / queued);
            metrics.put("drop_rate_percent", (totalDropped.get() * 100.0) / queued);
        } else {
            metrics.put("processing_success_rate_percent", 100.0);
            metrics.put("drop_rate_percent", 0.0);
        }
        
        return metrics;
    }
    
    /**
     * Get queue health status
     */
    public Map<String, Object> getHealthStatus() {
        Map<String, Object> health = new HashMap<>();
        
        double utilization = (priorityQueue.size() * 100.0) / DEFAULT_QUEUE_SIZE;
        double deadLetterUtilization = (deadLetterQueue.size() * 100.0) / DEAD_LETTER_QUEUE_SIZE;
        
        boolean healthy = utilization < 90 && deadLetterUtilization < 80 && 
                         !circuitBreakerOpen && backpressureLevel != BackpressureLevel.CRITICAL;
        
        health.put("healthy", healthy);
        health.put("running", running.get());
        health.put("queue_utilization_percent", utilization);
        health.put("dead_letter_utilization_percent", deadLetterUtilization);
        health.put("backpressure_level", backpressureLevel.toString());
        health.put("circuit_breaker_open", circuitBreakerOpen);
        
        List<String> issues = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        
        if (circuitBreakerOpen) {
            issues.add("Circuit breaker is open due to consecutive failures");
        }
        
        if (backpressureLevel == BackpressureLevel.CRITICAL) {
            issues.add("Queue under critical pressure - dropping low priority items");
        }
        
        if (utilization > 90) {
            warnings.add("Primary queue utilization high (" + String.format("%.1f", utilization) + "%)");
        }
        
        if (deadLetterUtilization > 80) {
            warnings.add("Dead letter queue utilization high (" + String.format("%.1f", deadLetterUtilization) + "%)");
        }
        
        if (!issues.isEmpty()) {
            health.put("issues", issues);
        }
        
        if (!warnings.isEmpty()) {
            health.put("warnings", warnings);
        }
        
        return health;
    }
    
    /**
     * Check if queue is healthy
     */
    public boolean isHealthy() {
        return (Boolean) getHealthStatus().get("healthy");
    }
}