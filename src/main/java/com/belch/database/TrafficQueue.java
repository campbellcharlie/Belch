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
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Asynchronous traffic queue system to handle high-volume proxy traffic
 * without impacting Burp's performance. Uses background processing and
 * batch operations for optimal database performance.
 * 
 * @author Charlie Campbell
 * @version 1.0.0
 */
public class TrafficQueue {
    
    private static final Logger logger = LoggerFactory.getLogger(TrafficQueue.class);
    
    // Queue configuration
    private static final int DEFAULT_QUEUE_SIZE = 50000; // Large enough for high-volume testing
    private static final int BATCH_SIZE = 100; // Process records in batches for better DB performance
    private static final int PROCESSING_INTERVAL_MS = 500; // Process queue every 500ms
    private static final int MAX_PROCESSING_TIME_MS = 200; // Don't spend more than 200ms per processing cycle
    
    private final DatabaseService databaseService;
    private final ApiConfig config;
    
    // Phase 12: WebSocket event broadcasting
    private EventBroadcaster eventBroadcaster;
    
    // Queue for storing traffic items
    private final BlockingQueue<TrafficItem> trafficQueue;
    
    // Background processing
    private final ExecutorService processingExecutor;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean shutdown = new AtomicBoolean(false);
    
    // Performance metrics
    private final AtomicLong totalQueued = new AtomicLong(0);
    private final AtomicLong totalProcessed = new AtomicLong(0);
    private final AtomicLong totalDropped = new AtomicLong(0);
    private final AtomicLong totalErrors = new AtomicLong(0);
    private volatile long lastProcessingTime = 0;
    private volatile int currentQueueSize = 0;
    
    // Project change detection
    private volatile long lastProjectCheckTime = 0;
    private static final long PROJECT_CHECK_INTERVAL_MS = 10000; // Check every 10 seconds
    
    private final Lock queueLock = new ReentrantLock();
    
    /**
     * Represents a traffic item to be processed.
     */
    public static class TrafficItem {
        public enum Type { REQUEST, RESPONSE, RAW_TRAFFIC }
        
        public final Type type;
        public final long timestamp;
        public final String sessionTag;
        public final TrafficSource source;
        
        // For requests
        public final InterceptedRequest request;
        
        // For responses
        public final InterceptedResponse response;
        
        // For raw traffic (imports, etc.)
        public final String method;
        public final String url;
        public final String host;
        public final String headers;
        public final String body;
        public final String responseHeaders;
        public final String responseBody;
        public final Integer statusCode;
        public final String requestHttpVersion;
        public final String responseHttpVersion;
        
        // Request constructor
        public TrafficItem(InterceptedRequest request, String sessionTag) {
            this.type = Type.REQUEST;
            this.timestamp = System.currentTimeMillis();
            this.request = request;
            this.response = null;
            this.sessionTag = sessionTag;
            this.source = TrafficSource.PROXY;
            this.method = null;
            this.url = null;
            this.host = null;
            this.headers = null;
            this.body = null;
            this.responseHeaders = null;
            this.responseBody = null;
            this.statusCode = null;
            this.requestHttpVersion = null;
            this.responseHttpVersion = null;
        }
        
        // Response constructor
        public TrafficItem(InterceptedResponse response, String sessionTag) {
            this.type = Type.RESPONSE;
            this.timestamp = System.currentTimeMillis();
            this.request = null;
            this.response = response;
            this.sessionTag = sessionTag;
            this.source = TrafficSource.PROXY;
            this.method = null;
            this.url = null;
            this.host = null;
            this.headers = null;
            this.body = null;
            this.responseHeaders = null;
            this.responseBody = null;
            this.statusCode = null;
            this.requestHttpVersion = null;
            this.responseHttpVersion = null;
        }
        
        // Raw traffic constructor
        public TrafficItem(String method, String url, String host, String headers, String body,
                          String responseHeaders, String responseBody, Integer statusCode, 
                          String sessionTag, TrafficSource source, String requestHttpVersion, String responseHttpVersion) {
            this.type = Type.RAW_TRAFFIC;
            this.timestamp = System.currentTimeMillis();
            this.request = null;
            this.response = null;
            this.sessionTag = sessionTag;
            this.source = source;
            this.method = method;
            this.url = url;
            this.host = host;
            this.headers = headers;
            this.body = body;
            this.responseHeaders = responseHeaders;
            this.responseBody = responseBody;
            this.statusCode = statusCode;
            this.requestHttpVersion = requestHttpVersion;
            this.responseHttpVersion = responseHttpVersion;
        }
        
        // Overloaded constructor for backward compatibility
        public TrafficItem(String method, String url, String host, String headers, String body,
                          String responseHeaders, String responseBody, Integer statusCode, 
                          String sessionTag, TrafficSource source) {
            this(method, url, host, headers, body, responseHeaders, responseBody, statusCode, 
                 sessionTag, source, null, null);
        }
    }
    
    /**
     * Constructor for TrafficQueue.
     * 
     * @param databaseService The database service for persistence
     * @param config The API configuration
     */
    public TrafficQueue(DatabaseService databaseService, ApiConfig config) {
        this.databaseService = databaseService;
        this.config = config;
        this.trafficQueue = new ArrayBlockingQueue<>(DEFAULT_QUEUE_SIZE);
        this.processingExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "TrafficQueue-Processor");
            t.setDaemon(true); // Don't prevent JVM shutdown
            t.setPriority(Thread.NORM_PRIORITY - 1); // Lower priority than main threads
            return t;
        });
    }
    
    /**
     * Starts the traffic queue processing.
     */
    public void start() {
        if (running.getAndSet(true)) {
            logger.warn("TrafficQueue already running");
            return;
        }
        
        logger.info("🚀 Starting TrafficQueue with capacity: {}, batch size: {}", 
                   DEFAULT_QUEUE_SIZE, BATCH_SIZE);
        
        // Start background processing thread
        processingExecutor.submit(this::processQueue);
        
        logger.info("✅ TrafficQueue started successfully");
    }
    
    /**
     * Set the event broadcaster for real-time WebSocket updates (Phase 12).
     */
    public void setEventBroadcaster(EventBroadcaster eventBroadcaster) {
        this.eventBroadcaster = eventBroadcaster;
        logger.info("[*] TrafficQueue WebSocket broadcasting enabled");
    }
    
    /**
     * Stops the traffic queue and processes remaining items.
     */
    public void stop() {
        if (shutdown.getAndSet(true)) {
            return;
        }
        
        logger.info("🛑 Stopping TrafficQueue...");
        running.set(false);
        
        // Process remaining items
        processRemainingItems();
        
        // Shutdown executor
        processingExecutor.shutdown();
        try {
            if (!processingExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                logger.warn("TrafficQueue processing did not terminate within 5 seconds, forcing shutdown");
                processingExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            processingExecutor.shutdownNow();
        }
        
        logger.info("✅ TrafficQueue stopped. Final stats: queued={}, processed={}, dropped={}, errors={}", 
                   totalQueued.get(), totalProcessed.get(), totalDropped.get(), totalErrors.get());
    }
    
    /**
     * Queues a request for asynchronous processing.
     * This method returns immediately without blocking Burp.
     * 
     * @param request The intercepted request
     */
    public void queueRequest(InterceptedRequest request) {
        if (shutdown.get()) {
            return;
        }
        
        TrafficItem item = new TrafficItem(request, config.getSessionTag());
        queueItem(item);
    }
    
    /**
     * Queues a response for asynchronous processing.
     * This method returns immediately without blocking Burp.
     * 
     * @param response The intercepted response
     */
    public void queueResponse(InterceptedResponse response) {
        if (shutdown.get()) {
            return;
        }
        
        TrafficItem item = new TrafficItem(response, config.getSessionTag());
        queueItem(item);
    }
    
    /**
     * Queues raw traffic data for asynchronous processing.
     * This method returns immediately without blocking Burp.
     * 
     * @param method HTTP method
     * @param url URL
     * @param host Host
     * @param headers Request headers
     * @param body Request body
     * @param responseHeaders Response headers
     * @param responseBody Response body
     * @param statusCode Status code
     * @param sessionTag Session tag
     * @param source Traffic source
     */
    public void queueRawTraffic(String method, String url, String host, String headers, String body,
                               String responseHeaders, String responseBody, Integer statusCode, 
                               String sessionTag, TrafficSource source) {
        if (shutdown.get()) {
            return;
        }
        
        TrafficItem item = new TrafficItem(method, url, host, headers, body, 
                                         responseHeaders, responseBody, statusCode, sessionTag, source);
        queueItem(item);
    }
    
    /**
     * Internal method to queue an item with backpressure handling.
     */
    private void queueItem(TrafficItem item) {
        totalQueued.incrementAndGet();
        
        // Non-blocking offer - if queue is full, drop the item to prevent blocking Burp
        boolean queued = trafficQueue.offer(item);
        
        if (!queued) {
            totalDropped.incrementAndGet();
            
            // Log warning occasionally (not for every drop to avoid log spam)
            if (totalDropped.get() % 1000 == 1) {
                logger.warn("⚠️ TrafficQueue full - dropping items. Total dropped: {}. " +
                           "Consider increasing queue size or database performance.", totalDropped.get());
            }
        }
        
        currentQueueSize = trafficQueue.size();
    }
    
    /**
     * Main processing loop that handles the traffic queue.
     */
    private void processQueue() {
        logger.info("✅ Traffic queue processing started");
        
        while (running.get() && !Thread.currentThread().isInterrupted()) {
            try {
                long processingStartTime = System.currentTimeMillis();
                
                // Check for project changes periodically
                checkForProjectChange();
                
                // Process batches of traffic items
                List<TrafficItem> batch = new ArrayList<>();
                
                // Collect items for batch processing (non-blocking)
                TrafficItem item;
                while (batch.size() < BATCH_SIZE && 
                       (item = trafficQueue.poll()) != null) {
                    batch.add(item);
                }
                
                if (!batch.isEmpty()) {
                    processBatch(batch);
                }
                
                // Update metrics
                lastProcessingTime = System.currentTimeMillis() - processingStartTime;
                currentQueueSize = trafficQueue.size();
                
                // Control processing rate
                if (lastProcessingTime < PROCESSING_INTERVAL_MS) {
                    Thread.sleep(PROCESSING_INTERVAL_MS - lastProcessingTime);
                }
                
            } catch (InterruptedException e) {
                logger.info("Traffic queue processing interrupted");
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                logger.error("Error in traffic queue processing", e);
                totalErrors.incrementAndGet();
                
                try {
                    Thread.sleep(1000); // Brief pause on error
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        
        logger.info("Traffic queue processing stopped");
    }
    
    /**
     * Checks for project changes and reinitializes database if needed.
     */
    private void checkForProjectChange() {
        long currentTime = System.currentTimeMillis();
        
        // Only check periodically to avoid overhead
        if (currentTime - lastProjectCheckTime < PROJECT_CHECK_INTERVAL_MS) {
            return;
        }
        
        lastProjectCheckTime = currentTime;
        
        try {
            if (databaseService.checkForProjectChangeAndReinitialize()) {
                logger.info("🔄 Database switched to new project, clearing queue to prevent cross-contamination");
                
                // Clear the queue to prevent storing data from the old project 
                // into the new project's database
                int cleared = trafficQueue.size();
                trafficQueue.clear();
                totalDropped.addAndGet(cleared);
                
                if (cleared > 0) {
                    logger.info("🗑️ Cleared {} queued items from previous project", cleared);
                }
            }
        } catch (Exception e) {
            logger.error("Failed to check for project change", e);
        }
    }
    
    /**
     * Processes a batch of traffic items efficiently with optimized database operations.
     * Uses the new normalized schema when available for better performance.
     */
    private void processBatch(List<TrafficItem> batch) {
        if (batch.isEmpty() || shutdown.get() || databaseService == null || !databaseService.isInitialized()) {
            return;
        }
        
        long startTime = System.currentTimeMillis();
        int processed = 0;
        int errors = 0;
        int duplicates = 0;
        
        try {
            // Use batched processing for better performance
            List<TrafficItem> batchedItems = new ArrayList<>();
            
            for (TrafficItem item : batch) {
                try {
                    switch (item.type) {
                        case REQUEST:
                            databaseService.storeRequest(item.request);
                            processed++;
                            break;
                            
                        case RESPONSE:
                            databaseService.storeResponse(item.response);
                            processed++;
                            break;
                            
                        case RAW_TRAFFIC:
                            // Use normalized schema storage if available
                            long result = databaseService.storeTrafficNormalized(
                                item.method, item.url, item.host, item.headers, item.body,
                                item.responseHeaders, item.responseBody, item.statusCode, 
                                item.sessionTag, item.source, item.requestHttpVersion, item.responseHttpVersion
                            );
                            
                            if (result > 0) {
                                processed++;
                                
                                // Phase 12: Broadcast new traffic event to WebSocket clients
                                if (eventBroadcaster != null) {
                                    Map<String, Object> trafficData = new HashMap<>();
                                    trafficData.put("id", result);
                                    trafficData.put("method", item.method);
                                    trafficData.put("url", item.url);
                                    trafficData.put("host", item.host);
                                    trafficData.put("status_code", item.statusCode);
                                    trafficData.put("timestamp", item.timestamp);
                                    trafficData.put("tool_source", item.source.toString());
                                    trafficData.put("body_size", item.body != null ? item.body.length() : 0);
                                    
                                    eventBroadcaster.broadcastTrafficCapture(trafficData, item.sessionTag);
                                }
                            } else if (result == -2) {
                                duplicates++; // Duplicate, not an error
                            } else {
                                errors++;
                            }
                            break;
                    }
                    
                } catch (Exception e) {
                    errors++;
                    logger.debug("Error processing traffic item: {}", e.getMessage());
                }
                
                // Don't spend too much time in one batch
                if (System.currentTimeMillis() - startTime > MAX_PROCESSING_TIME_MS) {
                    break;
                }
            }
            
            // Update performance metrics
            totalProcessed.addAndGet(processed);
            if (errors > 0) {
                totalErrors.addAndGet(errors);
            }
            
            long processingTime = System.currentTimeMillis() - startTime;
            
            // Enhanced logging with duplicate tracking
            if (totalProcessed.get() % 1000 == 0) {
                logger.debug("📊 TrafficQueue stats: processed={}, queue_size={}, processing_time={}ms, errors={}, duplicates_skipped={}", 
                           processed, currentQueueSize, processingTime, errors, duplicates);
            }
            
            // Log performance warnings
            if (processingTime > MAX_PROCESSING_TIME_MS) {
                logger.warn("⚠️ Batch processing exceeded time limit: {}ms (target: {}ms)", 
                           processingTime, MAX_PROCESSING_TIME_MS);
            }
            
            // Log efficiency metrics
            if (processed > 0) {
                double itemsPerSecond = (processed * 1000.0) / processingTime;
                if (itemsPerSecond < 50) { // Less than 50 items/second is slow
                    logger.warn("⚠️ Slow batch processing: {:.1f} items/second", itemsPerSecond);
                }
            }
            
        } catch (Exception e) {
            logger.error("Error processing traffic batch", e);
            totalErrors.incrementAndGet();
        }
    }
    
    /**
     * Processes remaining items during shutdown.
     */
    private void processRemainingItems() {
        if (trafficQueue.isEmpty()) {
            return;
        }
        
        logger.info("📋 Processing {} remaining traffic items...", trafficQueue.size());
        
        int processed = 0;
        long startTime = System.currentTimeMillis();
        
        // Process items in batches
        while (!trafficQueue.isEmpty() && System.currentTimeMillis() - startTime < 5000) {
            List<TrafficItem> batch = new ArrayList<>();
            
            // Collect batch
            for (int i = 0; i < BATCH_SIZE && !trafficQueue.isEmpty(); i++) {
                TrafficItem item = trafficQueue.poll();
                if (item != null) {
                    batch.add(item);
                }
            }
            
            if (!batch.isEmpty()) {
                processBatch(batch);
                processed += batch.size();
            }
        }
        
        logger.info("📋 Processed {} remaining items in {}ms", processed, System.currentTimeMillis() - startTime);
        
        if (!trafficQueue.isEmpty()) {
            logger.warn("⚠️ {} traffic items were not processed during shutdown (timeout)", trafficQueue.size());
        }
    }
    
    /**
     * Gets current queue performance metrics.
     * 
     * @return Map with performance metrics
     */
    public Map<String, Object> getMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        
        metrics.put("running", running.get());
        metrics.put("total_queued", totalQueued.get());
        metrics.put("total_processed", totalProcessed.get());
        metrics.put("total_dropped", totalDropped.get());
        metrics.put("total_errors", totalErrors.get());
        metrics.put("current_queue_size", currentQueueSize);
        metrics.put("queue_capacity", DEFAULT_QUEUE_SIZE);
        metrics.put("queue_utilization_percent", (currentQueueSize * 100.0) / DEFAULT_QUEUE_SIZE);
        metrics.put("last_processing_time_ms", lastProcessingTime);
        metrics.put("batch_size", BATCH_SIZE);
        metrics.put("processing_interval_ms", PROCESSING_INTERVAL_MS);
        
        // Calculate processing rate
        long processed = totalProcessed.get();
        long queued = totalQueued.get();
        if (queued > 0) {
            metrics.put("processing_success_rate_percent", (processed * 100.0) / queued);
        } else {
            metrics.put("processing_success_rate_percent", 100.0);
        }
        
        return metrics;
    }
    
    /**
     * Checks if the queue is healthy (not dropping too many items).
     * 
     * @return true if queue is healthy, false if experiencing issues
     */
    public boolean isHealthy() {
        long queued = totalQueued.get();
        long dropped = totalDropped.get();
        
        if (queued == 0) {
            return true; // No traffic yet
        }
        
        double dropRate = (dropped * 100.0) / queued;
        return dropRate < 5.0; // Healthy if dropping less than 5% of items
    }
    
    /**
     * Gets queue health status with details.
     * 
     * @return Map with health status and details
     */
    public Map<String, Object> getHealthStatus() {
        Map<String, Object> health = new HashMap<>();
        
        boolean healthy = isHealthy();
        health.put("healthy", healthy);
        health.put("running", running.get());
        health.put("queue_utilization_percent", (currentQueueSize * 100.0) / DEFAULT_QUEUE_SIZE);
        
        if (!healthy) {
            health.put("issues", List.of(
                "High drop rate detected - queue may be overloaded",
                "Consider optimizing database performance or increasing queue capacity"
            ));
        }
        
        if (currentQueueSize > DEFAULT_QUEUE_SIZE * 0.8) {
            health.put("warnings", List.of(
                "Queue utilization high (" + String.format("%.1f", (currentQueueSize * 100.0) / DEFAULT_QUEUE_SIZE) + "%)",
                "Monitor for potential dropping of traffic items"
            ));
        }
        
        return health;
    }
} 