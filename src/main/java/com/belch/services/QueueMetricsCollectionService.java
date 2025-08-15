package com.belch.services;

import com.belch.database.DatabaseService;
import com.belch.database.EnhancedTrafficQueue;
import com.belch.config.ApiConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Service for collecting and storing historical queue metrics over time.
 * Provides data for trend analysis, capacity planning, and performance monitoring.
 * 
 * Features:
 * - Automatic metrics collection at configurable intervals
 * - Multiple granularity levels (1m, 5m, 15m, 1h, 1d)
 * - Data aggregation and rollup
 * - Configurable retention policies
 * - Query interface for historical data retrieval
 */
public class QueueMetricsCollectionService {
    
    private static final Logger logger = LoggerFactory.getLogger(QueueMetricsCollectionService.class);
    
    private final DatabaseService databaseService;
    private final EnhancedTrafficQueue trafficQueue;
    private final ApiConfig config;
    
    private final ScheduledExecutorService metricsExecutor;
    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    
    // Collection intervals in seconds
    private static final int MINUTE_INTERVAL = 60;      // 1 minute
    private static final int FIVE_MINUTE_INTERVAL = 300; // 5 minutes
    private static final int FIFTEEN_MINUTE_INTERVAL = 900; // 15 minutes
    private static final int HOUR_INTERVAL = 3600;     // 1 hour
    private static final int DAY_INTERVAL = 86400;     // 1 day
    
    // Retention periods in days
    private static final int MINUTE_RETENTION_DAYS = 1;    // 1 day of 1-minute data
    private static final int FIVE_MINUTE_RETENTION_DAYS = 7;  // 7 days of 5-minute data
    private static final int FIFTEEN_MINUTE_RETENTION_DAYS = 30; // 30 days of 15-minute data
    private static final int HOUR_RETENTION_DAYS = 90;    // 90 days of hourly data
    private static final int DAY_RETENTION_DAYS = 365;    // 1 year of daily data
    
    public QueueMetricsCollectionService(DatabaseService databaseService, 
                                       EnhancedTrafficQueue trafficQueue, 
                                       ApiConfig config) {
        this.databaseService = databaseService;
        this.trafficQueue = trafficQueue;
        this.config = config;
        
        this.metricsExecutor = Executors.newScheduledThreadPool(2, r -> {
            Thread t = new Thread(r, "QueueMetricsCollection");
            t.setDaemon(true);
            t.setPriority(Thread.NORM_PRIORITY - 1);
            return t;
        });
        
        initializeDatabase();
        startMetricsCollection();
        
        logger.info("✅ QueueMetricsCollectionService initialized with historical data collection");
    }
    
    /**
     * Initialize database tables for metrics storage
     */
    private void initializeDatabase() {
        try (Connection conn = databaseService.getConnection()) {
            
            // Create main metrics table
            String createMetricsTable = """
                CREATE TABLE IF NOT EXISTS queue_metrics_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp_epoch INTEGER NOT NULL,
                    timestamp_iso TEXT NOT NULL,
                    granularity TEXT NOT NULL,
                    
                    -- Queue size metrics
                    queue_size INTEGER DEFAULT 0,
                    max_queue_size INTEGER DEFAULT 0,
                    queue_utilization_percent REAL DEFAULT 0.0,
                    
                    -- Processing metrics
                    messages_processed INTEGER DEFAULT 0,
                    messages_added INTEGER DEFAULT 0,
                    processing_rate_per_second REAL DEFAULT 0.0,
                    average_processing_time_ms REAL DEFAULT 0.0,
                    
                    -- Batch metrics
                    current_batch_size INTEGER DEFAULT 0,
                    batches_processed INTEGER DEFAULT 0,
                    average_batch_size REAL DEFAULT 0.0,
                    
                    -- Dead letter queue metrics
                    dead_letter_queue_size INTEGER DEFAULT 0,
                    messages_failed INTEGER DEFAULT 0,
                    failure_rate_percent REAL DEFAULT 0.0,
                    
                    -- Backpressure metrics
                    backpressure_level TEXT DEFAULT 'NONE',
                    circuit_breaker_open BOOLEAN DEFAULT FALSE,
                    rejected_messages INTEGER DEFAULT 0,
                    
                    -- Performance metrics
                    cpu_usage_percent REAL DEFAULT 0.0,
                    memory_usage_mb REAL DEFAULT 0.0,
                    active_threads INTEGER DEFAULT 0,
                    
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """;
            
            // Create aggregated metrics table for faster queries
            String createAggregatedTable = """
                CREATE TABLE IF NOT EXISTS queue_metrics_aggregated (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date_hour TEXT NOT NULL,
                    granularity TEXT NOT NULL,
                    
                    -- Aggregated values
                    avg_queue_size REAL DEFAULT 0.0,
                    max_queue_size INTEGER DEFAULT 0,
                    total_messages_processed INTEGER DEFAULT 0,
                    avg_processing_rate REAL DEFAULT 0.0,
                    avg_processing_time_ms REAL DEFAULT 0.0,
                    total_messages_failed INTEGER DEFAULT 0,
                    avg_failure_rate REAL DEFAULT 0.0,
                    
                    data_points INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    
                    UNIQUE(date_hour, granularity)
                )
            """;
            
            try (Statement stmt = conn.createStatement()) {
                stmt.execute(createMetricsTable);
                stmt.execute(createAggregatedTable);
                
                // Create indexes for performance
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON queue_metrics_history(timestamp_epoch)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_metrics_granularity ON queue_metrics_history(granularity)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_metrics_timestamp_granularity ON queue_metrics_history(timestamp_epoch, granularity)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_metrics_created ON queue_metrics_history(created_at)");
                
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_aggregated_date_hour ON queue_metrics_aggregated(date_hour)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_aggregated_granularity ON queue_metrics_aggregated(granularity)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_aggregated_date_granularity ON queue_metrics_aggregated(date_hour, granularity)");
                
                logger.info("📊 Queue metrics database tables created successfully");
            }
            
        } catch (SQLException e) {
            logger.error("Failed to initialize queue metrics database", e);
            throw new RuntimeException("Queue metrics database initialization failed", e);
        }
    }
    
    /**
     * Start automatic metrics collection
     */
    private void startMetricsCollection() {
        if (isRunning.compareAndSet(false, true)) {
            // Collect metrics at 1-minute intervals
            metricsExecutor.scheduleAtFixedRate(
                () -> collectMetrics("1m"), 
                MINUTE_INTERVAL, 
                MINUTE_INTERVAL, 
                TimeUnit.SECONDS
            );
            
            // Collect metrics at 5-minute intervals
            metricsExecutor.scheduleAtFixedRate(
                () -> collectMetrics("5m"), 
                FIVE_MINUTE_INTERVAL, 
                FIVE_MINUTE_INTERVAL, 
                TimeUnit.SECONDS
            );
            
            // Collect metrics at 15-minute intervals
            metricsExecutor.scheduleAtFixedRate(
                () -> collectMetrics("15m"), 
                FIFTEEN_MINUTE_INTERVAL, 
                FIFTEEN_MINUTE_INTERVAL, 
                TimeUnit.SECONDS
            );
            
            // Collect metrics at hourly intervals
            metricsExecutor.scheduleAtFixedRate(
                () -> collectMetrics("1h"), 
                HOUR_INTERVAL, 
                HOUR_INTERVAL, 
                TimeUnit.SECONDS
            );
            
            // Collect metrics at daily intervals
            metricsExecutor.scheduleAtFixedRate(
                () -> collectMetrics("1d"), 
                DAY_INTERVAL, 
                DAY_INTERVAL, 
                TimeUnit.SECONDS
            );
            
            // Cleanup old metrics every 6 hours
            metricsExecutor.scheduleAtFixedRate(
                this::cleanupOldMetrics, 
                6 * 3600, 
                6 * 3600, 
                TimeUnit.SECONDS
            );
            
            logger.info("📈 Queue metrics collection started (1m, 5m, 15m, 1h, 1d intervals)");
        }
    }
    
    /**
     * Collect current queue metrics and store them
     */
    private void collectMetrics(String granularity) {
        try {
            // Get current metrics from the traffic queue
            Map<String, Object> currentMetrics = trafficQueue.getEnhancedMetrics();
            Map<String, Object> healthStatus = trafficQueue.getHealthStatus();
            
            // Extract backpressure and performance data from the main metrics
            Map<String, Object> backpressureStatus = Map.of(
                "level", currentMetrics.getOrDefault("backpressure_level", "NORMAL"),
                "circuit_breaker_open", currentMetrics.getOrDefault("circuit_breaker_tripped", false),
                "rejected_messages", currentMetrics.getOrDefault("dropped_items", 0L)
            );
            
            Map<String, Object> performanceMetrics = Map.of(
                "cpu_usage_percent", 0.0, // Would need system monitoring for real CPU data
                "memory_usage_mb", Runtime.getRuntime().totalMemory() / 1024.0 / 1024.0,
                "active_threads", currentMetrics.getOrDefault("processing_threads", 0)
            );
            
            long timestamp = System.currentTimeMillis();
            String timestampIso = Instant.ofEpochMilli(timestamp)
                .atOffset(ZoneOffset.UTC)
                .format(DateTimeFormatter.ISO_INSTANT);
            
            // Store metrics in database
            try (Connection conn = databaseService.getConnection()) {
                String insertMetrics = """
                    INSERT INTO queue_metrics_history (
                        timestamp_epoch, timestamp_iso, granularity,
                        queue_size, max_queue_size, queue_utilization_percent,
                        messages_processed, messages_added, processing_rate_per_second, average_processing_time_ms,
                        current_batch_size, batches_processed, average_batch_size,
                        dead_letter_queue_size, messages_failed, failure_rate_percent,
                        backpressure_level, circuit_breaker_open, rejected_messages,
                        cpu_usage_percent, memory_usage_mb, active_threads
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """;
                
                try (PreparedStatement stmt = conn.prepareStatement(insertMetrics)) {
                    stmt.setLong(1, timestamp);
                    stmt.setString(2, timestampIso);
                    stmt.setString(3, granularity);
                    
                    // Queue size metrics
                    stmt.setInt(4, (Integer) currentMetrics.getOrDefault("current_queue_size", 0));
                    stmt.setInt(5, (Integer) currentMetrics.getOrDefault("max_queue_size", 0));
                    stmt.setDouble(6, (Double) currentMetrics.getOrDefault("queue_utilization_percent", 0.0));
                    
                    // Processing metrics
                    stmt.setLong(7, (Long) currentMetrics.getOrDefault("total_processed", 0L));
                    stmt.setLong(8, (Long) currentMetrics.getOrDefault("total_added", 0L));
                    stmt.setDouble(9, (Double) currentMetrics.getOrDefault("processing_rate", 0.0));
                    stmt.setDouble(10, (Double) currentMetrics.getOrDefault("average_processing_time", 0.0));
                    
                    // Batch metrics
                    stmt.setInt(11, (Integer) currentMetrics.getOrDefault("current_batch_size", 0));
                    stmt.setLong(12, (Long) currentMetrics.getOrDefault("batches_processed", 0L));
                    stmt.setDouble(13, (Double) currentMetrics.getOrDefault("average_batch_size", 0.0));
                    
                    // Dead letter queue metrics
                    stmt.setInt(14, (Integer) currentMetrics.getOrDefault("dead_letter_queue_size", 0));
                    stmt.setLong(15, (Long) currentMetrics.getOrDefault("failed_messages", 0L));
                    stmt.setDouble(16, (Double) currentMetrics.getOrDefault("failure_rate_percent", 0.0));
                    
                    // Backpressure metrics
                    stmt.setString(17, (String) backpressureStatus.getOrDefault("level", "NONE"));
                    stmt.setBoolean(18, (Boolean) backpressureStatus.getOrDefault("circuit_breaker_open", false));
                    stmt.setLong(19, (Long) backpressureStatus.getOrDefault("rejected_messages", 0L));
                    
                    // Performance metrics
                    stmt.setDouble(20, (Double) performanceMetrics.getOrDefault("cpu_usage_percent", 0.0));
                    stmt.setDouble(21, (Double) performanceMetrics.getOrDefault("memory_usage_mb", 0.0));
                    stmt.setInt(22, (Integer) performanceMetrics.getOrDefault("active_threads", 0));
                    
                    stmt.executeUpdate();
                }
            }
            
            logger.debug("📊 Collected {} metrics: queue_size={}, processing_rate={}", 
                        granularity, 
                        currentMetrics.get("current_queue_size"),
                        currentMetrics.get("processing_rate"));
            
        } catch (Exception e) {
            logger.error("Failed to collect queue metrics for granularity: " + granularity, e);
        }
    }
    
    /**
     * Get historical metrics for a specific timeframe and granularity
     */
    public Map<String, Object> getHistoricalMetrics(String timeframe, String granularity) {
        try {
            // Parse timeframe (e.g., "1h", "24h", "7d")
            long startTime = parseTimeframe(timeframe);
            long endTime = System.currentTimeMillis();
            
            // Validate granularity
            if (!isValidGranularity(granularity)) {
                granularity = "5m"; // Default fallback
            }
            
            List<Map<String, Object>> dataPoints = new ArrayList<>();
            Map<String, Object> summary = new HashMap<>();
            
            try (Connection conn = databaseService.getConnection()) {
                String query = """
                    SELECT 
                        timestamp_epoch, timestamp_iso,
                        queue_size, queue_utilization_percent,
                        messages_processed, processing_rate_per_second, average_processing_time_ms,
                        current_batch_size, average_batch_size,
                        dead_letter_queue_size, messages_failed, failure_rate_percent,
                        backpressure_level, circuit_breaker_open, rejected_messages,
                        cpu_usage_percent, memory_usage_mb, active_threads
                    FROM queue_metrics_history 
                    WHERE timestamp_epoch >= ? AND timestamp_epoch <= ? 
                    AND granularity = ?
                    ORDER BY timestamp_epoch ASC
                """;
                
                try (PreparedStatement stmt = conn.prepareStatement(query)) {
                    stmt.setLong(1, startTime);
                    stmt.setLong(2, endTime);
                    stmt.setString(3, granularity);
                    
                    try (ResultSet rs = stmt.executeQuery()) {
                        double totalQueueSize = 0;
                        double totalProcessingRate = 0;
                        double totalProcessingTime = 0;
                        double totalFailureRate = 0;
                        int dataPointCount = 0;
                        int maxQueueSize = 0;
                        
                        while (rs.next()) {
                            Map<String, Object> dataPoint = new HashMap<>();
                            
                            dataPoint.put("timestamp", rs.getLong("timestamp_epoch"));
                            dataPoint.put("timestamp_iso", rs.getString("timestamp_iso"));
                            dataPoint.put("queue_size", rs.getInt("queue_size"));
                            dataPoint.put("queue_utilization_percent", rs.getDouble("queue_utilization_percent"));
                            dataPoint.put("messages_processed", rs.getLong("messages_processed"));
                            dataPoint.put("processing_rate_per_second", rs.getDouble("processing_rate_per_second"));
                            dataPoint.put("average_processing_time_ms", rs.getDouble("average_processing_time_ms"));
                            dataPoint.put("current_batch_size", rs.getInt("current_batch_size"));
                            dataPoint.put("average_batch_size", rs.getDouble("average_batch_size"));
                            dataPoint.put("dead_letter_queue_size", rs.getInt("dead_letter_queue_size"));
                            dataPoint.put("messages_failed", rs.getLong("messages_failed"));
                            dataPoint.put("failure_rate_percent", rs.getDouble("failure_rate_percent"));
                            dataPoint.put("backpressure_level", rs.getString("backpressure_level"));
                            dataPoint.put("circuit_breaker_open", rs.getBoolean("circuit_breaker_open"));
                            dataPoint.put("rejected_messages", rs.getLong("rejected_messages"));
                            dataPoint.put("cpu_usage_percent", rs.getDouble("cpu_usage_percent"));
                            dataPoint.put("memory_usage_mb", rs.getDouble("memory_usage_mb"));
                            dataPoint.put("active_threads", rs.getInt("active_threads"));
                            
                            dataPoints.add(dataPoint);
                            
                            // Calculate summary statistics
                            totalQueueSize += rs.getInt("queue_size");
                            totalProcessingRate += rs.getDouble("processing_rate_per_second");
                            totalProcessingTime += rs.getDouble("average_processing_time_ms");
                            totalFailureRate += rs.getDouble("failure_rate_percent");
                            maxQueueSize = Math.max(maxQueueSize, rs.getInt("queue_size"));
                            dataPointCount++;
                        }
                        
                        // Build summary
                        if (dataPointCount > 0) {
                            summary.put("average_queue_size", totalQueueSize / dataPointCount);
                            summary.put("max_queue_size", maxQueueSize);
                            summary.put("average_processing_rate", totalProcessingRate / dataPointCount);
                            summary.put("average_processing_time_ms", totalProcessingTime / dataPointCount);
                            summary.put("average_failure_rate", totalFailureRate / dataPointCount);
                            summary.put("data_point_count", dataPointCount);
                        } else {
                            summary.put("note", "No data available for the specified timeframe and granularity");
                        }
                    }
                }
            }
            
            return Map.of(
                "timeframe", timeframe,
                "granularity", granularity,
                "start_time", startTime,
                "end_time", endTime,
                "data_points", dataPoints,
                "summary", summary,
                "total_points", dataPoints.size()
            );
            
        } catch (Exception e) {
            logger.error("Failed to get historical metrics", e);
            return Map.of(
                "error", "Failed to retrieve historical metrics: " + e.getMessage(),
                "timeframe", timeframe,
                "granularity", granularity,
                "data_points", List.of()
            );
        }
    }
    
    /**
     * Parse timeframe string into milliseconds ago
     */
    private long parseTimeframe(String timeframe) {
        if (timeframe == null) {
            timeframe = "1h";
        }
        
        long currentTime = System.currentTimeMillis();
        
        try {
            if (timeframe.endsWith("m")) {
                int minutes = Integer.parseInt(timeframe.substring(0, timeframe.length() - 1));
                return currentTime - (minutes * 60 * 1000L);
            } else if (timeframe.endsWith("h")) {
                int hours = Integer.parseInt(timeframe.substring(0, timeframe.length() - 1));
                return currentTime - (hours * 60 * 60 * 1000L);
            } else if (timeframe.endsWith("d")) {
                int days = Integer.parseInt(timeframe.substring(0, timeframe.length() - 1));
                return currentTime - (days * 24 * 60 * 60 * 1000L);
            }
        } catch (NumberFormatException e) {
            logger.warn("Invalid timeframe format: {}, using default 1h", timeframe);
        }
        
        // Default to 1 hour
        return currentTime - (60 * 60 * 1000L);
    }
    
    /**
     * Validate granularity parameter
     */
    private boolean isValidGranularity(String granularity) {
        return granularity != null && 
               (granularity.equals("1m") || granularity.equals("5m") || 
                granularity.equals("15m") || granularity.equals("1h") || 
                granularity.equals("1d"));
    }
    
    /**
     * Clean up old metrics based on retention policies
     */
    private void cleanupOldMetrics() {
        try (Connection conn = databaseService.getConnection()) {
            long currentTime = System.currentTimeMillis();
            
            // Clean up based on retention policies
            String cleanup1m = "DELETE FROM queue_metrics_history WHERE granularity = '1m' AND timestamp_epoch < ?";
            String cleanup5m = "DELETE FROM queue_metrics_history WHERE granularity = '5m' AND timestamp_epoch < ?";
            String cleanup15m = "DELETE FROM queue_metrics_history WHERE granularity = '15m' AND timestamp_epoch < ?";
            String cleanup1h = "DELETE FROM queue_metrics_history WHERE granularity = '1h' AND timestamp_epoch < ?";
            String cleanup1d = "DELETE FROM queue_metrics_history WHERE granularity = '1d' AND timestamp_epoch < ?";
            
            int deletedCount = 0;
            
            try (PreparedStatement stmt1m = conn.prepareStatement(cleanup1m);
                 PreparedStatement stmt5m = conn.prepareStatement(cleanup5m);
                 PreparedStatement stmt15m = conn.prepareStatement(cleanup15m);
                 PreparedStatement stmt1h = conn.prepareStatement(cleanup1h);
                 PreparedStatement stmt1d = conn.prepareStatement(cleanup1d)) {
                
                // 1-minute data: keep 1 day
                stmt1m.setLong(1, currentTime - (MINUTE_RETENTION_DAYS * 24 * 60 * 60 * 1000L));
                deletedCount += stmt1m.executeUpdate();
                
                // 5-minute data: keep 7 days
                stmt5m.setLong(1, currentTime - (FIVE_MINUTE_RETENTION_DAYS * 24 * 60 * 60 * 1000L));
                deletedCount += stmt5m.executeUpdate();
                
                // 15-minute data: keep 30 days
                stmt15m.setLong(1, currentTime - (FIFTEEN_MINUTE_RETENTION_DAYS * 24 * 60 * 60 * 1000L));
                deletedCount += stmt15m.executeUpdate();
                
                // Hourly data: keep 90 days
                stmt1h.setLong(1, currentTime - (HOUR_RETENTION_DAYS * 24 * 60 * 60 * 1000L));
                deletedCount += stmt1h.executeUpdate();
                
                // Daily data: keep 365 days
                stmt1d.setLong(1, currentTime - (DAY_RETENTION_DAYS * 24 * 60 * 60 * 1000L));
                deletedCount += stmt1d.executeUpdate();
            }
            
            if (deletedCount > 0) {
                logger.info("🧹 Cleaned up {} old queue metrics records", deletedCount);
            }
            
        } catch (SQLException e) {
            logger.error("Failed to cleanup old queue metrics", e);
        }
    }
    
    /**
     * Get metrics collection status
     */
    public Map<String, Object> getCollectionStatus() {
        Map<String, Object> status = new HashMap<>();
        
        status.put("is_running", isRunning.get());
        status.put("collection_intervals", Map.of(
            "1m", MINUTE_INTERVAL + "s",
            "5m", FIVE_MINUTE_INTERVAL + "s", 
            "15m", FIFTEEN_MINUTE_INTERVAL + "s",
            "1h", HOUR_INTERVAL + "s",
            "1d", DAY_INTERVAL + "s"
        ));
        status.put("retention_policies", Map.of(
            "1m", MINUTE_RETENTION_DAYS + " days",
            "5m", FIVE_MINUTE_RETENTION_DAYS + " days",
            "15m", FIFTEEN_MINUTE_RETENTION_DAYS + " days", 
            "1h", HOUR_RETENTION_DAYS + " days",
            "1d", DAY_RETENTION_DAYS + " days"
        ));
        
        // Get database stats
        try (Connection conn = databaseService.getConnection()) {
            String countQuery = "SELECT granularity, COUNT(*) as count FROM queue_metrics_history GROUP BY granularity";
            try (PreparedStatement stmt = conn.prepareStatement(countQuery);
                 ResultSet rs = stmt.executeQuery()) {
                
                Map<String, Integer> dataPointCounts = new HashMap<>();
                while (rs.next()) {
                    dataPointCounts.put(rs.getString("granularity"), rs.getInt("count"));
                }
                status.put("stored_data_points", dataPointCounts);
            }
        } catch (SQLException e) {
            status.put("database_error", e.getMessage());
        }
        
        return status;
    }
    
    /**
     * Shutdown the metrics collection service
     */
    public void shutdown() {
        if (isRunning.compareAndSet(true, false)) {
            metricsExecutor.shutdown();
            try {
                if (!metricsExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                    metricsExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                metricsExecutor.shutdownNow();
                Thread.currentThread().interrupt();
            }
            
            logger.info("✅ QueueMetricsCollectionService shutdown complete");
        }
    }
}