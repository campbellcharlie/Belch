package com.belch.services;

import com.belch.database.DatabaseService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Database optimization service for SQLite performance tuning, maintenance, and monitoring.
 * Provides table partitioning, archival, vacuuming, and performance analytics.
 */
public class DatabaseOptimizationService {
    
    private static final Logger logger = LoggerFactory.getLogger(DatabaseOptimizationService.class);
    
    private final DatabaseService databaseService;
    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private final AtomicBoolean shutdown = new AtomicBoolean(false);
    
    // Maintenance scheduling
    private final ScheduledExecutorService maintenanceScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "DatabaseMaintenance");
        t.setDaemon(true);
        return t;
    });
    
    // Performance metrics
    private final AtomicLong totalQueries = new AtomicLong(0);
    private final AtomicLong totalOptimizations = new AtomicLong(0);
    private final AtomicLong lastVacuumTime = new AtomicLong(0);
    private final AtomicLong archivedRecords = new AtomicLong(0);
    
    // Configuration
    private static final int VACUUM_INTERVAL_HOURS = 24;
    private static final int ARCHIVE_THRESHOLD_DAYS = 30;
    private static final int OPTIMIZATION_INTERVAL_HOURS = 6;
    private static final int MAX_RECORDS_PER_PARTITION = 50000;
    
    /**
     * Database performance statistics
     */
    public static class PerformanceStats {
        private final long totalQueries;
        private final long totalOptimizations;
        private final long lastVacuumTime;
        private final long archivedRecords;
        private final long databaseSizeBytes;
        private final int tableCount;
        private final Map<String, Long> tableSizes;
        private final Map<String, String> indexInfo;
        private final long timestamp;
        
        public PerformanceStats(long totalQueries, long totalOptimizations, long lastVacuumTime,
                              long archivedRecords, long databaseSizeBytes, int tableCount,
                              Map<String, Long> tableSizes, Map<String, String> indexInfo) {
            this.totalQueries = totalQueries;
            this.totalOptimizations = totalOptimizations;
            this.lastVacuumTime = lastVacuumTime;
            this.archivedRecords = archivedRecords;
            this.databaseSizeBytes = databaseSizeBytes;
            this.tableCount = tableCount;
            this.tableSizes = new HashMap<>(tableSizes);
            this.indexInfo = new HashMap<>(indexInfo);
            this.timestamp = System.currentTimeMillis();
        }
        
        // Getters
        public long getTotalQueries() { return totalQueries; }
        public long getTotalOptimizations() { return totalOptimizations; }
        public long getLastVacuumTime() { return lastVacuumTime; }
        public long getArchivedRecords() { return archivedRecords; }
        public long getDatabaseSizeBytes() { return databaseSizeBytes; }
        public int getTableCount() { return tableCount; }
        public Map<String, Long> getTableSizes() { return tableSizes; }
        public Map<String, String> getIndexInfo() { return indexInfo; }
        public long getTimestamp() { return timestamp; }
    }
    
    public DatabaseOptimizationService(DatabaseService databaseService) {
        this.databaseService = databaseService;
    }
    
    /**
     * Initialize the optimization service
     */
    public void initialize() {
        if (initialized.getAndSet(true)) {
            logger.warn("DatabaseOptimizationService already initialized");
            return;
        }
        
        if (databaseService == null || !databaseService.isInitialized()) {
            logger.error("Cannot initialize DatabaseOptimizationService - database service not available");
            throw new IllegalStateException("DatabaseService is required for DatabaseOptimizationService");
        }
        
        try {
            // Enable SQLite performance optimizations
            enablePerformanceOptimizations();
            
            // Create archive tables
            createArchiveTables();
            
            // Schedule maintenance tasks
            scheduleMaintenanceTasks();
            
            logger.info("DatabaseOptimizationService initialized successfully");
            
        } catch (Exception e) {
            logger.error("Failed to initialize DatabaseOptimizationService", e);
            initialized.set(false);
            throw new RuntimeException("Failed to initialize DatabaseOptimizationService", e);
        }
    }
    
    /**
     * Perform comprehensive database optimization
     */
    public void performOptimization() {
        if (!isReady()) {
            logger.warn("DatabaseOptimizationService not ready for optimization");
            return;
        }
        
        logger.info("Starting database optimization");
        long startTime = System.currentTimeMillis();
        
        try {
            // 1. Analyze query performance
            analyzeQueryPerformance();
            
            // 2. Update table statistics
            updateTableStatistics();
            
            // 3. Rebuild fragmented indexes
            rebuildIndexes();
            
            // 4. Archive old data
            archiveOldData();
            
            // 5. Vacuum database if needed
            vacuumIfNeeded();
            
            totalOptimizations.incrementAndGet();
            long duration = System.currentTimeMillis() - startTime;
            
            logger.info("Database optimization completed in {}ms", duration);
            
        } catch (Exception e) {
            logger.error("Database optimization failed", e);
            throw new RuntimeException("Database optimization failed", e);
        }
    }
    
    /**
     * Archive old traffic data to reduce main table size
     */
    public long archiveOldData() {
        logger.info("Starting data archival process");
        
        try (Connection conn = databaseService.getConnection()) {
            conn.setAutoCommit(false);
            
            // Calculate cutoff date
            LocalDateTime cutoffDate = LocalDateTime.now().minusDays(ARCHIVE_THRESHOLD_DAYS);
            String cutoffDateStr = cutoffDate.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            
            long archivedCount = 0;
            
            // Archive traffic records
            String archiveTrafficSql = "INSERT INTO traffic_archive " +
                "SELECT * FROM traffic " +
                "WHERE timestamp < ? " +
                "AND id NOT IN (SELECT DISTINCT traffic_id FROM traffic_archive WHERE traffic_id IS NOT NULL)";
            
            try (PreparedStatement stmt = conn.prepareStatement(archiveTrafficSql)) {
                stmt.setString(1, cutoffDateStr);
                archivedCount += stmt.executeUpdate();
            }
            
            // Delete archived records from main table
            String deleteTrafficSql = "DELETE FROM traffic " +
                "WHERE timestamp < ? " +
                "AND id IN (SELECT traffic_id FROM traffic_archive WHERE traffic_id IS NOT NULL)";
            
            try (PreparedStatement stmt = conn.prepareStatement(deleteTrafficSql)) {
                stmt.setString(1, cutoffDateStr);
                stmt.executeUpdate();
            }
            
            // Archive completed scan tasks
            String archiveScanTasksSql = "INSERT INTO scan_tasks_archive " +
                "SELECT * FROM scan_tasks " +
                "WHERE updated_at < ? " +
                "AND status IN ('COMPLETED', 'FAILED', 'CANCELLED') " +
                "AND id NOT IN (SELECT DISTINCT task_id FROM scan_tasks_archive WHERE task_id IS NOT NULL)";
            
            try (PreparedStatement stmt = conn.prepareStatement(archiveScanTasksSql)) {
                stmt.setString(1, cutoffDateStr);
                archivedCount += stmt.executeUpdate();
            }
            
            // Delete archived scan tasks
            String deleteScanTasksSql = "DELETE FROM scan_tasks " +
                "WHERE updated_at < ? " +
                "AND status IN ('COMPLETED', 'FAILED', 'CANCELLED') " +
                "AND id IN (SELECT task_id FROM scan_tasks_archive WHERE task_id IS NOT NULL)";
            
            try (PreparedStatement stmt = conn.prepareStatement(deleteScanTasksSql)) {
                stmt.setString(1, cutoffDateStr);
                stmt.executeUpdate();
            }
            
            conn.commit();
            archivedRecords.addAndGet(archivedCount);
            
            logger.info("Archived {} records older than {}", archivedCount, cutoffDate);
            return archivedCount;
            
        } catch (SQLException e) {
            logger.error("Failed to archive old data", e);
            throw new RuntimeException("Failed to archive old data", e);
        }
    }
    
    /**
     * Perform VACUUM operation to reclaim space and optimize database
     */
    public void performVacuum() {
        logger.info("Starting VACUUM operation");
        long startTime = System.currentTimeMillis();
        
        try (Connection conn = databaseService.getConnection();
             Statement stmt = conn.createStatement()) {
            
            // Get database size before vacuum
            long sizeBefore = getDatabaseSize();
            
            // Perform VACUUM
            stmt.execute("VACUUM");
            
            // Get database size after vacuum
            long sizeAfter = getDatabaseSize();
            long spaceReclaimed = sizeBefore - sizeAfter;
            
            lastVacuumTime.set(System.currentTimeMillis());
            long duration = System.currentTimeMillis() - startTime;
            
            logger.info("VACUUM completed in {}ms, reclaimed {} bytes", duration, spaceReclaimed);
            
        } catch (SQLException e) {
            logger.error("VACUUM operation failed", e);
            throw new RuntimeException("VACUUM operation failed", e);
        }
    }
    
    /**
     * Analyze database and create optimization recommendations
     */
    public List<String> analyzeAndRecommend() {
        List<String> recommendations = new ArrayList<>();
        
        try (Connection conn = databaseService.getConnection()) {
            
            // Check table sizes
            Map<String, Long> tableSizes = getTableSizes(conn);
            tableSizes.forEach((table, size) -> {
                if (size > MAX_RECORDS_PER_PARTITION) {
                    recommendations.add("Table '" + table + "' has " + size + " records. Consider archiving old data.");
                }
            });
            
            // Check for missing indexes
            List<String> missingIndexes = findMissingIndexes(conn);
            if (!missingIndexes.isEmpty()) {
                recommendations.add("Consider adding indexes: " + String.join(", ", missingIndexes));
            }
            
            // Check for fragmentation
            if (shouldVacuum()) {
                recommendations.add("Database fragmentation detected. VACUUM operation recommended.");
            }
            
            // Check archive table usage
            long archivedCount = getArchivedRecordCount();
            if (archivedCount == 0) {
                recommendations.add("No archived data found. Consider enabling automatic archival.");
            }
            
            // Check for slow queries (based on common patterns)
            recommendations.addAll(analyzeSlowQueryPatterns(conn));
            
        } catch (SQLException e) {
            logger.error("Failed to analyze database", e);
            recommendations.add("Database analysis failed: " + e.getMessage());
        }
        
        return recommendations;
    }
    
    /**
     * Get comprehensive performance statistics
     */
    public PerformanceStats getPerformanceStats() {
        try (Connection conn = databaseService.getConnection()) {
            
            Map<String, Long> tableSizes = getTableSizes(conn);
            Map<String, String> indexInfo = getIndexInfo(conn);
            long databaseSize = getDatabaseSize();
            int tableCount = getTableCount(conn);
            
            return new PerformanceStats(
                totalQueries.get(),
                totalOptimizations.get(),
                lastVacuumTime.get(),
                archivedRecords.get(),
                databaseSize,
                tableCount,
                tableSizes,
                indexInfo
            );
            
        } catch (SQLException e) {
            logger.error("Failed to get performance stats", e);
            return new PerformanceStats(0, 0, 0, 0, 0, 0, new HashMap<>(), new HashMap<>());
        }
    }
    
    /**
     * Force immediate optimization of specific table
     */
    public void optimizeTable(String tableName) {
        logger.info("Optimizing table: {}", tableName);
        
        try (Connection conn = databaseService.getConnection();
             Statement stmt = conn.createStatement()) {
            
            // Analyze table
            stmt.execute("ANALYZE " + tableName);
            
            // Rebuild indexes for this table
            ResultSet rs = stmt.executeQuery(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='" + tableName + "'"
            );
            
            while (rs.next()) {
                String indexName = rs.getString("name");
                if (!indexName.startsWith("sqlite_")) { // Skip system indexes
                    stmt.execute("REINDEX " + indexName);
                    logger.debug("Rebuilt index: {}", indexName);
                }
            }
            
            logger.info("Table {} optimization completed", tableName);
            
        } catch (SQLException e) {
            logger.error("Failed to optimize table: {}", tableName, e);
            throw new RuntimeException("Failed to optimize table: " + tableName, e);
        }
    }
    
    /**
     * Shutdown the optimization service
     */
    public void shutdown() {
        if (shutdown.getAndSet(true)) {
            return;
        }
        
        logger.info("DatabaseOptimizationService shutting down");
        
        // Stop maintenance scheduler
        maintenanceScheduler.shutdown();
        try {
            if (!maintenanceScheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                maintenanceScheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            maintenanceScheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
        
        logger.info("DatabaseOptimizationService shutdown completed");
    }
    
    // Private helper methods
    
    private void enablePerformanceOptimizations() throws SQLException {
        try (Connection conn = databaseService.getConnection();
             Statement stmt = conn.createStatement()) {
            
            // Enable Write-Ahead Logging (WAL) mode for better concurrency
            stmt.execute("PRAGMA journal_mode=WAL");
            
            // Set synchronous mode to NORMAL for better performance
            stmt.execute("PRAGMA synchronous=NORMAL");
            
            // Increase cache size (10MB)
            stmt.execute("PRAGMA cache_size=10000");
            
            // Enable memory-mapped I/O (256MB)
            stmt.execute("PRAGMA mmap_size=268435456");
            
            // Set temp store to memory
            stmt.execute("PRAGMA temp_store=memory");
            
            // Optimize foreign key checks
            stmt.execute("PRAGMA foreign_keys=ON");
            
            logger.info("Database performance optimizations enabled");
        }
    }
    
    private void createArchiveTables() throws SQLException {
        try (Connection conn = databaseService.getConnection();
             Statement stmt = conn.createStatement()) {
            
            // Create traffic archive table
            stmt.execute("CREATE TABLE IF NOT EXISTS traffic_archive (" +
                "id INTEGER," +
                "traffic_id INTEGER," +
                "method TEXT," +
                "url TEXT," +
                "host TEXT," +
                "request_headers TEXT," +
                "request_body TEXT," +
                "response_headers TEXT," +
                "response_body TEXT," +
                "status_code INTEGER," +
                "timestamp DATETIME," +
                "session_tag TEXT," +
                "source TEXT," +
                "archived_at DATETIME DEFAULT CURRENT_TIMESTAMP" +
                ")");
            
            // Create scan tasks archive table
            stmt.execute("CREATE TABLE IF NOT EXISTS scan_tasks_archive (" +
                "id TEXT," +
                "task_id TEXT," +
                "task_type TEXT," +
                "status TEXT," +
                "created_at TIMESTAMP," +
                "updated_at TIMESTAMP," +
                "started_at TIMESTAMP," +
                "completed_at TIMESTAMP," +
                "config TEXT," +
                "results TEXT," +
                "error_message TEXT," +
                "session_tag TEXT," +
                "archived_at DATETIME DEFAULT CURRENT_TIMESTAMP" +
                ")");
            
            // Create indexes on archive tables
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_traffic_archive_date ON traffic_archive(archived_at)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_scan_tasks_archive_date ON scan_tasks_archive(archived_at)");
            
            logger.debug("Archive tables created successfully");
        }
    }
    
    private void scheduleMaintenanceTasks() {
        // Schedule vacuum operation
        maintenanceScheduler.scheduleAtFixedRate(
            this::vacuumIfNeeded,
            VACUUM_INTERVAL_HOURS,
            VACUUM_INTERVAL_HOURS,
            TimeUnit.HOURS
        );
        
        // Schedule optimization
        maintenanceScheduler.scheduleAtFixedRate(
            this::performOptimization,
            OPTIMIZATION_INTERVAL_HOURS,
            OPTIMIZATION_INTERVAL_HOURS,
            TimeUnit.HOURS
        );
        
        // Schedule archival
        maintenanceScheduler.scheduleAtFixedRate(
            this::archiveOldData,
            24, // Daily
            24,
            TimeUnit.HOURS
        );
        
        logger.debug("Maintenance tasks scheduled");
    }
    
    private void analyzeQueryPerformance() throws SQLException {
        try (Connection conn = databaseService.getConnection();
             Statement stmt = conn.createStatement()) {
            
            // Update query planner statistics
            stmt.execute("ANALYZE");
            
            totalQueries.incrementAndGet();
            logger.debug("Query performance analysis completed");
        }
    }
    
    private void updateTableStatistics() throws SQLException {
        try (Connection conn = databaseService.getConnection();
             Statement stmt = conn.createStatement()) {
            
            // Get all user tables
            ResultSet rs = stmt.executeQuery(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            );
            
            while (rs.next()) {
                String tableName = rs.getString("name");
                stmt.execute("ANALYZE " + tableName);
            }
            
            logger.debug("Table statistics updated");
        }
    }
    
    private void rebuildIndexes() throws SQLException {
        try (Connection conn = databaseService.getConnection();
             Statement stmt = conn.createStatement()) {
            
            // Get all user indexes
            ResultSet rs = stmt.executeQuery(
                "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'"
            );
            
            List<String> indexes = new ArrayList<>();
            while (rs.next()) {
                indexes.add(rs.getString("name"));
            }
            
            // Rebuild each index
            for (String indexName : indexes) {
                stmt.execute("REINDEX " + indexName);
            }
            
            logger.debug("Rebuilt {} indexes", indexes.size());
        }
    }
    
    private void vacuumIfNeeded() {
        if (shouldVacuum()) {
            performVacuum();
        }
    }
    
    private boolean shouldVacuum() {
        // Vacuum if it's been more than the interval since last vacuum
        long timeSinceLastVacuum = System.currentTimeMillis() - lastVacuumTime.get();
        return timeSinceLastVacuum > TimeUnit.HOURS.toMillis(VACUUM_INTERVAL_HOURS);
    }
    
    private Map<String, Long> getTableSizes(Connection conn) throws SQLException {
        Map<String, Long> sizes = new HashMap<>();
        
        try (Statement stmt = conn.createStatement()) {
            ResultSet rs = stmt.executeQuery(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            );
            
            while (rs.next()) {
                String tableName = rs.getString("name");
                
                try (PreparedStatement countStmt = conn.prepareStatement(
                    "SELECT COUNT(*) as count FROM " + tableName)) {
                    ResultSet countRs = countStmt.executeQuery();
                    if (countRs.next()) {
                        sizes.put(tableName, countRs.getLong("count"));
                    }
                }
            }
        }
        
        return sizes;
    }
    
    private Map<String, String> getIndexInfo(Connection conn) throws SQLException {
        Map<String, String> indexInfo = new HashMap<>();
        
        try (Statement stmt = conn.createStatement()) {
            ResultSet rs = stmt.executeQuery(
                "SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'"
            );
            
            while (rs.next()) {
                String indexName = rs.getString("name");
                String tableName = rs.getString("tbl_name");
                String sql = rs.getString("sql");
                indexInfo.put(indexName, "Table: " + tableName + ", SQL: " + sql);
            }
        }
        
        return indexInfo;
    }
    
    private long getDatabaseSize() {
        try (Connection conn = databaseService.getConnection();
             Statement stmt = conn.createStatement()) {
            
            ResultSet rs = stmt.executeQuery("PRAGMA page_count");
            long pageCount = rs.next() ? rs.getLong(1) : 0;
            
            rs = stmt.executeQuery("PRAGMA page_size");
            long pageSize = rs.next() ? rs.getLong(1) : 0;
            
            return pageCount * pageSize;
            
        } catch (SQLException e) {
            logger.warn("Failed to get database size", e);
            return 0;
        }
    }
    
    private int getTableCount(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            ResultSet rs = stmt.executeQuery(
                "SELECT COUNT(*) as count FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            );
            return rs.next() ? rs.getInt("count") : 0;
        }
    }
    
    private List<String> findMissingIndexes(Connection conn) throws SQLException {
        List<String> suggestions = new ArrayList<>();
        
        // Check for commonly needed indexes
        Map<String, String> potentialIndexes = Map.of(
            "traffic.timestamp", "CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic(timestamp)",
            "traffic.session_tag", "CREATE INDEX IF NOT EXISTS idx_traffic_session_tag ON traffic(session_tag)",
            "traffic.host", "CREATE INDEX IF NOT EXISTS idx_traffic_host ON traffic(host)",
            "scan_tasks.status", "CREATE INDEX IF NOT EXISTS idx_scan_tasks_status ON scan_tasks(status)",
            "scan_tasks.session_tag", "CREATE INDEX IF NOT EXISTS idx_scan_tasks_session_tag ON scan_tasks(session_tag)"
        );
        
        try (Statement stmt = conn.createStatement()) {
            for (Map.Entry<String, String> entry : potentialIndexes.entrySet()) {
                String indexDescription = entry.getKey();
                String createSQL = entry.getValue();
                
                // Extract index name from SQL
                String indexName = createSQL.substring(createSQL.indexOf("idx_"), createSQL.indexOf(" ON"));
                
                // Check if index exists
                ResultSet rs = stmt.executeQuery(
                    "SELECT name FROM sqlite_master WHERE type='index' AND name='" + indexName + "'"
                );
                
                if (!rs.next()) {
                    suggestions.add(indexDescription);
                }
            }
        }
        
        return suggestions;
    }
    
    private List<String> analyzeSlowQueryPatterns(Connection conn) throws SQLException {
        List<String> suggestions = new ArrayList<>();
        
        // Check for tables without proper indexes on commonly queried columns
        Map<String, Long> tableSizes = getTableSizes(conn);
        
        tableSizes.forEach((table, size) -> {
            if (size > 10000) { // Only analyze larger tables
                suggestions.add("Large table '" + table + "' (" + size + " records) - ensure proper indexing on query columns");
            }
        });
        
        return suggestions;
    }
    
    private long getArchivedRecordCount() {
        try (Connection conn = databaseService.getConnection();
             Statement stmt = conn.createStatement()) {
            
            long count = 0;
            
            // Count archived traffic records
            ResultSet rs = stmt.executeQuery("SELECT COUNT(*) as count FROM traffic_archive");
            if (rs.next()) {
                count += rs.getLong("count");
            }
            
            // Count archived scan task records
            rs = stmt.executeQuery("SELECT COUNT(*) as count FROM scan_tasks_archive");
            if (rs.next()) {
                count += rs.getLong("count");
            }
            
            return count;
            
        } catch (SQLException e) {
            logger.warn("Failed to get archived record count", e);
            return 0;
        }
    }
    
    public boolean isReady() {
        return initialized.get() && !shutdown.get() && databaseService != null && databaseService.isInitialized();
    }
}