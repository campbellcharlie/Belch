package com.belch.services;

import com.belch.database.DatabaseService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Database Maintenance Service
 * 
 * Provides automated SQLite performance maintenance:
 * - Periodic ANALYZE for optimal query planning
 * - Scheduled VACUUM for space reclamation
 * - WAL checkpoint management
 * - Index statistics refresh
 * - Performance monitoring and alerts
 * 
 * @author Charlie Campbell
 * @version 1.0.0
 */
public class DatabaseMaintenanceService {
    
    private static final Logger logger = LoggerFactory.getLogger(DatabaseMaintenanceService.class);
    
    // OPTIMAL MAINTENANCE INTERVALS for high-performance systems
    private static final long ANALYZE_INTERVAL_HOURS = 6;     // Every 6 hours
    private static final long VACUUM_INTERVAL_HOURS = 24;     // Daily vacuum
    private static final long CHECKPOINT_INTERVAL_HOURS = 1;  // Hourly WAL checkpoints
    private static final long INDEX_REFRESH_HOURS = 12;       // Twice daily index stats
    
    private final DatabaseService databaseService;
    private final ScheduledExecutorService scheduler;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean shutdown = new AtomicBoolean(false);
    
    // Maintenance statistics
    private final AtomicLong analyzeOperations = new AtomicLong(0);
    private final AtomicLong vacuumOperations = new AtomicLong(0);
    private final AtomicLong checkpointOperations = new AtomicLong(0);
    private final AtomicLong indexRefreshOperations = new AtomicLong(0);
    private volatile LocalDateTime lastAnalyze;
    private volatile LocalDateTime lastVacuum;
    private volatile LocalDateTime lastCheckpoint;
    
    /**
     * Constructor for DatabaseMaintenanceService.
     * 
     * @param databaseService The database service to maintain
     */
    public DatabaseMaintenanceService(DatabaseService databaseService) {
        this.databaseService = databaseService;
        this.scheduler = Executors.newScheduledThreadPool(2, r -> {
            Thread t = new Thread(r, "DatabaseMaintenance");
            t.setDaemon(true);
            return t;
        });
    }
    
    /**
     * Start the maintenance service with scheduled operations.
     */
    public void start() {
        if (running.getAndSet(true)) {
            logger.warn("DatabaseMaintenanceService already running");
            return;
        }
        
        if (databaseService == null || !databaseService.isInitialized()) {
            logger.error("Cannot start maintenance service - database service not available");
            return;
        }
        
        logger.info("Starting Database Maintenance Service...");
        logger.info("   ANALYZE: every {} hours", ANALYZE_INTERVAL_HOURS);
        logger.info("   VACUUM: every {} hours", VACUUM_INTERVAL_HOURS);
        logger.info("   CHECKPOINT: every {} hours", CHECKPOINT_INTERVAL_HOURS);
        logger.info("   INDEX REFRESH: every {} hours", INDEX_REFRESH_HOURS);
        
        // Schedule maintenance operations
        scheduleAnalyzeOperations();
        scheduleVacuumOperations();
        scheduleCheckpointOperations();
        scheduleIndexRefreshOperations();
        
        // Run initial maintenance after startup delay
        scheduler.schedule(this::performInitialMaintenance, 5, TimeUnit.MINUTES);
        
        logger.info("Database Maintenance Service started successfully");
    }
    
    /**
     * Schedule periodic ANALYZE operations for optimal query planning.
     */
    private void scheduleAnalyzeOperations() {
        scheduler.scheduleAtFixedRate(() -> {
            try {
                performAnalyze();
            } catch (Exception e) {
                logger.error("Scheduled ANALYZE operation failed", e);
            }
        }, ANALYZE_INTERVAL_HOURS, ANALYZE_INTERVAL_HOURS, TimeUnit.HOURS);
    }
    
    /**
     * Schedule periodic VACUUM operations for space reclamation.
     */
    private void scheduleVacuumOperations() {
        scheduler.scheduleAtFixedRate(() -> {
            try {
                performVacuum();
            } catch (Exception e) {
                logger.error("Scheduled VACUUM operation failed", e);
            }
        }, VACUUM_INTERVAL_HOURS, VACUUM_INTERVAL_HOURS, TimeUnit.HOURS);
    }
    
    /**
     * Schedule periodic WAL checkpoint operations.
     */
    private void scheduleCheckpointOperations() {
        scheduler.scheduleAtFixedRate(() -> {
            try {
                performCheckpoint();
            } catch (Exception e) {
                logger.error("Scheduled CHECKPOINT operation failed", e);
            }
        }, CHECKPOINT_INTERVAL_HOURS, CHECKPOINT_INTERVAL_HOURS, TimeUnit.HOURS);
    }
    
    /**
     * Schedule periodic index statistics refresh.
     */
    private void scheduleIndexRefreshOperations() {
        scheduler.scheduleAtFixedRate(() -> {
            try {
                performIndexRefresh();
            } catch (Exception e) {
                logger.error("Scheduled INDEX REFRESH operation failed", e);
            }
        }, INDEX_REFRESH_HOURS, INDEX_REFRESH_HOURS, TimeUnit.HOURS);
    }
    
    /**
     * Perform initial maintenance operations after startup.
     */
    private void performInitialMaintenance() {
        logger.info("Performing initial database maintenance...");
        
        try {
            // Light maintenance on startup
            performCheckpoint();
            performIndexRefresh();
            
            logger.info("Initial maintenance completed");
        } catch (Exception e) {
            logger.error("Initial maintenance failed", e);
        }
    }
    
    /**
     * Perform ANALYZE operation to update query planner statistics.
     */
    public void performAnalyze() {
        if (shutdown.get()) return;
        
        logger.info("Starting ANALYZE operation...");
        long startTime = System.currentTimeMillis();
        
        try (Connection conn = databaseService.getConnection();
             Statement stmt = conn.createStatement()) {
            
            // Analyze all tables for optimal query planning
            stmt.execute("ANALYZE");
            
            long duration = System.currentTimeMillis() - startTime;
            analyzeOperations.incrementAndGet();
            lastAnalyze = LocalDateTime.now();
            
            logger.info("ANALYZE completed in {}ms - query planner statistics updated", duration);
            
        } catch (SQLException e) {
            logger.error("ANALYZE operation failed", e);
        }
    }
    
    /**
     * Perform VACUUM operation to reclaim space and defragment.
     */
    public void performVacuum() {
        if (shutdown.get()) return;
        
        logger.info("Starting VACUUM operation...");
        long startTime = System.currentTimeMillis();
        
        try (Connection conn = databaseService.getConnection();
             Statement stmt = conn.createStatement()) {
            
            // Get database size before vacuum
            long sizeBefore = getDatabaseSize(stmt);
            
            // Perform vacuum operation
            stmt.execute("VACUUM");
            
            // Get database size after vacuum
            long sizeAfter = getDatabaseSize(stmt);
            long spaceReclaimed = sizeBefore - sizeAfter;
            
            long duration = System.currentTimeMillis() - startTime;
            vacuumOperations.incrementAndGet();
            lastVacuum = LocalDateTime.now();
            
            logger.info("VACUUM completed in {}ms - reclaimed {} KB", 
                       duration, spaceReclaimed / 1024);
            
        } catch (SQLException e) {
            logger.error("VACUUM operation failed", e);
        }
    }
    
    /**
     * Perform WAL checkpoint to move data from WAL to main database.
     */
    public void performCheckpoint() {
        if (shutdown.get()) return;
        
        logger.debug("Starting WAL CHECKPOINT...");
        long startTime = System.currentTimeMillis();
        
        try (Connection conn = databaseService.getConnection();
             Statement stmt = conn.createStatement()) {
            
            // Perform checkpoint operation
            stmt.execute("PRAGMA wal_checkpoint(TRUNCATE)");
            
            long duration = System.currentTimeMillis() - startTime;
            checkpointOperations.incrementAndGet();
            lastCheckpoint = LocalDateTime.now();
            
            logger.debug("WAL CHECKPOINT completed in {}ms", duration);
            
        } catch (SQLException e) {
            logger.error("WAL CHECKPOINT failed", e);
        }
    }
    
    /**
     * Refresh index statistics for optimal performance.
     */
    public void performIndexRefresh() {
        if (shutdown.get()) return;
        
        logger.debug("Refreshing index statistics...");
        long startTime = System.currentTimeMillis();
        
        try (Connection conn = databaseService.getConnection();
             Statement stmt = conn.createStatement()) {
            
            // Optimize indexes and refresh statistics
            stmt.execute("PRAGMA optimize");
            
            long duration = System.currentTimeMillis() - startTime;
            indexRefreshOperations.incrementAndGet();
            
            logger.debug("Index statistics refreshed in {}ms", duration);
            
        } catch (SQLException e) {
            logger.error("Index refresh failed", e);
        }
    }
    
    /**
     * Get database size in bytes.
     */
    private long getDatabaseSize(Statement stmt) {
        try {
            var rs = stmt.executeQuery("PRAGMA page_count");
            if (rs.next()) {
                long pageCount = rs.getLong(1);
                rs.close();
                
                rs = stmt.executeQuery("PRAGMA page_size");
                if (rs.next()) {
                    long pageSize = rs.getLong(1);
                    return pageCount * pageSize;
                }
            }
        } catch (SQLException e) {
            logger.debug("Could not get database size: {}", e.getMessage());
        }
        return 0;
    }
    
    /**
     * Get maintenance statistics.
     */
    public MaintenanceStats getStats() {
        return new MaintenanceStats(
            analyzeOperations.get(),
            vacuumOperations.get(),
            checkpointOperations.get(),
            indexRefreshOperations.get(),
            lastAnalyze,
            lastVacuum,
            lastCheckpoint
        );
    }
    
    /**
     * Check if maintenance service is healthy.
     */
    public boolean isHealthy() {
        return running.get() && !shutdown.get() && !scheduler.isShutdown();
    }
    
    /**
     * Shutdown the maintenance service.
     */
    public void shutdown() {
        if (!shutdown.getAndSet(true)) {
            logger.info("Shutting down Database Maintenance Service...");
            
            running.set(false);
            scheduler.shutdown();
            
            try {
                if (!scheduler.awaitTermination(10, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                scheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
            
            logger.info("Database Maintenance Service shutdown complete");
        }
    }
    
    /**
     * Maintenance statistics for monitoring.
     */
    public static class MaintenanceStats {
        public final long analyzeOperations;
        public final long vacuumOperations;
        public final long checkpointOperations;
        public final long indexRefreshOperations;
        public final LocalDateTime lastAnalyze;
        public final LocalDateTime lastVacuum;
        public final LocalDateTime lastCheckpoint;
        
        public MaintenanceStats(long analyzeOps, long vacuumOps, long checkpointOps, long indexRefreshOps,
                               LocalDateTime lastAnalyze, LocalDateTime lastVacuum, LocalDateTime lastCheckpoint) {
            this.analyzeOperations = analyzeOps;
            this.vacuumOperations = vacuumOps;
            this.checkpointOperations = checkpointOps;
            this.indexRefreshOperations = indexRefreshOps;
            this.lastAnalyze = lastAnalyze;
            this.lastVacuum = lastVacuum;
            this.lastCheckpoint = lastCheckpoint;
        }
        
        @Override
        public String toString() {
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
            return String.format("MaintenanceStats{analyze=%d, vacuum=%d, checkpoint=%d, indexRefresh=%d, " +
                               "lastAnalyze=%s, lastVacuum=%s, lastCheckpoint=%s}",
                               analyzeOperations, vacuumOperations, checkpointOperations, indexRefreshOperations,
                               lastAnalyze != null ? lastAnalyze.format(formatter) : "never",
                               lastVacuum != null ? lastVacuum.format(formatter) : "never",
                               lastCheckpoint != null ? lastCheckpoint.format(formatter) : "never");
        }
    }
}