package com.belch.database.schema;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Manages database schema creation and migrations with normalized tables.
 * Features:
 * - Normalized schema: traffic_meta, traffic_requests, traffic_responses
 * - Versioned migrations using Map<Integer, Runnable>
 * - Thread-safe and idempotent operations
 * - Optimized indexes for high-performance queries
 * - Optional FTS5 full-text search support
 * 
 * @author Charlie Campbell
 * @version 2.0.0
 */
public class SchemaManager {
    
    private static final Logger logger = LoggerFactory.getLogger(SchemaManager.class);
    
    // Schema version - updated to 11 for enhancements
    private static final int CURRENT_SCHEMA_VERSION = 11;
    
    // Thread safety
    private final ReentrantLock migrationLock = new ReentrantLock();
    private final Map<String, Boolean> appliedMigrations = new ConcurrentHashMap<>();
    
    // Migration registry - maps version to migration logic
    private final Map<Integer, MigrationTask> migrations = new HashMap<>();
    
    /**
     * Interface for migration tasks to ensure consistency
     */
    @FunctionalInterface
    private interface MigrationTask {
        void execute(Connection connection) throws SQLException;
    }
    
    public SchemaManager() {
        initializeMigrations();
    }
    
    /**
     * Initialize all migrations in the registry
     */
    private void initializeMigrations() {
        // Legacy migrations (1-5) for backwards compatibility
        migrations.put(1, this::applyMigrationV1_Legacy);
        migrations.put(2, this::applyMigrationV2_Legacy);
        migrations.put(3, this::applyMigrationV3_Legacy);
        migrations.put(4, this::applyMigrationV4_Legacy);
        migrations.put(5, this::applyMigrationV5_Legacy);
        
        // New normalized schema migrations (6-10)
        migrations.put(6, this::applyMigrationV6_CreateTrafficMeta);
        migrations.put(7, this::applyMigrationV7_CreateRequestsTable);
        migrations.put(8, this::applyMigrationV8_CreateResponsesTable);
        migrations.put(9, this::applyMigrationV9_MigrateDataAndIndexes);
        migrations.put(10, this::applyMigrationV10_CreateFTS5AndCleanup);
        
        // enhancement migrations (11+)
        migrations.put(11, this::applyMigrationV11_PhaseEnhancements);
    }
    
    /**
     * Initializes the database schema with thread safety.
     * Creates tables if they don't exist and handles migrations.
     * 
     * @param connection The database connection
     * @throws SQLException if there's an error with database operations
     */
    public void initializeSchema(Connection connection) throws SQLException {
        migrationLock.lock();
        try {
            logger.info("🚀 Starting database schema initialization (target version: {})", CURRENT_SCHEMA_VERSION);
            
            // Create schema version table if it doesn't exist
            logger.info("📋 Creating schema version table...");
            createSchemaVersionTable(connection);
            logger.info("✅ Schema version table created successfully");
            
            // Get current schema version
            int currentVersion = getCurrentSchemaVersion(connection);
            logger.info("📊 Current schema version: {}", currentVersion);
            
            // Apply migrations if needed
            if (currentVersion < CURRENT_SCHEMA_VERSION) {
                logger.info("🔄 Schema upgrade needed: {} -> {}", currentVersion, CURRENT_SCHEMA_VERSION);
                applyMigrations(connection, currentVersion);
            } else {
                logger.info("✅ Schema is up to date (version {})", currentVersion);
            }
            
            // Verify schema integrity
            verifySchemaIntegrity(connection);
            
            logger.info("🎉 Schema initialization completed successfully");
            
        } catch (SQLException e) {
            logger.error("❌ CRITICAL: Schema initialization failed", e);
            logger.error("SQL State: {}, Error Code: {}", e.getSQLState(), e.getErrorCode());
            throw e;
        } catch (Exception e) {
            logger.error("❌ CRITICAL: Unexpected error during schema initialization", e);
            throw new SQLException("Schema initialization failed: " + e.getMessage(), e);
        } finally {
            migrationLock.unlock();
        }
    }
    
    /**
     * Creates the schema version table (idempotent).
     */
    private void createSchemaVersionTable(Connection connection) throws SQLException {
        // Check if schema_version table exists
        if (!tableExists(connection, "schema_version")) {
            // Create new table with all columns
            String sql = "CREATE TABLE schema_version (" +
                        "version INTEGER PRIMARY KEY, " +
                        "applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                        "description TEXT" +
                        ")";
            
            try (Statement stmt = connection.createStatement()) {
                stmt.execute(sql);
                logger.info("Created new schema_version table");
            }
        } else {
            // Table exists, check if it has the description column
            if (!columnExists(connection, "schema_version", "description")) {
                logger.info("Upgrading existing schema_version table structure");
                
                try (Statement stmt = connection.createStatement()) {
                    // Add missing columns
                    stmt.execute("ALTER TABLE schema_version ADD COLUMN description TEXT");
                    stmt.execute("ALTER TABLE schema_version ADD COLUMN applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP");
                    logger.info("✅ Schema_version table structure upgraded");
                } catch (SQLException e) {
                    // If alter fails (column already exists), that's fine
                    logger.debug("Column may already exist: {}", e.getMessage());
                }
            }
        }
    }
    
    /**
     * Gets the current schema version from the database.
     */
    private int getCurrentSchemaVersion(Connection connection) throws SQLException {
        String sql = "SELECT MAX(version) as version FROM schema_version";
        
        try (PreparedStatement stmt = connection.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {
            
            if (rs.next()) {
                int version = rs.getInt("version");
                return rs.wasNull() ? 0 : version;
            }
        }
        
        return 0;
    }
    
    /**
     * Applies schema migrations from the current version to the latest.
     * Each migration is idempotent and thread-safe.
     */
    private void applyMigrations(Connection connection, int fromVersion) throws SQLException {
        logger.info("Applying schema migrations from version {} to {}", fromVersion, CURRENT_SCHEMA_VERSION);
        
        // Use transaction for migration safety
        boolean originalAutoCommit = connection.getAutoCommit();
        connection.setAutoCommit(false);
        
        try {
            for (int version = fromVersion + 1; version <= CURRENT_SCHEMA_VERSION; version++) {
                String migrationKey = "migration_v" + version;
                
                // Skip if already applied (idempotency check)
                if (appliedMigrations.containsKey(migrationKey)) {
                    logger.debug("Migration v{} already applied, skipping", version);
                    continue;
                }
                
                logger.info("Applying migration to version {}", version);
                
                MigrationTask migration = migrations.get(version);
                if (migration == null) {
                    throw new SQLException("Unknown migration version: " + version);
                }
                
                // Execute migration
                migration.execute(connection);
                
                // Update schema version
                updateSchemaVersion(connection, version, getMigrationDescription(version));
                
                // Mark as applied
                appliedMigrations.put(migrationKey, true);
                
                logger.info("✅ Migration v{} completed successfully", version);
            }
            
            connection.commit();
        } catch (SQLException e) {
            logger.error("❌ Migration failed, rolling back", e);
            connection.rollback();
            throw e;
        } finally {
            connection.setAutoCommit(originalAutoCommit);
        }
    }
    
    /**
     * Get migration description for logging
     */
    private String getMigrationDescription(int version) {
        switch (version) {
            case 1: return "Legacy: Initial proxy_traffic table";
            case 2: return "Legacy: Schema optimizations";
            case 3: return "Legacy: Scope cache table";
            case 4: return "Legacy: Deduplication features";
            case 5: return "Legacy: Traffic source tracking";
            case 6: return "Create normalized traffic_meta table";
            case 7: return "Create traffic_requests table";
            case 8: return "Create traffic_responses table";
            case 9: return "Migrate data and create optimized indexes";
            case 10: return "Create FTS5 search and cleanup";
            case 11: return "enhancements: metadata, tagging, saved queries, request FTS";
            default: return "Unknown migration";
        }
    }
    
    //=================================================================================
    // LEGACY MIGRATIONS (1-5) - For backwards compatibility
    //=================================================================================
    
    private void applyMigrationV1_Legacy(Connection connection) throws SQLException {
        logger.info("🔨 Applying Legacy Migration V1: Creating proxy_traffic table");
        
        String createTableSql = "CREATE TABLE IF NOT EXISTS proxy_traffic (" +
                               "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                               "timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, " +
                               "method VARCHAR(10) NOT NULL, " +
                               "url TEXT NOT NULL, " +
                               "host VARCHAR(255) NOT NULL, " +
                               "status_code INTEGER, " +
                               "headers TEXT, " +
                               "body TEXT, " +
                               "response_headers TEXT, " +
                               "response_body TEXT, " +
                               "session_tag VARCHAR(100) DEFAULT '' " +
                               ")";
        
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(createTableSql);
            
            // Basic indexes
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_legacy_timestamp ON proxy_traffic(timestamp)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_legacy_url ON proxy_traffic(url)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_legacy_host ON proxy_traffic(host)");
        }
    }
    
    private void applyMigrationV2_Legacy(Connection connection) throws SQLException {
        logger.info("🔨 Applying Legacy Migration V2: Optimizations");
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("ANALYZE proxy_traffic");
            stmt.execute("PRAGMA optimize");
        }
    }
    
    private void applyMigrationV3_Legacy(Connection connection) throws SQLException {
        logger.info("🔨 Applying Legacy Migration V3: Scope cache");
        String sql = "CREATE TABLE IF NOT EXISTS scope_cache (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "url TEXT NOT NULL UNIQUE, " +
                    "in_scope BOOLEAN NOT NULL, " +
                    "last_checked TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP" +
                    ")";
        
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(sql);
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_scope_cache_url ON scope_cache(url)");
        }
    }
    
    private void applyMigrationV4_Legacy(Connection connection) throws SQLException {
        logger.info("🔨 Applying Legacy Migration V4: Deduplication");
        try (Statement stmt = connection.createStatement()) {
            // Add content_hash column if it doesn't exist
            try {
                stmt.execute("ALTER TABLE proxy_traffic ADD COLUMN content_hash TEXT");
            } catch (SQLException e) {
                if (!e.getMessage().contains("duplicate column name")) {
                    throw e;
                }
            }
            
            // Create deduplication log table
            String dedupeSql = "CREATE TABLE IF NOT EXISTS deduplication_log (" +
                             "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                             "operation_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, " +
                             "operation_type VARCHAR(50) NOT NULL, " +
                             "records_processed INTEGER NOT NULL, " +
                             "duplicates_found INTEGER NOT NULL, " +
                             "duplicates_removed INTEGER NOT NULL, " +
                             "session_tag VARCHAR(100)" +
                             ")";
            stmt.execute(dedupeSql);
        }
    }
    
    private void applyMigrationV5_Legacy(Connection connection) throws SQLException {
        logger.info("🔨 Applying Legacy Migration V5: Traffic source");
        try (Statement stmt = connection.createStatement()) {
            try {
                stmt.execute("ALTER TABLE proxy_traffic ADD COLUMN traffic_source VARCHAR(20) DEFAULT 'UNKNOWN'");
            } catch (SQLException e) {
                if (!e.getMessage().contains("duplicate column name")) {
                    throw e;
                }
            }
        }
    }
    
    //=================================================================================
    // NEW NORMALIZED SCHEMA MIGRATIONS (6-10)
    //=================================================================================
    
    /**
     * Migration V6: Create normalized traffic_meta table
     */
    private void applyMigrationV6_CreateTrafficMeta(Connection connection) throws SQLException {
        logger.info("🔨 Applying Migration V6: Creating normalized traffic_meta table");
        
        String sql = "CREATE TABLE IF NOT EXISTS traffic_meta (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, " +
                    "session_tag VARCHAR(100) NOT NULL DEFAULT '', " +
                    "tool_source VARCHAR(20) NOT NULL DEFAULT 'UNKNOWN', " +
                    "replayed_flag BOOLEAN NOT NULL DEFAULT 0, " +
                    "content_hash TEXT, " +
                    "url TEXT NOT NULL, " +
                    "host VARCHAR(255) NOT NULL, " +
                    "method VARCHAR(10) NOT NULL, " +
                    "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, " +
                    "updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP" +
                    ")";
        
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(sql);
            logger.info("✅ traffic_meta table created successfully");
        }
    }
    
    /**
     * Migration V7: Create traffic_requests table
     */
    private void applyMigrationV7_CreateRequestsTable(Connection connection) throws SQLException {
        logger.info("🔨 Applying Migration V7: Creating traffic_requests table");
        
        String sql = "CREATE TABLE IF NOT EXISTS traffic_requests (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "traffic_meta_id INTEGER NOT NULL, " +
                    "headers TEXT, " +
                    "body TEXT, " +
                    "body_size INTEGER DEFAULT 0, " +
                    "content_type VARCHAR(100), " +
                    "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, " +
                    "FOREIGN KEY (traffic_meta_id) REFERENCES traffic_meta(id) ON DELETE CASCADE" +
                    ")";
        
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(sql);
            logger.info("✅ traffic_requests table created successfully");
        }
    }
    
    /**
     * Migration V8: Create traffic_responses table
     */
    private void applyMigrationV8_CreateResponsesTable(Connection connection) throws SQLException {
        logger.info("🔨 Applying Migration V8: Creating traffic_responses table");
        
        String sql = "CREATE TABLE IF NOT EXISTS traffic_responses (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "traffic_meta_id INTEGER NOT NULL, " +
                    "status_code INTEGER, " +
                    "headers TEXT, " +
                    "body TEXT, " +
                    "body_size INTEGER DEFAULT 0, " +
                    "content_type VARCHAR(100), " +
                    "response_time_ms INTEGER DEFAULT 0, " +
                    "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, " +
                    "FOREIGN KEY (traffic_meta_id) REFERENCES traffic_meta(id) ON DELETE CASCADE" +
                    ")";
        
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(sql);
            logger.info("✅ traffic_responses table created successfully");
        }
    }
    
    /**
     * Migration V9: Create optimized indexes and migrate existing data
     */
    private void applyMigrationV9_MigrateDataAndIndexes(Connection connection) throws SQLException {
        logger.info("🔨 Applying Migration V9: Creating indexes and migrating data");
        
        try (Statement stmt = connection.createStatement()) {
            // Create comprehensive indexes for performance
            createOptimizedIndexes(connection);
            
            // Migrate existing data from proxy_traffic to normalized tables
            migrateExistingData(connection);
            
            logger.info("✅ Indexes created and data migrated successfully");
        }
    }
    
    /**
     * Migration V10: Create FTS5 table and cleanup
     */
    private void applyMigrationV10_CreateFTS5AndCleanup(Connection connection) throws SQLException {
        logger.info("🔨 Applying Migration V10: Creating FTS5 search and cleanup");
        
        try (Statement stmt = connection.createStatement()) {
            // Check if FTS5 is available
            if (isFTS5Available(connection)) {
                createFTS5SearchTable(connection);
            } else {
                logger.warn("FTS5 not available, skipping full-text search setup");
            }
            
            // Final optimizations
            stmt.execute("ANALYZE");
            stmt.execute("PRAGMA optimize");
            
            logger.info("✅ FTS5 setup and cleanup completed");
        }
    }
    
    /**
     * Migration V11: enhancements - metadata, tagging, saved queries, request FTS
     */
    private void applyMigrationV11_PhaseEnhancements(Connection connection) throws SQLException {
        logger.info("🔨 Applying Migration V11: API refinement and extensibility enhancements");
        
        try (Statement stmt = connection.createStatement()) {
            // Add new columns to traffic_meta table
            logger.info("📝 Adding metadata columns to traffic_meta table");
            
            // Add tags column (JSON or CSV format)
            if (!columnExists(connection, "traffic_meta", "tags")) {
                stmt.execute("ALTER TABLE traffic_meta ADD COLUMN tags TEXT");
                logger.info("✅ Added tags column to traffic_meta");
            }
            
            // Add comment column for analyst notes
            if (!columnExists(connection, "traffic_meta", "comment")) {
                stmt.execute("ALTER TABLE traffic_meta ADD COLUMN comment TEXT");
                logger.info("✅ Added comment column to traffic_meta");
            }
            
            // Add replayed_from column for replay lineage tracking
            if (!columnExists(connection, "traffic_meta", "replayed_from")) {
                stmt.execute("ALTER TABLE traffic_meta ADD COLUMN replayed_from INTEGER REFERENCES traffic_meta(id)");
                logger.info("✅ Added replayed_from column to traffic_meta");
            }
            
            // Create saved_queries table for query presets
            logger.info("📋 Creating saved_queries table");
            String createSavedQueriesTable = "CREATE TABLE IF NOT EXISTS saved_queries (" +
                                           "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                                           "name VARCHAR(255) NOT NULL UNIQUE, " +
                                           "description TEXT, " +
                                           "query_params TEXT NOT NULL, " + // JSON format
                                           "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                                           "updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                                           "session_tag VARCHAR(255)" +
                                           ")";
            stmt.execute(createSavedQueriesTable);
            logger.info("✅ Created saved_queries table");
            
            // Create request_index FTS5 table for request body search
            if (isFTS5Available(connection)) {
                logger.info("📝 Creating FTS5 request index for request body search");
                
                String createRequestIndexSql = "CREATE VIRTUAL TABLE IF NOT EXISTS request_index USING fts5(" +
                                              "traffic_meta_id, " +
                                              "request_headers, " +
                                              "request_body, " +
                                              "url, " +
                                              "method, " +
                                              "content='traffic_requests', " +
                                              "content_rowid='id'" +
                                              ")";
                stmt.execute(createRequestIndexSql);
                
                // Create triggers for request_index
                String insertTrigger = "CREATE TRIGGER IF NOT EXISTS request_index_insert AFTER INSERT ON traffic_requests BEGIN " +
                                      "INSERT INTO request_index(traffic_meta_id, request_headers, request_body, url, method) " +
                                      "SELECT NEW.traffic_meta_id, NEW.headers, NEW.body, tm.url, tm.method " +
                                      "FROM traffic_meta tm WHERE tm.id = NEW.traffic_meta_id; END;";
                
                String deleteTrigger = "CREATE TRIGGER IF NOT EXISTS request_index_delete AFTER DELETE ON traffic_requests BEGIN " +
                                      "DELETE FROM request_index WHERE rowid = OLD.id; END;";
                
                String updateTrigger = "CREATE TRIGGER IF NOT EXISTS request_index_update AFTER UPDATE ON traffic_requests BEGIN " +
                                      "DELETE FROM request_index WHERE rowid = OLD.id; " +
                                      "INSERT INTO request_index(traffic_meta_id, request_headers, request_body, url, method) " +
                                      "SELECT NEW.traffic_meta_id, NEW.headers, NEW.body, tm.url, tm.method " +
                                      "FROM traffic_meta tm WHERE tm.id = NEW.traffic_meta_id; END;";
                
                stmt.execute(insertTrigger);
                stmt.execute(deleteTrigger);
                stmt.execute(updateTrigger);
                
                // Populate request_index with existing data
                String populateRequestIndexSql = "INSERT INTO request_index(traffic_meta_id, request_headers, request_body, url, method) " +
                                               "SELECT tr.traffic_meta_id, tr.headers, tr.body, tm.url, tm.method " +
                                               "FROM traffic_requests tr " +
                                               "JOIN traffic_meta tm ON tm.id = tr.traffic_meta_id";
                
                int populatedRequests = stmt.executeUpdate(populateRequestIndexSql);
                logger.info("✅ Created request_index FTS5 table and populated with {} records", populatedRequests);
            } else {
                logger.warn("FTS5 not available, skipping request body search index creation");
            }
            
            // Create indexes for new columns
            logger.info("📊 Creating indexes for new metadata columns");
            String[] newIndexes = {
                "CREATE INDEX IF NOT EXISTS idx_traffic_meta_tags ON traffic_meta(tags)",
                "CREATE INDEX IF NOT EXISTS idx_traffic_meta_replayed_from ON traffic_meta(replayed_from)",
                "CREATE INDEX IF NOT EXISTS idx_saved_queries_name ON saved_queries(name)",
                "CREATE INDEX IF NOT EXISTS idx_saved_queries_session_tag ON saved_queries(session_tag)",
                "CREATE INDEX IF NOT EXISTS idx_saved_queries_created_at ON saved_queries(created_at)"
            };
            
            for (String indexSql : newIndexes) {
                try {
                    stmt.execute(indexSql);
                } catch (SQLException e) {
                    logger.warn("Failed to create index: {}, error: {}", indexSql, e.getMessage());
                }
            }
            
            // Final optimizations
            stmt.execute("ANALYZE");
            stmt.execute("PRAGMA optimize");
            
            logger.info("✅ enhancements migration completed successfully");
        }
    }
    
    /**
     * Create optimized indexes for high-performance queries
     */
    private void createOptimizedIndexes(Connection connection) throws SQLException {
        logger.info("📊 Creating optimized database indexes");
        
        String[] indexes = {
            // traffic_meta indexes
            "CREATE INDEX IF NOT EXISTS idx_traffic_meta_timestamp ON traffic_meta(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_traffic_meta_session_tag ON traffic_meta(session_tag)",
            "CREATE INDEX IF NOT EXISTS idx_traffic_meta_tool_source ON traffic_meta(tool_source)",
            "CREATE INDEX IF NOT EXISTS idx_traffic_meta_content_hash ON traffic_meta(content_hash)",
            "CREATE INDEX IF NOT EXISTS idx_traffic_meta_url ON traffic_meta(url)",
            "CREATE INDEX IF NOT EXISTS idx_traffic_meta_host ON traffic_meta(host)",
            "CREATE INDEX IF NOT EXISTS idx_traffic_meta_method ON traffic_meta(method)",
            "CREATE INDEX IF NOT EXISTS idx_traffic_meta_replayed ON traffic_meta(replayed_flag)",
            
            // Composite indexes for common query patterns
            "CREATE INDEX IF NOT EXISTS idx_traffic_meta_host_timestamp ON traffic_meta(host, timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_traffic_meta_session_tool ON traffic_meta(session_tag, tool_source)",
            "CREATE INDEX IF NOT EXISTS idx_traffic_meta_method_status ON traffic_meta(method, timestamp)",
            
            // traffic_requests indexes
            "CREATE INDEX IF NOT EXISTS idx_traffic_requests_meta_id ON traffic_requests(traffic_meta_id)",
            "CREATE INDEX IF NOT EXISTS idx_traffic_requests_content_type ON traffic_requests(content_type)",
            "CREATE INDEX IF NOT EXISTS idx_traffic_requests_body_size ON traffic_requests(body_size)",
            
            // traffic_responses indexes
            "CREATE INDEX IF NOT EXISTS idx_traffic_responses_meta_id ON traffic_responses(traffic_meta_id)",
            "CREATE INDEX IF NOT EXISTS idx_traffic_responses_status_code ON traffic_responses(status_code)",
            "CREATE INDEX IF NOT EXISTS idx_traffic_responses_content_type ON traffic_responses(content_type)",
            "CREATE INDEX IF NOT EXISTS idx_traffic_responses_body_size ON traffic_responses(body_size)",
            "CREATE INDEX IF NOT EXISTS idx_traffic_responses_response_time ON traffic_responses(response_time_ms)",
            
            // Composite indexes for responses
            "CREATE INDEX IF NOT EXISTS idx_traffic_responses_status_time ON traffic_responses(status_code, response_time_ms)"
        };
        
        try (Statement stmt = connection.createStatement()) {
            for (String indexSql : indexes) {
                try {
                    stmt.execute(indexSql);
                } catch (SQLException e) {
                    logger.warn("Failed to create index: {}, error: {}", indexSql, e.getMessage());
                }
            }
        }
        
        logger.info("✅ Optimized indexes created successfully");
    }
    
    /**
     * Migrate existing data from legacy proxy_traffic table to normalized tables
     */
    private void migrateExistingData(Connection connection) throws SQLException {
        // Check if legacy table exists and has data
        if (!tableExists(connection, "proxy_traffic")) {
            logger.info("No legacy proxy_traffic table found, skipping migration");
            return;
        }
        
        String countSql = "SELECT COUNT(*) FROM proxy_traffic";
        try (PreparedStatement stmt = connection.prepareStatement(countSql);
             ResultSet rs = stmt.executeQuery()) {
            if (rs.next() && rs.getInt(1) == 0) {
                logger.info("Legacy proxy_traffic table is empty, skipping migration");
                return;
            }
        }
        
        logger.info("🔄 Migrating existing data from proxy_traffic to normalized tables");
        
        // Migration query - insert into traffic_meta and related tables
        String migrationSql = "INSERT INTO traffic_meta (timestamp, session_tag, tool_source, url, host, method, content_hash) " +
                             "SELECT timestamp, session_tag, COALESCE(traffic_source, 'UNKNOWN'), url, host, method, content_hash " +
                             "FROM proxy_traffic WHERE NOT EXISTS (" +
                             "  SELECT 1 FROM traffic_meta tm WHERE tm.content_hash = proxy_traffic.content_hash" +
                             ")";
        
        try (Statement stmt = connection.createStatement()) {
            int migrated = stmt.executeUpdate(migrationSql);
            logger.info("Migrated {} records to traffic_meta", migrated);
            
            // Migrate request data
            migrateRequestData(connection);
            
            // Migrate response data
            migrateResponseData(connection);
            
            logger.info("✅ Data migration completed successfully");
        }
    }
    
    private void migrateRequestData(Connection connection) throws SQLException {
        String sql = "INSERT INTO traffic_requests (traffic_meta_id, headers, body, body_size, content_type) " +
                    "SELECT tm.id, pt.headers, pt.body, " +
                    "COALESCE(LENGTH(pt.body), 0), " +
                    "CASE WHEN pt.headers LIKE '%Content-Type:%' " +
                    "     THEN TRIM(SUBSTR(pt.headers, INSTR(LOWER(pt.headers), 'content-type:') + 13, 100)) " +
                    "     ELSE 'unknown' END " +
                    "FROM proxy_traffic pt " +
                    "JOIN traffic_meta tm ON tm.content_hash = pt.content_hash " +
                    "WHERE NOT EXISTS (SELECT 1 FROM traffic_requests tr WHERE tr.traffic_meta_id = tm.id)";
        
        try (Statement stmt = connection.createStatement()) {
            int migrated = stmt.executeUpdate(sql);
            logger.info("Migrated {} request records", migrated);
        }
    }
    
    private void migrateResponseData(Connection connection) throws SQLException {
        String sql = "INSERT INTO traffic_responses (traffic_meta_id, status_code, headers, body, body_size, content_type) " +
                    "SELECT tm.id, pt.status_code, pt.response_headers, pt.response_body, " +
                    "COALESCE(LENGTH(pt.response_body), 0), " +
                    "CASE WHEN pt.response_headers LIKE '%Content-Type:%' " +
                    "     THEN TRIM(SUBSTR(pt.response_headers, INSTR(LOWER(pt.response_headers), 'content-type:') + 13, 100)) " +
                    "     ELSE 'unknown' END " +
                    "FROM proxy_traffic pt " +
                    "JOIN traffic_meta tm ON tm.content_hash = pt.content_hash " +
                    "WHERE pt.status_code IS NOT NULL " +
                    "AND NOT EXISTS (SELECT 1 FROM traffic_responses tr WHERE tr.traffic_meta_id = tm.id)";
        
        try (Statement stmt = connection.createStatement()) {
            int migrated = stmt.executeUpdate(sql);
            logger.info("Migrated {} response records", migrated);
        }
    }
    
    /**
     * Check if FTS5 is available in this SQLite build
     */
    private boolean isFTS5Available(Connection connection) throws SQLException {
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery("PRAGMA compile_options")) {
            
            while (rs.next()) {
                String option = rs.getString(1);
                if (option.contains("FTS5")) {
                    return true;
                }
            }
        } catch (SQLException e) {
            logger.debug("Could not check FTS5 availability: {}", e.getMessage());
        }
        
        return false;
    }
    
    /**
     * Create FTS5 virtual table for full-text search
     */
    private void createFTS5SearchTable(Connection connection) throws SQLException {
        logger.info("📝 Creating FTS5 full-text search table");
        
        String createFTS5Sql = "CREATE VIRTUAL TABLE IF NOT EXISTS response_index USING fts5(" +
                              "traffic_meta_id, " +
                              "response_headers, " +
                              "response_body, " +
                              "url, " +
                              "content='traffic_responses', " +
                              "content_rowid='id'" +
                              ")";
        
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(createFTS5Sql);
            
            // Create triggers to keep FTS5 index updated
            String insertTrigger = "CREATE TRIGGER IF NOT EXISTS response_index_insert AFTER INSERT ON traffic_responses BEGIN " +
                                  "INSERT INTO response_index(traffic_meta_id, response_headers, response_body, url) " +
                                  "SELECT NEW.traffic_meta_id, NEW.headers, NEW.body, tm.url " +
                                  "FROM traffic_meta tm WHERE tm.id = NEW.traffic_meta_id; END;";
            
            String deleteTrigger = "CREATE TRIGGER IF NOT EXISTS response_index_delete AFTER DELETE ON traffic_responses BEGIN " +
                                  "DELETE FROM response_index WHERE rowid = OLD.id; END;";
            
            String updateTrigger = "CREATE TRIGGER IF NOT EXISTS response_index_update AFTER UPDATE ON traffic_responses BEGIN " +
                                  "DELETE FROM response_index WHERE rowid = OLD.id; " +
                                  "INSERT INTO response_index(traffic_meta_id, response_headers, response_body, url) " +
                                  "SELECT NEW.traffic_meta_id, NEW.headers, NEW.body, tm.url " +
                                  "FROM traffic_meta tm WHERE tm.id = NEW.traffic_meta_id; END;";
            
            stmt.execute(insertTrigger);
            stmt.execute(deleteTrigger);
            stmt.execute(updateTrigger);
            
            // Populate FTS5 table with existing data
            String populateSql = "INSERT INTO response_index(traffic_meta_id, response_headers, response_body, url) " +
                               "SELECT tr.traffic_meta_id, tr.headers, tr.body, tm.url " +
                               "FROM traffic_responses tr " +
                               "JOIN traffic_meta tm ON tm.id = tr.traffic_meta_id";
            
            int populated = stmt.executeUpdate(populateSql);
            logger.info("✅ FTS5 search table created and populated with {} records", populated);
        }
    }
    
    /**
     * Verify schema integrity after migrations
     */
    private void verifySchemaIntegrity(Connection connection) throws SQLException {
        logger.info("🔍 Verifying schema integrity");
        
        // Check that all required tables exist
        String[] requiredTables = {"traffic_meta", "traffic_requests", "traffic_responses", "schema_version"};
        
        for (String table : requiredTables) {
            if (!tableExists(connection, table)) {
                throw new SQLException("Required table missing: " + table);
            }
        }
        
        // Check foreign key constraints
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("PRAGMA foreign_key_check");
        }
        
        logger.info("✅ Schema integrity verified");
    }
    
    /**
     * Updates the schema version in the database.
     */
    private void updateSchemaVersion(Connection connection, int version, String description) throws SQLException {
        // Check if description column exists before using it
        boolean hasDescription = columnExists(connection, "schema_version", "description");
        
        String sql;
        if (hasDescription) {
            sql = "INSERT INTO schema_version (version, description) VALUES (?, ?)";
        } else {
            sql = "INSERT INTO schema_version (version) VALUES (?)";
        }
        
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, version);
            if (hasDescription) {
                stmt.setString(2, description);
            }
            stmt.executeUpdate();
        }
        
        logger.info("Schema version updated to {} - {}", version, description);
    }
    
    /**
     * Checks if a table exists in the database.
     */
    public boolean tableExists(Connection connection, String tableName) throws SQLException {
        DatabaseMetaData metaData = connection.getMetaData();
        try (ResultSet rs = metaData.getTables(null, null, tableName, new String[]{"TABLE"})) {
            return rs.next();
        }
    }
    
    /**
     * Checks if a column exists in a table.
     */
    private boolean columnExists(Connection connection, String tableName, String columnName) throws SQLException {
        DatabaseMetaData metaData = connection.getMetaData();
        try (ResultSet rs = metaData.getColumns(null, null, tableName, columnName)) {
            return rs.next();
        }
    }
    
    /**
     * Get current schema version (public method for external use)
     */
    public int getSchemaVersion(Connection connection) throws SQLException {
        return getCurrentSchemaVersion(connection);
    }
    
    /**
     * Check if normalized schema is available
     */
    public boolean isNormalizedSchemaAvailable(Connection connection) throws SQLException {
        return tableExists(connection, "traffic_meta") && 
               tableExists(connection, "traffic_requests") && 
               tableExists(connection, "traffic_responses");
    }
    
    /**
     * Check if FTS5 search is available
     */
    public boolean isFTS5SearchAvailable(Connection connection) throws SQLException {
        return tableExists(connection, "response_index");
    }
    
    /**
     * Check if request FTS5 search is available
     */
    public boolean isRequestFTS5SearchAvailable(Connection connection) throws SQLException {
        return tableExists(connection, "request_index");
    }
    
    /**
     * Check if saved queries functionality is available
     */
    public boolean isSavedQueriesAvailable(Connection connection) throws SQLException {
        return tableExists(connection, "saved_queries");
    }
    
    /**
     * Check if enhanced metadata features are available (tags, comments, replay lineage)
     */
    public boolean isEnhancedMetadataAvailable(Connection connection) throws SQLException {
        return columnExists(connection, "traffic_meta", "tags") && 
               columnExists(connection, "traffic_meta", "comment") && 
               columnExists(connection, "traffic_meta", "replayed_from");
    }
} 