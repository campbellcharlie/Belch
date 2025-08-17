package com.belch.database;

import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.MontoyaApi;
import com.belch.config.ApiConfig;
import com.belch.database.schema.SchemaManager;
import com.belch.logging.TrafficSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

/**
 * Service class for managing database operations.
 * Handles SQLite database initialization, schema management,
 * and storage/retrieval of proxy traffic data.
 * Supports project-specific databases to prevent data contamination between different Burp projects.
 * 
 * @author Charlie Campbell
 * @version 1.0.0
 */
public class DatabaseService {
    
    private static final Logger logger = LoggerFactory.getLogger(DatabaseService.class);
    
    private final ApiConfig config;
    private final MontoyaApi api;
    private final SchemaManager schemaManager;
    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private final AtomicBoolean shutdown = new AtomicBoolean(false);
    
    private Connection connection;
    private String currentProjectName;
    private String currentDatabasePath;
    
    /**
     * Constructor for DatabaseService.
     * 
     * @param api The MontoyaApi instance to access project information
     * @param config The API configuration
     */
    public DatabaseService(MontoyaApi api, ApiConfig config) {
        this.api = api;
        this.config = config;
        this.schemaManager = new SchemaManager();
    }
    
    /**
     * Initializes the database service.
     * Creates connection and ensures schema is up to date.
     * Automatically detects project changes and creates project-specific databases.
     */
    public void initialize() {
        if (initialized.getAndSet(true)) {
            logger.warn("DatabaseService already initialized");
            return;
        }
        
        try {
            logger.info("🚀 Starting database initialization...");
            
            // Detect current project and create project-specific database path
            String projectName = detectCurrentProject();
            String projectDbPath = generateProjectSpecificDatabasePath(projectName);
            
            logger.info("📍 Current Burp project: {}", projectName);
            logger.info("🐛 DATABASE DEBUG: Config database path: {}", config.getDatabasePath());
            logger.info("📍 Project-specific database path: {}", projectDbPath);
            
            this.currentProjectName = projectName;
            this.currentDatabasePath = projectDbPath;
            
            // Test ClassLoader and SQLite availability with detailed logging
            try {
                logger.info("🔍 Step 1: Loading SQLite JDBC driver...");
                Class<?> sqliteDriver = Class.forName("org.sqlite.JDBC");
                logger.info("✅ SQLite JDBC driver loaded successfully: {}", sqliteDriver.getName());
            } catch (ClassNotFoundException e) {
                logger.error("❌ CRITICAL: SQLite JDBC driver not found in classpath", e);
                throw e;
            }
            
            // Test DriverManager registration
            try {
                logger.info("🔍 Step 2: Testing DriverManager SQLite support...");
                java.sql.Driver driver = java.sql.DriverManager.getDriver("jdbc:sqlite:test");
                logger.info("✅ DriverManager SQLite support confirmed: {}", driver.getClass().getName());
            } catch (SQLException e) {
                logger.warn("⚠️ DriverManager test failed, will try direct connection: {}", e.getMessage());
            }
            
            // Create database connection with enhanced error reporting
            String dbUrl = "jdbc:sqlite:" + currentDatabasePath;
            logger.info("🔍 Step 3: Creating database connection to: {}", dbUrl);
            
            // Ensure directory exists
            java.io.File dbFile = new java.io.File(currentDatabasePath);
            java.io.File parentDir = dbFile.getParentFile();
            if (parentDir != null && !parentDir.exists()) {
                boolean created = parentDir.mkdirs();
                logger.info("📁 Created database directory {}: {}", parentDir.getAbsolutePath(), created);
            }
            
            logger.info("🔍 Step 4: Establishing database connection...");
            connection = DriverManager.getConnection(dbUrl);
            logger.info("✅ Database connection established successfully");
            
            // Test basic SQL functionality
            try {
                logger.info("🔍 Step 5: Testing basic SQL functionality...");
                try (java.sql.Statement testStmt = getConnection().createStatement()) {
                    testStmt.execute("SELECT 1");
                    logger.info("✅ Basic SQL test successful");
                }
            } catch (SQLException e) {
                logger.error("❌ Basic SQL test failed", e);
                throw e;
            }
            
            // Configure connection
            logger.info("🔍 Step 6: Configuring SQLite connection...");
            configureConnection();
            logger.info("✅ Connection configured successfully");
            
            // Initialize or upgrade schema
            logger.info("🔍 Step 7: Initializing database schema...");
            schemaManager.initializeSchema(connection);
            logger.info("✅ Schema initialization completed");
            
            // Create database indexes for better query performance
            createIndexes();
            
            logger.info("🎉 Database service initialized successfully with project-specific database");
            logger.info("📊 Project: {} | Database: {}", projectName, currentDatabasePath);
            
        } catch (ClassNotFoundException e) {
            logger.error("❌ STEP FAILED: SQLite JDBC driver not available - this is a critical classpath issue", e);
            initialized.set(false);
            throw new RuntimeException("SQLite JDBC driver not found: " + e.getMessage(), e);
        } catch (SQLException e) {
            logger.error("❌ STEP FAILED: SQL error during database initialization", e);
            logger.error("Database URL attempted: jdbc:sqlite:{}", currentDatabasePath);
            logger.error("Database file parent directory: {}", new java.io.File(currentDatabasePath).getParent());
            initialized.set(false);
            throw new RuntimeException("Database connection failed: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error("❌ STEP FAILED: Unexpected error during database initialization", e);
            logger.error("Database path: {}", currentDatabasePath);
            logger.error("Working directory: {}", System.getProperty("user.dir"));
            logger.error("Java version: {}", System.getProperty("java.version"));
            initialized.set(false);
            throw new RuntimeException("Failed to initialize database service: " + e.getMessage(), e);
        }
    }
    
    /**
     * Detects the current Burp project name.
     * 
     * @return The current project name, or a default name if not available
     */
    private String detectCurrentProject() {
        try {
            String projectName = api.project().name();
            
            // Handle various project name scenarios
            if (projectName == null || projectName.trim().isEmpty()) {
                projectName = "Temporary project";
                logger.info("🔍 Project name is null/empty, using: {}", projectName);
            } else {
                logger.info("🔍 Detected project name from Burp API: {}", projectName);
            }
            
            // Sanitize project name for file system use
            String sanitizedName = sanitizeProjectNameForFileSystem(projectName);
            logger.info("🔍 Sanitized project name for database: {}", sanitizedName);
            
            return sanitizedName;
            
        } catch (Exception e) {
            logger.warn("⚠️ Failed to detect project name from Burp API: {}", e.getMessage());
            String fallbackName = "unknown-project-" + System.currentTimeMillis();
            logger.info("🔍 Using fallback project name: {}", fallbackName);
            return fallbackName;
        }
    }
    
    /**
     * Sanitizes a project name for safe use in file system paths.
     * 
     * @param projectName The original project name
     * @return A sanitized project name safe for file paths
     */
    private String sanitizeProjectNameForFileSystem(String projectName) {
        if (projectName == null) {
            return "unnamed-project";
        }
        
        // Replace unsafe characters with underscores and limit length
        String sanitized = projectName
            .replaceAll("[^a-zA-Z0-9\\-_\\s]", "_")  // Replace unsafe chars
            .replaceAll("\\s+", "_")                  // Replace spaces with underscores
            .replaceAll("_{2,}", "_")                 // Collapse multiple underscores
            .replaceAll("^_+|_+$", "");               // Remove leading/trailing underscores
        
        // Ensure it's not empty and not too long
        if (sanitized.isEmpty()) {
            sanitized = "unnamed_project";
        }
        
        if (sanitized.length() > 100) {
            sanitized = sanitized.substring(0, 100);
        }
        
        return sanitized;
    }
    
    /**
     * Generates a project-specific database path based on the configured base path and project name.
     * 
     * @param projectName The sanitized project name
     * @return The complete path to the project-specific database file
     */
    private String generateProjectSpecificDatabasePath(String projectName) {
        String baseDatabasePath = config.getDatabasePath();
        
        // TEMPORARY FIX: Force correct base filename for Charlie's system
        if (baseDatabasePath.contains("burp_api")) {
            baseDatabasePath = baseDatabasePath.replace("burp_api", "belch");
            logger.info("🔧 TEMP FIX: Corrected database path from burp_api to belch: {}", baseDatabasePath);
        }
        
        // Extract the directory and base filename from the configured path
        java.io.File baseFile = new java.io.File(baseDatabasePath);
        String baseDir = baseFile.getParent();
        String baseFileName = baseFile.getName();
        
        // Remove .db extension if present to add project name
        String baseNameWithoutExt = baseFileName;
        if (baseFileName.toLowerCase().endsWith(".db")) {
            baseNameWithoutExt = baseFileName.substring(0, baseFileName.length() - 3);
        }
        
        // Create project-specific filename
        String projectDbFileName = baseNameWithoutExt + "_" + projectName + ".db";
        
        // Combine directory and filename
        if (baseDir != null) {
            return baseDir + java.io.File.separator + projectDbFileName;
        } else {
            return projectDbFileName;
        }
    }
    
    /**
     * Checks if the current project has changed and reinitializes the database if needed.
     * This method should be called periodically or when project changes are suspected.
     * 
     * @return true if project changed and database was reinitialized, false if no change
     */
    public boolean checkForProjectChangeAndReinitialize() {
        try {
            String newProjectName = detectCurrentProject();
            String newDatabasePath = generateProjectSpecificDatabasePath(newProjectName);
            
            // Check if project has changed OR database path has changed OR connection is invalid
            boolean projectChanged = !newProjectName.equals(currentProjectName);
            boolean databasePathChanged = !newDatabasePath.equals(currentDatabasePath);
            boolean connectionInvalid = (connection == null || connection.isClosed());
            
            if (projectChanged || databasePathChanged || connectionInvalid) {
                if (projectChanged) {
                    logger.info("🔄 Project change detected: {} -> {}", currentProjectName, newProjectName);
                }
                if (databasePathChanged) {
                    logger.info("🔄 Database path change detected: {} -> {}", currentDatabasePath, newDatabasePath);
                }
                if (connectionInvalid) {
                    logger.info("🔄 Invalid database connection detected, reinitializing...");
                }
                logger.info("🔄 Reinitializing database...");
                
                // Close current connection
                if (connection != null && !connection.isClosed()) {
                    connection.close();
                    logger.info("📤 Closed previous project database connection");
                }
                
                // Reset initialization state
                initialized.set(false);
                
                // Reinitialize with new project
                try {
                    initialize();
                    logger.info("✅ Successfully switched to new project database");
                } catch (Exception e) {
                    logger.error("❌ FAILED to reinitialize database after project change: {}", e.getMessage(), e);
                    throw e;
                }
                logger.info("📊 New Project: {} | Database: {}", currentProjectName, currentDatabasePath);
                
                return true;
            }
            
            return false;
            
        } catch (Exception e) {
            logger.error("❌ Failed to check for project change", e);
            return false;
        }
    }
    
    /**
     * Gets the current project name.
     * 
     * @return The current project name
     */
    public String getCurrentProjectName() {
        return currentProjectName;
    }
    
    /**
     * Gets the current database path.
     * 
     * @return The current database path
     */
    public String getCurrentDatabasePath() {
        return currentDatabasePath;
    }
    
    /**
     * Configures the SQLite connection with optimal settings.
     */
    private void configureConnection() throws SQLException {
        try (Statement stmt = getConnection().createStatement()) {
            // CRITICAL: Ensure autocommit is enabled for SQLite
            connection.setAutoCommit(true);
            logger.info("Database autocommit enabled: {}", connection.getAutoCommit());
            
            // Enable WAL mode for better concurrent access
            stmt.execute("PRAGMA journal_mode=WAL");
            // Enable foreign key constraints
            stmt.execute("PRAGMA foreign_keys=ON");
            // Set synchronous mode for better performance
            stmt.execute("PRAGMA synchronous=NORMAL");
            // Set cache size (negative value means KB)
            stmt.execute("PRAGMA cache_size=-10000");
            
            logger.info("SQLite connection configured successfully");
        }
    }
    
    /**
     * Creates database indexes for better query performance.
     */
    private void createIndexes() throws SQLException {
        logger.info("Creating database indexes for optimal query performance...");
        
        String[] indexes = {
            "CREATE INDEX IF NOT EXISTS idx_proxy_traffic_url ON proxy_traffic(url)",
            "CREATE INDEX IF NOT EXISTS idx_proxy_traffic_method ON proxy_traffic(method)", 
            "CREATE INDEX IF NOT EXISTS idx_proxy_traffic_host ON proxy_traffic(host)",
            "CREATE INDEX IF NOT EXISTS idx_proxy_traffic_status_code ON proxy_traffic(status_code)",
            "CREATE INDEX IF NOT EXISTS idx_proxy_traffic_session_tag ON proxy_traffic(session_tag)",
            "CREATE INDEX IF NOT EXISTS idx_proxy_traffic_timestamp ON proxy_traffic(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_proxy_traffic_compound ON proxy_traffic(timestamp DESC, host, method)",
            "CREATE INDEX IF NOT EXISTS idx_proxy_traffic_scope ON proxy_traffic(url, timestamp) WHERE status_code IS NOT NULL"
        };
        
        try (Statement stmt = getConnection().createStatement()) {
            for (String indexSql : indexes) {
                try {
                    stmt.execute(indexSql);
                    logger.debug("Created index: {}", indexSql.substring(indexSql.indexOf("idx_")));
                } catch (SQLException e) {
                    logger.warn("Failed to create index: {}", e.getMessage());
                }
            }
        }
        
        logger.info("✅ Database indexes created successfully");
    }
    
    /**
     * Stores a proxy request in the database.
     * 
     * @param request The intercepted request to store
     */
    public void storeRequest(InterceptedRequest request) {
        if (shutdown.get() || connection == null) {
            return;
        }
        
        String sql = "INSERT INTO proxy_traffic (" +
                    "timestamp, method, url, host, headers, body, session_tag" +
                    ") VALUES (?, ?, ?, ?, ?, ?, ?)";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setTimestamp(1, Timestamp.valueOf(LocalDateTime.now()));
            stmt.setString(2, sanitizeString(request.method(), 10));
            stmt.setString(3, sanitizeString(request.url(), 8192));
            stmt.setString(4, sanitizeString(request.httpService().host(), 255));
            stmt.setString(5, sanitizeString(request.headers().toString(), 65536));
            stmt.setString(6, sanitizeString(request.bodyToString(), 65536));
            stmt.setString(7, sanitizeString(config.getSessionTag(), 100));
            
            stmt.executeUpdate();
            
            logger.debug("Stored request: {} {}", request.method(), request.url());
            
        } catch (SQLException e) {
            logger.error("Failed to store request", e);
        }
    }
    
    /**
     * Stores a proxy response and updates the corresponding request.
     * 
     * @param response The intercepted response to store
     */
    public void storeResponse(InterceptedResponse response) {
        if (shutdown.get() || connection == null) {
            return;
        }
        
        String requestUrl = response.initiatingRequest().url();
        String requestMethod = response.initiatingRequest().method();
        
        logger.debug("Attempting to store response: {} for {} {}", 
                    response.statusCode(), requestMethod, requestUrl);
        
        // Strategy 1: Try exact URL + method match within recent time window (last 60 seconds)
        String exactMatchSql = "UPDATE proxy_traffic " +
                              "SET status_code = ?, response_headers = ?, response_body = ? " +
                              "WHERE url = ? AND method = ? AND status_code IS NULL " +
                              "AND timestamp > datetime('now', '-60 seconds') " +
                              "ORDER BY timestamp DESC LIMIT 1";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(exactMatchSql)) {
            stmt.setInt(1, response.statusCode());
            stmt.setString(2, sanitizeString(response.headers().toString(), 65536));
            stmt.setString(3, sanitizeString(response.bodyToString(), 65536));
            stmt.setString(4, sanitizeString(requestUrl, 8192));
            stmt.setString(5, sanitizeString(requestMethod, 10));
            
            int updated = stmt.executeUpdate();
            
            if (updated > 0) {
                logger.info("✅ Exact match - Updated response: {} for {} {}", 
                           response.statusCode(), requestMethod, requestUrl);
                return;
            }
        } catch (SQLException e) {
            logger.error("Failed exact match for response", e);
        }
        
        // Strategy 2: Try fuzzy URL match (without query params) + method within time window
        String baseUrl = requestUrl.split("\\?")[0]; // Remove query parameters
        String fuzzyMatchSql = "UPDATE proxy_traffic " +
                              "SET status_code = ?, response_headers = ?, response_body = ? " +
                              "WHERE url LIKE ? AND method = ? AND status_code IS NULL " +
                              "AND timestamp > datetime('now', '-60 seconds') " +
                              "ORDER BY timestamp DESC LIMIT 1";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(fuzzyMatchSql)) {
            stmt.setInt(1, response.statusCode());
            stmt.setString(2, sanitizeString(response.headers().toString(), 65536));
            stmt.setString(3, sanitizeString(response.bodyToString(), 65536));
            stmt.setString(4, sanitizeString(baseUrl, 8192) + "%");
            stmt.setString(5, sanitizeString(requestMethod, 10));
            
            int updated = stmt.executeUpdate();
            
            if (updated > 0) {
                logger.info("✅ Fuzzy match - Updated response: {} for {} {} (base: {})", 
                           response.statusCode(), requestMethod, requestUrl, baseUrl);
                return;
            }
        } catch (SQLException e) {
            logger.error("Failed fuzzy match for response", e);
        }
        
        // Strategy 3: Fallback to most recent unmatched request within time window
        String fallbackSql = "UPDATE proxy_traffic " +
                            "SET status_code = ?, response_headers = ?, response_body = ? " +
                            "WHERE status_code IS NULL " +
                            "AND timestamp > datetime('now', '-120 seconds') " +
                            "ORDER BY timestamp DESC LIMIT 1";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(fallbackSql)) {
            stmt.setInt(1, response.statusCode());
            stmt.setString(2, sanitizeString(response.headers().toString(), 65536));
            stmt.setString(3, sanitizeString(response.bodyToString(), 65536));
            
            int updated = stmt.executeUpdate();
            
            if (updated > 0) {
                logger.info("✅ Fallback match - Updated response: {} for {} {}", 
                           response.statusCode(), requestMethod, requestUrl);
                return;
            }
        } catch (SQLException e) {
            logger.error("Failed fallback match for response", e);
        }
        
        // Strategy 4: No match found - create orphaned response record
        logger.warn("❌ No matching request found for response: {} {} - URL: {}", 
                  requestMethod, response.statusCode(), requestUrl);
        logger.info("Creating new record for orphaned response");
        storeOrphanedResponse(response);
    }
    
    /**
     * Stores an orphaned response (response without a matching request) as a new record.
     */
    private void storeOrphanedResponse(InterceptedResponse response) {
        String sql = "INSERT INTO proxy_traffic (" +
                    "timestamp, method, url, host, headers, body, status_code, response_headers, response_body, session_tag" +
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setTimestamp(1, Timestamp.valueOf(LocalDateTime.now()));
            stmt.setString(2, sanitizeString(response.initiatingRequest().method(), 10));
            stmt.setString(3, sanitizeString(response.initiatingRequest().url(), 8192));
            stmt.setString(4, sanitizeString(response.initiatingRequest().httpService().host(), 255));
            stmt.setString(5, sanitizeString(response.initiatingRequest().headers().toString(), 65536));
            stmt.setString(6, sanitizeString(response.initiatingRequest().bodyToString(), 65536));
            stmt.setInt(7, response.statusCode());
            stmt.setString(8, sanitizeString(response.headers().toString(), 65536));
            stmt.setString(9, sanitizeString(response.bodyToString(), 65536));
            stmt.setString(10, sanitizeString(config.getSessionTag(), 100));
            
            stmt.executeUpdate();
            logger.debug("Stored orphaned response as new record");
            
        } catch (SQLException e) {
            logger.error("Failed to store orphaned response", e);
        }
    }
    
    /**
     * Sanitizes a string by removing control characters and null bytes,
     * and truncating to the specified maximum length.
     * 
     * @param input The input string to sanitize
     * @param maxLength The maximum allowed length
     * @return The sanitized string
     */
    private String sanitizeString(String input, int maxLength) {
        if (input == null) {
            return "";
        }
        
        // Remove null bytes and control characters (except newlines and tabs)
        String sanitized = input.replaceAll("[\u0000-\u0008\u000B-\u000C\u000E-\u001F\u007F]", "");
        
        // Truncate to maximum length if necessary
        if (sanitized.length() > maxLength) {
            sanitized = sanitized.substring(0, maxLength - 3) + "...";
            logger.debug("Truncated string from {} to {} characters", input.length(), sanitized.length());
        }
        
        return sanitized;
    }
    
    /**
     * Searches for proxy traffic based on criteria with advanced filtering options.
     * Optimized for large databases with safety limits and performance hints.
     * 
     * @param searchParams Map of search parameters
     * @return List of traffic records
     */
    public List<Map<String, Object>> searchTraffic(Map<String, String> searchParams) {
        if (shutdown.get() || connection == null) {
            return new ArrayList<>();
        }
        
        StringBuilder sql = new StringBuilder("SELECT * FROM proxy_traffic WHERE 1=1");
        List<Object> params = new ArrayList<>();
        
        // Determine case sensitivity
        boolean caseInsensitive = Boolean.parseBoolean(searchParams.getOrDefault("case_insensitive", "false"));
        String likeOperator = caseInsensitive ? " AND LOWER(url) LIKE LOWER(?)" : " AND url LIKE ?";
        String hostLikeOperator = caseInsensitive ? " AND LOWER(host) LIKE LOWER(?)" : " AND host LIKE ?";
        
        // Add search filters
        if (searchParams.containsKey("url")) {
            sql.append(likeOperator);
            String urlPattern = searchParams.get("url");
            // Convert wildcard patterns (* and ?) to SQL LIKE patterns (% and _)
            if (urlPattern.contains("*") || urlPattern.contains("?")) {
                urlPattern = urlPattern.replace("*", "%").replace("?", "_");
                params.add(urlPattern);
            } else {
                // Default behavior: wrap with % for substring search
                params.add("%" + urlPattern + "%");
            }
        }
        
        // Add url_pattern filter (always uses wildcard conversion)
        if (searchParams.containsKey("url_pattern")) {
            sql.append(likeOperator);
            String urlPattern = searchParams.get("url_pattern");
            // Convert wildcard patterns (* and ?) to SQL LIKE patterns (% and _)
            urlPattern = urlPattern.replace("*", "%").replace("?", "_");
            params.add(urlPattern);
        }
        
        if (searchParams.containsKey("method")) {
            if (caseInsensitive) {
                sql.append(" AND LOWER(method) = LOWER(?)");
            } else {
                sql.append(" AND method = ?");
            }
            params.add(searchParams.get("method"));
        }
        
        if (searchParams.containsKey("host")) {
            sql.append(hostLikeOperator);
            params.add("%" + searchParams.get("host") + "%");
        }
        
        if (searchParams.containsKey("status_code")) {
            sql.append(" AND status_code = ?");
            params.add(Integer.parseInt(searchParams.get("status_code")));
        }
        
        if (searchParams.containsKey("session_tag")) {
            if (caseInsensitive) {
                sql.append(" AND LOWER(session_tag) = LOWER(?)");
            } else {
                sql.append(" AND session_tag = ?");
            }
            params.add(searchParams.get("session_tag"));
        }
        
        // Add time-range filters
        if (searchParams.containsKey("start_time")) {
            sql.append(" AND timestamp >= ?");
            params.add(parseTimestamp(searchParams.get("start_time")));
        }
        
        if (searchParams.containsKey("end_time")) {
            sql.append(" AND timestamp <= ?");
            params.add(parseTimestamp(searchParams.get("end_time")));
        }
        
        // Add ordering - support sort and order parameters
        String sortColumn = searchParams.getOrDefault("sort", "timestamp");
        String sortOrder = searchParams.getOrDefault("order", "desc");
        
        // Validate sort column for security (prevent SQL injection)
        String[] allowedSortColumns = {"id", "timestamp", "method", "host", "status_code", "url"};
        boolean validSortColumn = false;
        for (String allowed : allowedSortColumns) {
            if (allowed.equalsIgnoreCase(sortColumn)) {
                sortColumn = allowed;
                validSortColumn = true;
                break;
            }
        }
        if (!validSortColumn) {
            sortColumn = "timestamp"; // Default fallback
        }
        
        // Validate sort order
        if (!sortOrder.equalsIgnoreCase("asc") && !sortOrder.equalsIgnoreCase("desc")) {
            sortOrder = "desc"; // Default fallback
        }
        
        sql.append(" ORDER BY ").append(sortColumn).append(" ").append(sortOrder.toUpperCase());
        
        // Safety limits and pagination
        int limit = 100; // Default safe limit
        int offset = 0;
        int maxLimit = 50000; // Absolute maximum for safety
        
        if (searchParams.containsKey("limit")) {
            try {
                int requestedLimit = Integer.parseInt(searchParams.get("limit"));
                if (requestedLimit > maxLimit) {
                    logger.warn("Requested limit {} exceeds maximum {}, capping to maximum", requestedLimit, maxLimit);
                    limit = maxLimit;
                } else if (requestedLimit > 0) {
                    limit = requestedLimit;
                }
            } catch (NumberFormatException e) {
                logger.warn("Invalid limit parameter, using default: {}", searchParams.get("limit"));
            }
        }
        
        if (searchParams.containsKey("offset")) {
            try {
                offset = Math.max(0, Integer.parseInt(searchParams.get("offset")));
            } catch (NumberFormatException e) {
                logger.warn("Invalid offset parameter, using 0: {}", searchParams.get("offset"));
                offset = 0;
            }
        }
        
        // Always apply limit to prevent runaway queries
        sql.append(" LIMIT ? OFFSET ?");
        params.add(limit);
        params.add(offset);
        
        List<Map<String, Object>> results = new ArrayList<>();
        long queryStartTime = System.currentTimeMillis();
        
        // Debug logging
        logger.info("DEBUG searchTraffic: Executing SQL: {}", sql.toString());
        logger.info("DEBUG searchTraffic: Parameters: {}", params);
        try {
            logger.info("DEBUG searchTraffic: Connection valid: {}", connection != null && !connection.isClosed());
        } catch (SQLException e) {
            logger.warn("Could not check connection status: {}", e.getMessage());
        }
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql.toString())) {
            // Set parameters
            for (int i = 0; i < params.size(); i++) {
                stmt.setObject(i + 1, params.get(i));
            }
            
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> record = new HashMap<>();
                    record.put("id", rs.getLong("id"));
                    
                    // Handle both timestamp formats (epoch millis and formatted timestamp)
                    try {
                        Object timestampObj = rs.getObject("timestamp");
                        if (timestampObj instanceof Number) {
                            // Epoch milliseconds
                            record.put("timestamp", new Timestamp(((Number) timestampObj).longValue()));
                        } else {
                            // Formatted timestamp string
                            record.put("timestamp", rs.getTimestamp("timestamp"));
                        }
                    } catch (SQLException e) {
                        logger.warn("Failed to parse timestamp, using raw value: {}", e.getMessage());
                        record.put("timestamp", rs.getObject("timestamp"));
                    }
                    record.put("method", rs.getString("method"));
                    record.put("url", rs.getString("url"));
                    record.put("host", rs.getString("host"));
                    record.put("status_code", rs.getObject("status_code"));
                    record.put("headers", rs.getString("headers"));
                    record.put("body", rs.getString("body"));
                    record.put("response_headers", rs.getString("response_headers"));
                    record.put("response_body", rs.getString("response_body"));
                    record.put("session_tag", rs.getString("session_tag"));
                    results.add(record);
                }
            }
            
            logger.info("DEBUG searchTraffic: Found {} results", results.size());
            long queryTime = System.currentTimeMillis() - queryStartTime;
            logger.debug("Search query completed: {} results in {}ms (limit={}, offset={})", 
                        results.size(), queryTime, limit, offset);
            
            // Log slow queries for performance monitoring
            if (queryTime > 5000) {
                logger.warn("Slow query detected: {}ms for {} results. Consider adding filters or reducing limit.", 
                           queryTime, results.size());
            }
            
        } catch (SQLException e) {
            logger.error("CRITICAL: Failed to search traffic - SQL: {} - Params: {} - Error: {}", 
                        sql.toString(), params, e.getMessage(), e);
        } catch (Exception e) {
            logger.error("CRITICAL: Unexpected error in searchTraffic - SQL: {} - Params: {} - Error: {}", 
                        sql.toString(), params, e.getMessage(), e);
        }
        
        return results;
    }
    
    /**
     * Gets the total count of records matching the search criteria (for pagination).
     * 
     * @param searchParams Map of search parameters
     * @return Total count of matching records
     */
    public long getSearchCount(Map<String, String> searchParams) {
        if (shutdown.get() || connection == null) {
            return 0;
        }
        
        StringBuilder sql = new StringBuilder("SELECT COUNT(*) FROM proxy_traffic WHERE 1=1");
        List<Object> params = new ArrayList<>();
        
        // Determine case sensitivity
        boolean caseInsensitive = Boolean.parseBoolean(searchParams.getOrDefault("case_insensitive", "false"));
        String likeOperator = caseInsensitive ? " AND LOWER(url) LIKE LOWER(?)" : " AND url LIKE ?";
        String hostLikeOperator = caseInsensitive ? " AND LOWER(host) LIKE LOWER(?)" : " AND host LIKE ?";
        
        // Add same filters as searchTraffic (excluding limit/offset)
        if (searchParams.containsKey("url")) {
            sql.append(likeOperator);
            String urlPattern = searchParams.get("url");
            // Convert wildcard patterns (* and ?) to SQL LIKE patterns (% and _)
            if (urlPattern.contains("*") || urlPattern.contains("?")) {
                urlPattern = urlPattern.replace("*", "%").replace("?", "_");
                params.add(urlPattern);
            } else {
                // Default behavior: wrap with % for substring search
                params.add("%" + urlPattern + "%");
            }
        }
        
        // Add url_pattern filter (always uses wildcard conversion)
        if (searchParams.containsKey("url_pattern")) {
            sql.append(likeOperator);
            String urlPattern = searchParams.get("url_pattern");
            // Convert wildcard patterns (* and ?) to SQL LIKE patterns (% and _)
            urlPattern = urlPattern.replace("*", "%").replace("?", "_");
            params.add(urlPattern);
        }
        
        if (searchParams.containsKey("method")) {
            if (caseInsensitive) {
                sql.append(" AND LOWER(method) = LOWER(?)");
            } else {
                sql.append(" AND method = ?");
            }
            params.add(searchParams.get("method"));
        }
        
        if (searchParams.containsKey("host")) {
            sql.append(hostLikeOperator);
            params.add("%" + searchParams.get("host") + "%");
        }
        
        if (searchParams.containsKey("status_code")) {
            sql.append(" AND status_code = ?");
            params.add(Integer.parseInt(searchParams.get("status_code")));
        }
        
        if (searchParams.containsKey("session_tag")) {
            if (caseInsensitive) {
                sql.append(" AND LOWER(session_tag) = LOWER(?)");
            } else {
                sql.append(" AND session_tag = ?");
            }
            params.add(searchParams.get("session_tag"));
        }
        
        // Add time-range filters
        if (searchParams.containsKey("start_time")) {
            sql.append(" AND timestamp >= ?");
            params.add(parseTimestamp(searchParams.get("start_time")));
        }
        
        if (searchParams.containsKey("end_time")) {
            sql.append(" AND timestamp <= ?");
            params.add(parseTimestamp(searchParams.get("end_time")));
        }
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql.toString())) {
            // Set parameters
            for (int i = 0; i < params.size(); i++) {
                stmt.setObject(i + 1, params.get(i));
            }
            
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getLong(1);
                }
            }
            
        } catch (SQLException e) {
            logger.error("Failed to get search count", e);
        }
        
        return 0;
    }
    
    /**
     * Parses a timestamp string in ISO 8601 format to a SQL Timestamp.
     * 
     * @param timestampStr The timestamp string to parse
     * @return SQL Timestamp object
     */
    private Timestamp parseTimestamp(String timestampStr) {
        try {
            // Handle ISO 8601 format (e.g., "2024-05-30T19:20:00Z" or "2024-05-30T19:20:00")
            LocalDateTime localDateTime;
            if (timestampStr.endsWith("Z")) {
                localDateTime = LocalDateTime.parse(timestampStr.substring(0, timestampStr.length() - 1));
            } else if (timestampStr.contains("T")) {
                localDateTime = LocalDateTime.parse(timestampStr);
            } else {
                // Handle date-only format (e.g., "2024-05-30")
                localDateTime = LocalDateTime.parse(timestampStr + "T00:00:00");
            }
            return Timestamp.valueOf(localDateTime);
        } catch (Exception e) {
            logger.warn("Failed to parse timestamp '{}', using current time", timestampStr);
            return Timestamp.valueOf(LocalDateTime.now());
        }
    }
    
    /**
     * Shuts down the database service and closes connections.
     */
    public void shutdown() {
        if (shutdown.getAndSet(true)) {
            return;
        }
        
        logger.info("Shutting down database service");
        
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
                logger.info("Database connection closed");
            }
        } catch (SQLException e) {
            logger.error("Error closing database connection", e);
        }
    }
    
    /**
     * Checks if the database service is initialized.
     * 
     * @return true if initialized, false otherwise
     */
    public boolean isInitialized() {
        return initialized.get();
    }
    
    /**
     * Returns connection for external use, reconnecting if necessary.
     */
    public Connection getConnection() {
        try {
            // Check for project changes first, before connection state
            checkForProjectChangeAndReinitialize();
            
            if (connection == null || connection.isClosed()) {
                logger.warn("Database connection is closed, attempting to reconnect...");
                if (!initialized.get()) {
                    initialize();
                } else {
                    // Reinitialize if connection is closed
                    initialized.set(false);
                    initialize();
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to check or restore database connection: {}", e.getMessage(), e);
        } catch (Exception e) {
            logger.warn("Failed to check for project changes in getConnection: {}", e.getMessage());
            // Continue with existing connection logic
        }
        return connection;
    }
    
    /**
     * Deletes traffic records by session tag.
     * 
     * @param sessionTag The session tag to delete
     * @return Number of records deleted
     */
    public int deleteTrafficBySessionTag(String sessionTag) {
        if (shutdown.get() || connection == null) {
            return 0;
        }
        
        String sql = "DELETE FROM proxy_traffic WHERE session_tag = ?";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, sessionTag);
            int deleted = stmt.executeUpdate();
            logger.info("Deleted {} records for session tag '{}'", deleted, sessionTag);
            return deleted;
        } catch (SQLException e) {
            logger.error("Failed to delete traffic by session tag", e);
            return 0;
        }
    }
    
    /**
     * Deletes all traffic records.
     * 
     * @return Number of records deleted
     */
    public int deleteAllTraffic() {
        if (shutdown.get() || connection == null) {
            return 0;
        }
        
        String sql = "DELETE FROM proxy_traffic";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            int deleted = stmt.executeUpdate();
            logger.info("Deleted all {} traffic records", deleted);
            return deleted;
        } catch (SQLException e) {
            logger.error("Failed to delete all traffic", e);
            return 0;
        }
    }
    
    /**
     * Deletes traffic records within a time range.
     * 
     * @param startTime Start time (inclusive)
     * @param endTime End time (inclusive)
     * @return Number of records deleted
     */
    public int deleteTrafficByTimeRange(String startTime, String endTime) {
        if (shutdown.get() || connection == null) {
            return 0;
        }
        
        StringBuilder sql = new StringBuilder("DELETE FROM proxy_traffic WHERE 1=1");
        List<Object> params = new ArrayList<>();
        
        if (startTime != null) {
            sql.append(" AND timestamp >= ?");
            params.add(parseTimestamp(startTime));
        }
        
        if (endTime != null) {
            sql.append(" AND timestamp <= ?");
            params.add(parseTimestamp(endTime));
        }
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql.toString())) {
            for (int i = 0; i < params.size(); i++) {
                stmt.setObject(i + 1, params.get(i));
            }
            
            int deleted = stmt.executeUpdate();
            logger.info("Deleted {} records in time range {} to {}", deleted, startTime, endTime);
            return deleted;
        } catch (SQLException e) {
            logger.error("Failed to delete traffic by time range", e);
            return 0;
        }
    }
    
    /**
     * Generates a content hash for deduplication based on request/response content.
     * 
     * @param method HTTP method
     * @param url URL
     * @param headers Headers string
     * @param body Body string
     * @param responseHeaders Response headers (optional)
     * @param responseBody Response body (optional)
     * @return SHA-256 hash of the combined content
     */
    private String generateContentHash(String method, String url, String headers, String body, 
                                     String responseHeaders, String responseBody) {
        try {
            StringBuilder content = new StringBuilder();
            content.append(method != null ? method : "");
            content.append("|");
            content.append(url != null ? url : "");
            content.append("|");
            content.append(headers != null ? headers : "");
            content.append("|");
            content.append(body != null ? body : "");
            content.append("|");
            content.append(responseHeaders != null ? responseHeaders : "");
            content.append("|");
            content.append(responseBody != null ? responseBody : "");
            
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(content.toString().getBytes(StandardCharsets.UTF_8));
            
            // Convert to hex string
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            
            return hexString.toString();
            
        } catch (Exception e) {
            logger.warn("Failed to generate content hash, using fallback", e);
            // Fallback to a simpler hash
            return String.valueOf((method + url + (headers != null ? headers.hashCode() : "")).hashCode());
        }
    }
    
    /**
     * Checks if a record with the same content already exists.
     * 
     * @param method HTTP method
     * @param url URL
     * @param host Host
     * @param contentHash Content hash
     * @return true if duplicate exists, false otherwise
     */
    private boolean isDuplicateRecord(String method, String url, String host, String contentHash) {
        if (shutdown.get() || connection == null) {
            return false;
        }
        
        String sql = "SELECT COUNT(*) FROM proxy_traffic WHERE method = ? AND url = ? AND host = ? AND content_hash = ?";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, method);
            stmt.setString(2, url);
            stmt.setString(3, host);
            stmt.setString(4, contentHash);
            
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt(1) > 0;
                }
            }
        } catch (SQLException e) {
            logger.debug("Failed to check for duplicate record", e);
        }
        
        return false;
    }
    
    /**
     * Removes duplicate records from the database and logs the operation.
     * 
     * @param sessionTag Optional session tag to filter duplicates
     * @return Map with deduplication results
     */
    public Map<String, Object> removeDuplicateRecords(String sessionTag) {
        if (shutdown.get() || connection == null) {
            return Map.of("error", "Database not available");
        }
        
        Map<String, Object> result = new HashMap<>();
        int recordsProcessed = 0;
        int duplicatesFound = 0;
        int duplicatesRemoved = 0;
        
        try {
            // First, identify duplicates
            StringBuilder findDuplicatesSql = new StringBuilder(
                "SELECT method, url, host, content_hash, COUNT(*) as count, " +
                "GROUP_CONCAT(id) as ids " +
                "FROM proxy_traffic WHERE 1=1"
            );
            
            List<Object> params = new ArrayList<>();
            if (sessionTag != null && !sessionTag.isEmpty()) {
                findDuplicatesSql.append(" AND session_tag = ?");
                params.add(sessionTag);
            }
            
            findDuplicatesSql.append(" GROUP BY method, url, host, content_hash HAVING count > 1");
            
            try (PreparedStatement stmt = getConnection().prepareStatement(findDuplicatesSql.toString())) {
                for (int i = 0; i < params.size(); i++) {
                    stmt.setObject(i + 1, params.get(i));
                }
                
                try (ResultSet rs = stmt.executeQuery()) {
                    while (rs.next()) {
                        duplicatesFound++;
                        String ids = rs.getString("ids");
                        int count = rs.getInt("count");
                        recordsProcessed += count;
                        
                        // Keep the first record (lowest ID) and delete the rest
                        String[] idArray = ids.split(",");
                        for (int i = 1; i < idArray.length; i++) {
                            try {
                                long idToDelete = Long.parseLong(idArray[i].trim());
                                String deleteSql = "DELETE FROM proxy_traffic WHERE id = ?";
                                try (PreparedStatement deleteStmt = getConnection().prepareStatement(deleteSql)) {
                                    deleteStmt.setLong(1, idToDelete);
                                    int deleted = deleteStmt.executeUpdate();
                                    if (deleted > 0) {
                                        duplicatesRemoved++;
                                    }
                                }
                            } catch (NumberFormatException e) {
                                logger.warn("Invalid ID format in duplicate removal: {}", idArray[i]);
                            }
                        }
                    }
                }
            }
            
            // Log the deduplication operation
            String logSql = "INSERT INTO deduplication_log " +
                          "(operation_type, records_processed, duplicates_found, duplicates_removed, session_tag) " +
                          "VALUES (?, ?, ?, ?, ?)";
            
            try (PreparedStatement logStmt = getConnection().prepareStatement(logSql)) {
                logStmt.setString(1, "MANUAL_DEDUPLICATION");
                logStmt.setInt(2, recordsProcessed);
                logStmt.setInt(3, duplicatesFound);
                logStmt.setInt(4, duplicatesRemoved);
                logStmt.setString(5, sessionTag);
                logStmt.executeUpdate();
            }
            
            result.put("operation", "deduplication_completed");
            result.put("records_processed", recordsProcessed);
            result.put("duplicate_groups_found", duplicatesFound);
            result.put("duplicate_records_removed", duplicatesRemoved);
            result.put("session_tag", sessionTag);
            result.put("timestamp", System.currentTimeMillis());
            
            logger.info("✅ Deduplication completed: {} duplicates removed from {} groups", 
                       duplicatesRemoved, duplicatesFound);
            
        } catch (SQLException e) {
            logger.error("Failed to remove duplicate records", e);
            result.put("error", "Deduplication failed: " + e.getMessage());
        }
        
        return result;
    }
    
    /**
     * Gets deduplication statistics and history.
     * 
     * @return Map with deduplication information
     */
    public Map<String, Object> getDeduplicationStats() {
        if (shutdown.get() || connection == null) {
            return Map.of("error", "Database not available");
        }
        
        Map<String, Object> stats = new HashMap<>();
        
        try {
            // Get current duplicate count
            String duplicateCountSql = "SELECT COUNT(*) as total_duplicates FROM (" +
                                     "SELECT method, url, host, content_hash, COUNT(*) as count " +
                                     "FROM proxy_traffic " +
                                     "GROUP BY method, url, host, content_hash " +
                                     "HAVING count > 1" +
                                     ")";
            
            try (PreparedStatement stmt = getConnection().prepareStatement(duplicateCountSql)) {
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        stats.put("current_duplicate_groups", rs.getInt("total_duplicates"));
                    }
                }
            }
            
            // Get total records with no content hash (need migration)
            String noHashSql = "SELECT COUNT(*) as no_hash_count FROM proxy_traffic WHERE content_hash IS NULL";
            try (PreparedStatement stmt = getConnection().prepareStatement(noHashSql)) {
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        stats.put("records_without_hash", rs.getInt("no_hash_count"));
                    }
                }
            }
            
            // Get deduplication history
            String historySql = "SELECT operation_type, operation_timestamp, records_processed, " +
                              "duplicates_found, duplicates_removed, session_tag " +
                              "FROM deduplication_log ORDER BY operation_timestamp DESC LIMIT 10";
            
            List<Map<String, Object>> history = new ArrayList<>();
            try (PreparedStatement stmt = getConnection().prepareStatement(historySql)) {
                try (ResultSet rs = stmt.executeQuery()) {
                    while (rs.next()) {
                        Map<String, Object> operation = new HashMap<>();
                        operation.put("operation_type", rs.getString("operation_type"));
                        operation.put("timestamp", rs.getTimestamp("operation_timestamp"));
                        operation.put("records_processed", rs.getInt("records_processed"));
                        operation.put("duplicates_found", rs.getInt("duplicates_found"));
                        operation.put("duplicates_removed", rs.getInt("duplicates_removed"));
                        operation.put("session_tag", rs.getString("session_tag"));
                        history.add(operation);
                    }
                }
            }
            
            stats.put("deduplication_history", history);
            stats.put("timestamp", System.currentTimeMillis());
            
        } catch (SQLException e) {
            logger.error("Failed to get deduplication statistics", e);
            stats.put("error", "Failed to get statistics: " + e.getMessage());
        }
        
        return stats;
    }
    
    /**
     * Stores raw HTTP traffic data (for uploads/imports) with deduplication.
     * 
     * @param method HTTP method
     * @param url URL
     * @param host Host
     * @param headers Headers string
     * @param body Body string
     * @param responseHeaders Response headers (optional)
     * @param responseBody Response body (optional)
     * @param statusCode Status code (optional)
     * @param sessionTag Session tag
     * @return Generated ID of the stored record, -1 if failed, -2 if duplicate skipped
     */
    public long storeRawTraffic(String method, String url, String host, 
                               String headers, String body, String responseHeaders, 
                               String responseBody, Integer statusCode, String sessionTag) {
        if (shutdown.get() || connection == null) {
            return -1;
        }
        
        // Generate content hash for deduplication
        String contentHash = generateContentHash(method, url, headers, body, responseHeaders, responseBody);
        
        // Check for duplicates
        if (isDuplicateRecord(method, url, host, contentHash)) {
            logger.debug("Skipping duplicate record: {} {} (Source: {})", method, url, sessionTag);
            return -2; // Indicate duplicate was skipped
        }
        
        String sql = "INSERT INTO proxy_traffic (" +
                    "timestamp, method, url, host, headers, body, response_headers, response_body, status_code, session_tag, content_hash" +
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setTimestamp(1, Timestamp.valueOf(LocalDateTime.now()));
            stmt.setString(2, sanitizeString(method, 10));
            stmt.setString(3, sanitizeString(url, 8192));
            stmt.setString(4, sanitizeString(host, 255));
            stmt.setString(5, sanitizeString(headers, 65536));
            stmt.setString(6, sanitizeString(body, 65536));
            stmt.setString(7, sanitizeString(responseHeaders, 65536));
            stmt.setString(8, sanitizeString(responseBody, 65536));
            stmt.setObject(9, statusCode);
            stmt.setString(10, sanitizeString(sessionTag, 100));
            stmt.setString(11, contentHash);
            
            int rowsAffected = stmt.executeUpdate();
            
            if (rowsAffected > 0) {
                // Use SQLite's last_insert_rowid() instead of getGeneratedKeys()
                try (PreparedStatement idStmt = getConnection().prepareStatement("SELECT last_insert_rowid()")) {
                    try (ResultSet rs = idStmt.executeQuery()) {
                        if (rs.next()) {
                            long id = rs.getLong(1);
                            logger.debug("Stored raw traffic: {} {} with ID {} (Source: {})", 
                                       method, url, id, sessionTag);
                            return id;
                        }
                    }
                }
            }
            
        } catch (SQLException e) {
            if (e.getMessage().contains("UNIQUE constraint failed")) {
                logger.debug("Duplicate record detected by database constraint: {} {} (Source: {})", 
                           method, url, sessionTag);
                return -2; // Indicate duplicate was rejected by database
            }
            logger.error("Failed to store raw traffic", e);
        }
        
        return -1;
    }
    
    /**
     * Stores raw traffic data with source tracking for unified logging.
     * 
     * @param method HTTP method
     * @param url Request URL  
     * @param host Host name
     * @param headers Request headers
     * @param body Request body
     * @param responseHeaders Response headers (optional)
     * @param responseBody Response body (optional)
     * @param statusCode Status code (optional)
     * @param sessionTag Session tag
     * @param source Traffic source for tracking
     * @return Generated ID of the stored record, -1 if failed, -2 if duplicate skipped
     */
    public long storeRawTrafficWithSource(String method, String url, String host, 
                                        String headers, String body, String responseHeaders, 
                                        String responseBody, Integer statusCode, String sessionTag,
                                        TrafficSource source) {
        if (shutdown.get() || connection == null) {
            return -1;
        }
        
        // Generate content hash for deduplication
        String contentHash = generateContentHash(method, url, headers, body, responseHeaders, responseBody);
        
        // Check for duplicates
        if (isDuplicateRecord(method, url, host, contentHash)) {
            logger.debug("Skipping duplicate record: {} {} (Source: {})", method, url, source);
            return -2; // Indicate duplicate was skipped
        }
        
        String sql = "INSERT INTO proxy_traffic (" +
                    "timestamp, method, url, host, headers, body, response_headers, response_body, status_code, session_tag, content_hash, traffic_source" +
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setTimestamp(1, Timestamp.valueOf(LocalDateTime.now()));
            stmt.setString(2, sanitizeString(method, 10));
            stmt.setString(3, sanitizeString(url, 8192));
            stmt.setString(4, sanitizeString(host, 255));
            stmt.setString(5, sanitizeString(headers, 65536));
            stmt.setString(6, sanitizeString(body, 65536));
            stmt.setString(7, sanitizeString(responseHeaders, 65536));
            stmt.setString(8, sanitizeString(responseBody, 65536));
            stmt.setObject(9, statusCode);
            stmt.setString(10, sanitizeString(sessionTag, 100));
            stmt.setString(11, contentHash);
            stmt.setString(12, source.getValue());
            
            int rowsAffected = stmt.executeUpdate();
            
            if (rowsAffected > 0) {
                // Use SQLite's last_insert_rowid() instead of getGeneratedKeys()
                try (PreparedStatement idStmt = getConnection().prepareStatement("SELECT last_insert_rowid()")) {
                    try (ResultSet rs = idStmt.executeQuery()) {
                        if (rs.next()) {
                            long id = rs.getLong(1);
                            logger.debug("Stored raw traffic with source: {} {} with ID {} (Source: {})", 
                                       method, url, id, source);
                            return id;
                        }
                    }
                }
            }
            
        } catch (SQLException e) {
            if (e.getMessage().contains("UNIQUE constraint failed")) {
                logger.debug("Duplicate record detected by database constraint: {} {} (Source: {})", 
                           method, url, source);
                return -2; // Indicate duplicate was rejected by database
            }
            logger.error("Failed to store raw traffic with source: " + source, e);
        }
        
        return -1;
    }
    
    /**
     * Stores a traffic record using the normalized schema with optimized batch processing.
     * Uses the new traffic_meta, traffic_requests, and traffic_responses tables.
     * 
     * @param method HTTP method
     * @param url Request URL
     * @param host Host header value
     * @param headers Request headers
     * @param body Request body
     * @param responseHeaders Response headers
     * @param responseBody Response body
     * @param statusCode HTTP response status code
     * @param sessionTag Session identifier
     * @param source Traffic source (PROXY, REPEATER, etc.)
     * @return traffic_meta ID if successful, -1 if failed, -2 if duplicate
     */
    public long storeTrafficNormalized(String method, String url, String host, String headers, String body,
                                      String responseHeaders, String responseBody, Integer statusCode, 
                                      String sessionTag, TrafficSource source) {
        if (shutdown.get() || connection == null) {
            return -1;
        }
        
        try {
            // Check if we should use normalized schema
            if (!schemaManager.isNormalizedSchemaAvailable(connection)) {
                // Fall back to legacy method
                return storeRawTrafficWithSource(method, url, host, headers, body, 
                                               responseHeaders, responseBody, statusCode, sessionTag, source);
            }
            
            // Generate content hash for deduplication
            String contentHash = generateContentHash(method, url, headers, body, responseHeaders, responseBody);
            
            // Use transaction for atomicity
            boolean originalAutoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);
            
            try {
                // Insert into traffic_meta
                long trafficMetaId = insertTrafficMeta(method, url, host, sessionTag, source, contentHash);
                if (trafficMetaId <= 0) {
                    connection.rollback();
                    return trafficMetaId; // Return -1 for error, -2 for duplicate
                }
                
                // Insert request data
                insertTrafficRequest(trafficMetaId, headers, body);
                
                // Insert response data (if available)
                if (statusCode != null || responseHeaders != null || responseBody != null) {
                    // Response time measurement would require timing at HTTP request level
                    // For now, use 0 as placeholder - future enhancement needed in HTTP loggers
                    insertTrafficResponse(trafficMetaId, statusCode, responseHeaders, responseBody, 0L);
                }
                
                connection.commit();
                
                logger.debug("Stored normalized traffic: {} {} with ID {} (Source: {})", 
                           method, url, trafficMetaId, source);
                
                return trafficMetaId;
                
            } catch (SQLException e) {
                connection.rollback();
                throw e;
            } finally {
                connection.setAutoCommit(originalAutoCommit);
            }
            
        } catch (SQLException e) {
            if (e.getMessage().contains("UNIQUE constraint failed") || e.getMessage().contains("content_hash")) {
                logger.debug("Duplicate record detected: {} {} (Source: {})", method, url, source);
                return -2;
            }
            logger.error("Failed to store normalized traffic", e);
            return -1;
        }
    }
    
    /**
     * Insert traffic metadata with optimized prepared statement
     */
    private long insertTrafficMeta(String method, String url, String host, String sessionTag, 
                                   TrafficSource source, String contentHash) throws SQLException {
        String sql = "INSERT INTO traffic_meta (timestamp, method, url, host, session_tag, tool_source, content_hash) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?)";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setTimestamp(1, Timestamp.valueOf(LocalDateTime.now()));
            stmt.setString(2, sanitizeString(method, 10));
            stmt.setString(3, sanitizeString(url, 8192));
            stmt.setString(4, sanitizeString(host, 255));
            stmt.setString(5, sanitizeString(sessionTag, 100));
            stmt.setString(6, source.getValue());
            stmt.setString(7, contentHash);
            
            int rowsAffected = stmt.executeUpdate();
            
            if (rowsAffected > 0) {
                // Get the generated ID
                try (PreparedStatement idStmt = getConnection().prepareStatement("SELECT last_insert_rowid()")) {
                    try (ResultSet rs = idStmt.executeQuery()) {
                        if (rs.next()) {
                            return rs.getLong(1);
                        }
                    }
                }
            }
        }
        
        return -1;
    }
    
    /**
     * Insert request data with content analysis
     */
    private void insertTrafficRequest(long trafficMetaId, String headers, String body) throws SQLException {
        String sql = "INSERT INTO traffic_requests (traffic_meta_id, headers, body, body_size, content_type) " +
                    "VALUES (?, ?, ?, ?, ?)";
        
        String contentType = extractContentType(headers);
        int bodySize = body != null ? body.length() : 0;
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setLong(1, trafficMetaId);
            stmt.setString(2, sanitizeString(headers, 65536));
            stmt.setString(3, sanitizeString(body, 65536));
            stmt.setInt(4, bodySize);
            stmt.setString(5, sanitizeString(contentType, 100));
            
            stmt.executeUpdate();
        }
    }
    
    /**
     * Insert response data with performance metrics
     */
    private void insertTrafficResponse(long trafficMetaId, Integer statusCode, String responseHeaders, 
                                       String responseBody, long responseTimeMs) throws SQLException {
        String sql = "INSERT INTO traffic_responses (traffic_meta_id, status_code, headers, body, body_size, content_type, response_time_ms) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?)";
        
        String contentType = extractContentType(responseHeaders);
        int bodySize = responseBody != null ? responseBody.length() : 0;
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setLong(1, trafficMetaId);
            stmt.setObject(2, statusCode);
            stmt.setString(3, sanitizeString(responseHeaders, 65536));
            stmt.setString(4, sanitizeString(responseBody, 65536));
            stmt.setInt(5, bodySize);
            stmt.setString(6, sanitizeString(contentType, 100));
            stmt.setLong(7, responseTimeMs);
            
            stmt.executeUpdate();
        }
    }
    
    /**
     * Extract content type from headers
     */
    private String extractContentType(String headers) {
        if (headers == null || headers.isEmpty()) {
            return "unknown";
        }
        
        String lowerHeaders = headers.toLowerCase();
        int contentTypeIndex = lowerHeaders.indexOf("content-type:");
        if (contentTypeIndex != -1) {
            int start = contentTypeIndex + 13; // Length of "content-type:"
            int end = lowerHeaders.indexOf('\n', start);
            if (end == -1) end = lowerHeaders.indexOf('\r', start);
            if (end == -1) end = headers.length();
            
            String contentType = headers.substring(start, end).trim();
            // Extract just the media type (before semicolon)
            int semicolonIndex = contentType.indexOf(';');
            if (semicolonIndex != -1) {
                contentType = contentType.substring(0, semicolonIndex).trim();
            }
            return contentType;
        }
        
        return "unknown";
    }

    /**
     * Search traffic using the normalized schema with enhanced filtering
     */
    public List<Map<String, Object>> searchTrafficNormalized(Map<String, Object> searchParams, 
                                                             int limit, int offset) {
        if (shutdown.get() || connection == null) {
            return new ArrayList<>();
        }
        
        // Fall back to legacy search if normalized schema not available
        try {
            if (!schemaManager.isNormalizedSchemaAvailable(connection)) {
                // Convert params and use legacy search
                Map<String, String> legacyParams = new HashMap<>();
                if (searchParams != null) {
                    searchParams.forEach((k, v) -> legacyParams.put(k, v != null ? v.toString() : null));
                }
                return searchTraffic(legacyParams);
            }
        } catch (SQLException e) {
            logger.error("Error checking normalized schema availability", e);
            return new ArrayList<>();
        }
        
        List<Map<String, Object>> results = new ArrayList<>();
        long queryStartTime = System.currentTimeMillis();
        
        // Build optimized query using normalized tables
        StringBuilder sql = new StringBuilder();
        sql.append("SELECT tm.id, tm.timestamp, tm.method, tm.url, tm.host, tm.session_tag, tm.tool_source, ")
           .append("tm.tags, tm.comment, tm.replayed_from, ")
           .append("tr.headers, tr.body, tr.body_size, tr.content_type as request_content_type, ")
           .append("tres.status_code, tres.headers as response_headers, tres.body as response_body, ")
           .append("tres.body_size as response_body_size, tres.content_type as response_content_type, ")
           .append("tres.response_time_ms ")
           .append("FROM traffic_meta tm ")
           .append("LEFT JOIN traffic_requests tr ON tm.id = tr.traffic_meta_id ")
           .append("LEFT JOIN traffic_responses tres ON tm.id = tres.traffic_meta_id ");
        
        List<Object> params = new ArrayList<>();
        
        // Add WHERE conditions
        if (searchParams != null && !searchParams.isEmpty()) {
            sql.append("WHERE 1=1 ");
            
            if (searchParams.containsKey("method")) {
                sql.append("AND tm.method = ? ");
                params.add(searchParams.get("method"));
            }
            
            if (searchParams.containsKey("host")) {
                sql.append("AND tm.host LIKE ? ");
                params.add("%" + searchParams.get("host") + "%");
            }
            
            if (searchParams.containsKey("url")) {
                sql.append("AND tm.url LIKE ? ");
                params.add("%" + searchParams.get("url") + "%");
            }
            
            if (searchParams.containsKey("status_code")) {
                sql.append("AND tres.status_code = ? ");
                params.add(searchParams.get("status_code"));
            }
            
            if (searchParams.containsKey("session_tag")) {
                sql.append("AND tm.session_tag = ? ");
                params.add(searchParams.get("session_tag"));
            }
            
            if (searchParams.containsKey("tool_source")) {
                sql.append("AND tm.tool_source = ? ");
                params.add(searchParams.get("tool_source"));
            }
            
            if (searchParams.containsKey("start_time")) {
                sql.append("AND tm.timestamp >= ? ");
                params.add(parseTimestamp(searchParams.get("start_time").toString()));
            }
            
            if (searchParams.containsKey("end_time")) {
                sql.append("AND tm.timestamp <= ? ");
                params.add(parseTimestamp(searchParams.get("end_time").toString()));
            }
            
            // Phase 10 enhanced search parameters
            if (searchParams.containsKey("tags")) {
                sql.append("AND tm.tags LIKE ? ");
                params.add("%" + searchParams.get("tags") + "%");
            }
            
            if (searchParams.containsKey("comment")) {
                sql.append("AND tm.comment LIKE ? ");
                params.add("%" + searchParams.get("comment") + "%");
            }
            
            if (searchParams.containsKey("replayed_from")) {
                sql.append("AND tm.replayed_from = ? ");
                params.add(searchParams.get("replayed_from"));
            }
            
            if (searchParams.containsKey("request_body_contains")) {
                sql.append("AND tr.body LIKE ? ");
                params.add("%" + searchParams.get("request_body_contains") + "%");
            }
        }
        
        // Add ordering and pagination
        sql.append("ORDER BY tm.timestamp DESC ");
        sql.append("LIMIT ? OFFSET ?");
        params.add(limit);
        params.add(offset);
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql.toString())) {
            // Set parameters
            for (int i = 0; i < params.size(); i++) {
                stmt.setObject(i + 1, params.get(i));
            }
            
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> record = new HashMap<>();
                    record.put("id", rs.getLong("id"));
                    record.put("timestamp", rs.getTimestamp("timestamp"));
                    record.put("method", rs.getString("method"));
                    record.put("url", rs.getString("url"));
                    record.put("host", rs.getString("host"));
                    record.put("session_tag", rs.getString("session_tag"));
                    record.put("tool_source", rs.getString("tool_source"));
                    record.put("tags", rs.getString("tags"));
                    record.put("comment", rs.getString("comment"));
                    record.put("replayed_from", rs.getObject("replayed_from"));
                    record.put("headers", rs.getString("headers"));
                    record.put("body", rs.getString("body"));
                    record.put("body_size", rs.getInt("body_size"));
                    record.put("request_content_type", rs.getString("request_content_type"));
                    record.put("status_code", rs.getObject("status_code"));
                    record.put("response_headers", rs.getString("response_headers"));
                    record.put("response_body", rs.getString("response_body"));
                    record.put("response_body_size", rs.getInt("response_body_size"));
                    record.put("response_content_type", rs.getString("response_content_type"));
                    record.put("response_time_ms", rs.getInt("response_time_ms"));
                    results.add(record);
                }
            }
            
            long queryTime = System.currentTimeMillis() - queryStartTime;
            logger.debug("Normalized search completed: {} results in {}ms", results.size(), queryTime);
            
            // Log slow queries for performance monitoring
            if (queryTime > 5000) {
                logger.warn("Slow normalized query: {}ms for {} results", queryTime, results.size());
            }
            
        } catch (SQLException e) {
            logger.error("Failed to search normalized traffic", e);
        }
        
        return results;
    }
    
    /**
     * Perform full-text search using FTS5 if available
     */
    public List<Map<String, Object>> searchTrafficFullText(String searchQuery, int limit, int offset) {
        if (shutdown.get() || connection == null) {
            return new ArrayList<>();
        }
        
        // Check if FTS5 is available
        try {
            if (!schemaManager.isFTS5SearchAvailable(connection)) {
                logger.warn("FTS5 search not available, falling back to LIKE search");
                return searchTrafficLike(searchQuery, limit, offset);
            }
        } catch (SQLException e) {
            logger.error("Error checking FTS5 availability", e);
            return new ArrayList<>();
        }
        
        List<Map<String, Object>> results = new ArrayList<>();
        long queryStartTime = System.currentTimeMillis();
        
        String sql = "SELECT tm.id, tm.timestamp, tm.method, tm.url, tm.host, tm.session_tag, tm.tool_source, " +
                    "tr.headers, tr.body, tres.status_code, tres.headers as response_headers, tres.body as response_body " +
                    "FROM response_index ri " +
                    "JOIN traffic_meta tm ON tm.id = ri.traffic_meta_id " +
                    "LEFT JOIN traffic_requests tr ON tm.id = tr.traffic_meta_id " +
                    "LEFT JOIN traffic_responses tres ON tm.id = tres.traffic_meta_id " +
                    "WHERE response_index MATCH ? " +
                    "ORDER BY tm.timestamp DESC " +
                    "LIMIT ? OFFSET ?";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, searchQuery);
            stmt.setInt(2, limit);
            stmt.setInt(3, offset);
            
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> record = new HashMap<>();
                    record.put("id", rs.getLong("id"));
                    record.put("timestamp", rs.getTimestamp("timestamp"));
                    record.put("method", rs.getString("method"));
                    record.put("url", rs.getString("url"));
                    record.put("host", rs.getString("host"));
                    record.put("session_tag", rs.getString("session_tag"));
                    record.put("tool_source", rs.getString("tool_source"));
                    record.put("headers", rs.getString("headers"));
                    record.put("body", rs.getString("body"));
                    record.put("status_code", rs.getObject("status_code"));
                    record.put("response_headers", rs.getString("response_headers"));
                    record.put("response_body", rs.getString("response_body"));
                    results.add(record);
                }
            }
            
            long queryTime = System.currentTimeMillis() - queryStartTime;
            logger.debug("FTS5 search completed: {} results in {}ms", results.size(), queryTime);
            
        } catch (SQLException e) {
            logger.error("Failed to perform FTS5 search", e);
        }
        
        return results;
    }
    
    /**
     * Fallback LIKE-based search when FTS5 is not available
     */
    private List<Map<String, Object>> searchTrafficLike(String searchQuery, int limit, int offset) {
        Map<String, Object> searchParams = new HashMap<>();
        // Simple fallback - search in URL
        searchParams.put("url", searchQuery);
        return searchTrafficNormalized(searchParams, limit, offset);
    }

    /**
     * Gets a traffic record by ID for replay purposes.
     * 
     * @param id The record ID
     * @return Traffic record map or null if not found
     */
    public Map<String, Object> getTrafficById(long id) {
        if (shutdown.get() || connection == null) {
            return null;
        }
        
        String sql = "SELECT * FROM proxy_traffic WHERE id = ?";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setLong(1, id);
            
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    Map<String, Object> record = new HashMap<>();
                    record.put("id", rs.getLong("id"));
                    record.put("timestamp", rs.getTimestamp("timestamp"));
                    record.put("method", rs.getString("method"));
                    record.put("url", rs.getString("url"));
                    record.put("host", rs.getString("host"));
                    record.put("status_code", rs.getObject("status_code"));
                    record.put("headers", rs.getString("headers"));
                    record.put("body", rs.getString("body"));
                    record.put("response_headers", rs.getString("response_headers"));
                    record.put("response_body", rs.getString("response_body"));
                    record.put("session_tag", rs.getString("session_tag"));
                    return record;
                }
            }
            
        } catch (SQLException e) {
            logger.error("Failed to get traffic by ID", e);
        }
        
        return null;
    }
    
    /**
     * Gets traffic statistics grouped by host, method, and status code.
     * 
     * @param searchParams Optional search parameters for filtering
     * @return Statistics data grouped by various dimensions
     */
    public Map<String, Object> getTrafficStats(Map<String, String> searchParams) {
        if (shutdown.get() || connection == null) {
            return new HashMap<>();
        }
        
        Map<String, Object> stats = new HashMap<>();
        
        try {
            // Build base WHERE clause from search parameters
            StringBuilder whereClause = new StringBuilder("WHERE 1=1");
            List<Object> parameters = new ArrayList<>();
            
            if (searchParams.containsKey("host")) {
                whereClause.append(" AND host LIKE ?");
                parameters.add("%" + searchParams.get("host") + "%");
            }
            if (searchParams.containsKey("method")) {
                whereClause.append(" AND method = ?");
                parameters.add(searchParams.get("method"));
            }
            if (searchParams.containsKey("session_tag")) {
                whereClause.append(" AND session_tag = ?");
                parameters.add(searchParams.get("session_tag"));
            }
            if (searchParams.containsKey("start_time")) {
                whereClause.append(" AND timestamp >= ?");
                parameters.add(parseTimestamp(searchParams.get("start_time")));
            }
            if (searchParams.containsKey("end_time")) {
                whereClause.append(" AND timestamp <= ?");
                parameters.add(parseTimestamp(searchParams.get("end_time")));
            }
            
            // Total count
            String totalSql = "SELECT COUNT(*) as total FROM proxy_traffic " + whereClause;
            try (PreparedStatement stmt = getConnection().prepareStatement(totalSql)) {
                for (int i = 0; i < parameters.size(); i++) {
                    stmt.setObject(i + 1, parameters.get(i));
                }
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) {
                    stats.put("total_requests", rs.getLong("total"));
                }
            }
            
            // Count of requests with responses
            String completedSql = "SELECT COUNT(*) as completed FROM proxy_traffic " + 
                                whereClause + " AND status_code IS NOT NULL";
            try (PreparedStatement stmt = getConnection().prepareStatement(completedSql)) {
                for (int i = 0; i < parameters.size(); i++) {
                    stmt.setObject(i + 1, parameters.get(i));
                }
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) {
                    stats.put("completed_requests", rs.getLong("completed"));
                }
            }
            
            // Count of orphaned requests (no response)
            String orphanedSql = "SELECT COUNT(*) as orphaned FROM proxy_traffic " + 
                                whereClause + " AND status_code IS NULL";
            try (PreparedStatement stmt = getConnection().prepareStatement(orphanedSql)) {
                for (int i = 0; i < parameters.size(); i++) {
                    stmt.setObject(i + 1, parameters.get(i));
                }
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) {
                    stats.put("orphaned_requests", rs.getLong("orphaned"));
                }
            }
            
            // Recent orphaned requests (last 10 minutes)
            String recentOrphanedSql = "SELECT COUNT(*) as recent_orphaned FROM proxy_traffic " + 
                                     whereClause + " AND status_code IS NULL " +
                                     "AND timestamp > datetime('now', '-10 minutes')";
            try (PreparedStatement stmt = getConnection().prepareStatement(recentOrphanedSql)) {
                for (int i = 0; i < parameters.size(); i++) {
                    stmt.setObject(i + 1, parameters.get(i));
                }
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) {
                    stats.put("recent_orphaned_requests", rs.getLong("recent_orphaned"));
                }
            }
            
            // Stats by host
            String hostSql = "SELECT host, COUNT(*) as count FROM proxy_traffic " + 
                           whereClause + " GROUP BY host ORDER BY count DESC LIMIT 50";
            try (PreparedStatement stmt = getConnection().prepareStatement(hostSql)) {
                for (int i = 0; i < parameters.size(); i++) {
                    stmt.setObject(i + 1, parameters.get(i));
                }
                ResultSet rs = stmt.executeQuery();
                List<Map<String, Object>> hostStats = new ArrayList<>();
                while (rs.next()) {
                    Map<String, Object> hostStat = new HashMap<>();
                    hostStat.put("host", rs.getString("host"));
                    hostStat.put("count", rs.getLong("count"));
                    hostStats.add(hostStat);
                }
                stats.put("by_host", hostStats);
            }
            
            // Stats by method
            String methodSql = "SELECT method, COUNT(*) as count FROM proxy_traffic " + 
                             whereClause + " GROUP BY method ORDER BY count DESC";
            try (PreparedStatement stmt = getConnection().prepareStatement(methodSql)) {
                for (int i = 0; i < parameters.size(); i++) {
                    stmt.setObject(i + 1, parameters.get(i));
                }
                ResultSet rs = stmt.executeQuery();
                List<Map<String, Object>> methodStats = new ArrayList<>();
                while (rs.next()) {
                    Map<String, Object> methodStat = new HashMap<>();
                    methodStat.put("method", rs.getString("method"));
                    methodStat.put("count", rs.getLong("count"));
                    methodStats.add(methodStat);
                }
                stats.put("by_method", methodStats);
            }
            
            // Stats by status code
            String statusSql = "SELECT status_code, COUNT(*) as count FROM proxy_traffic " + 
                             whereClause + " AND status_code IS NOT NULL GROUP BY status_code ORDER BY count DESC";
            try (PreparedStatement stmt = getConnection().prepareStatement(statusSql)) {
                for (int i = 0; i < parameters.size(); i++) {
                    stmt.setObject(i + 1, parameters.get(i));
                }
                ResultSet rs = stmt.executeQuery();
                List<Map<String, Object>> statusStats = new ArrayList<>();
                while (rs.next()) {
                    Map<String, Object> statusStat = new HashMap<>();
                    statusStat.put("status_code", rs.getInt("status_code"));
                    statusStat.put("count", rs.getLong("count"));
                    statusStats.add(statusStat);
                }
                stats.put("by_status_code", statusStats);
            }
            
            // Stats by session tag
            String sessionSql = "SELECT session_tag, COUNT(*) as count FROM proxy_traffic " + 
                              whereClause + " GROUP BY session_tag ORDER BY count DESC LIMIT 20";
            try (PreparedStatement stmt = getConnection().prepareStatement(sessionSql)) {
                for (int i = 0; i < parameters.size(); i++) {
                    stmt.setObject(i + 1, parameters.get(i));
                }
                ResultSet rs = stmt.executeQuery();
                List<Map<String, Object>> sessionStats = new ArrayList<>();
                while (rs.next()) {
                    Map<String, Object> sessionStat = new HashMap<>();
                    sessionStat.put("session_tag", rs.getString("session_tag"));
                    sessionStat.put("count", rs.getLong("count"));
                    sessionStats.add(sessionStat);
                }
                stats.put("by_session_tag", sessionStats);
            }
            
        } catch (SQLException e) {
            logger.error("Failed to get traffic statistics", e);
        }
        
        return stats;
    }
    
    /**
     * Gets traffic statistics grouped by traffic source for unified logging analytics.
     * 
     * @return Statistics data grouped by traffic source
     */
    public Map<String, Object> getTrafficStatsBySource() {
        if (shutdown.get() || connection == null) {
            return new HashMap<>();
        }
        
        Map<String, Object> stats = new HashMap<>();
        
        try {
            // Total count by traffic source
            String sourceSql = "SELECT traffic_source, COUNT(*) as count FROM proxy_traffic " +
                             "GROUP BY traffic_source ORDER BY count DESC";
            
            try (PreparedStatement stmt = getConnection().prepareStatement(sourceSql)) {
                ResultSet rs = stmt.executeQuery();
                List<Map<String, Object>> sourceStats = new ArrayList<>();
                while (rs.next()) {
                    Map<String, Object> sourceStat = new HashMap<>();
                    sourceStat.put("source", rs.getString("traffic_source"));
                    sourceStat.put("count", rs.getLong("count"));
                    sourceStats.add(sourceStat);
                }
                stats.put("by_source", sourceStats);
            }
            
            // Success rates by source
            String successRateSql = "SELECT traffic_source, " +
                                  "COUNT(*) as total_requests, " +
                                  "COUNT(CASE WHEN status_code IS NOT NULL THEN 1 END) as completed_requests, " +
                                  "COUNT(CASE WHEN status_code >= 200 AND status_code < 300 THEN 1 END) as success_requests, " +
                                  "COUNT(CASE WHEN status_code >= 400 THEN 1 END) as error_requests " +
                                  "FROM proxy_traffic GROUP BY traffic_source ORDER BY total_requests DESC";
            
            try (PreparedStatement stmt = getConnection().prepareStatement(successRateSql)) {
                ResultSet rs = stmt.executeQuery();
                List<Map<String, Object>> successRateStats = new ArrayList<>();
                while (rs.next()) {
                    Map<String, Object> rateStat = new HashMap<>();
                    long totalRequests = rs.getLong("total_requests");
                    long completedRequests = rs.getLong("completed_requests");
                    long successRequests = rs.getLong("success_requests");
                    long errorRequests = rs.getLong("error_requests");
                    
                    rateStat.put("source", rs.getString("traffic_source"));
                    rateStat.put("total_requests", totalRequests);
                    rateStat.put("completed_requests", completedRequests);
                    rateStat.put("success_requests", successRequests);
                    rateStat.put("error_requests", errorRequests);
                    
                    // Calculate percentages
                    if (totalRequests > 0) {
                        rateStat.put("completion_rate", Math.round((completedRequests * 100.0) / totalRequests));
                    } else {
                        rateStat.put("completion_rate", 0);
                    }
                    
                    if (completedRequests > 0) {
                        rateStat.put("success_rate", Math.round((successRequests * 100.0) / completedRequests));
                        rateStat.put("error_rate", Math.round((errorRequests * 100.0) / completedRequests));
                    } else {
                        rateStat.put("success_rate", 0);
                        rateStat.put("error_rate", 0);
                    }
                    
                    successRateStats.add(rateStat);
                }
                stats.put("success_rates_by_source", successRateStats);
            }
            
            // Recent activity by source (last 24 hours)
            String recentSql = "SELECT traffic_source, COUNT(*) as recent_count " +
                             "FROM proxy_traffic WHERE timestamp > datetime('now', '-24 hours') " +
                             "GROUP BY traffic_source ORDER BY recent_count DESC";
            
            try (PreparedStatement stmt = getConnection().prepareStatement(recentSql)) {
                ResultSet rs = stmt.executeQuery();
                List<Map<String, Object>> recentStats = new ArrayList<>();
                while (rs.next()) {
                    Map<String, Object> recentStat = new HashMap<>();
                    recentStat.put("source", rs.getString("traffic_source"));
                    recentStat.put("recent_count", rs.getLong("recent_count"));
                    recentStats.add(recentStat);
                }
                stats.put("recent_activity_by_source", recentStats);
            }
            
            // Overall summary
            String totalSql = "SELECT COUNT(*) as total_records FROM proxy_traffic";
            try (PreparedStatement stmt = getConnection().prepareStatement(totalSql)) {
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) {
                    stats.put("total_records", rs.getLong("total_records"));
                }
            }
            
        } catch (SQLException e) {
            logger.error("Failed to get traffic statistics by source", e);
        }
        
        return stats;
    }
    
    /**
     * Gets traffic timeline grouped by time intervals.
     * Uses actual request dates from response headers instead of database import timestamps.
     * 
     * @param searchParams Search parameters for filtering
     * @param interval Time interval for grouping (hour, day, minute)
     * @return Timeline data grouped by time intervals
     */
    public List<Map<String, Object>> getTrafficTimeline(Map<String, String> searchParams, String interval) {
        if (shutdown.get() || connection == null) {
            return new ArrayList<>();
        }
        
        // Since we need to parse response headers to get actual request dates,
        // we'll fetch the data and process it in Java rather than SQL
        Map<String, Map<String, Long>> timelineMap = new HashMap<>();
        
        try {
            // Build WHERE clause for initial filtering
            StringBuilder whereClause = new StringBuilder("WHERE 1=1");
            List<Object> parameters = new ArrayList<>();
            
            if (searchParams.containsKey("host")) {
                whereClause.append(" AND host LIKE ?");
                parameters.add("%" + searchParams.get("host") + "%");
            }
            if (searchParams.containsKey("method")) {
                whereClause.append(" AND method = ?");
                parameters.add(searchParams.get("method"));
            }
            if (searchParams.containsKey("session_tag")) {
                whereClause.append(" AND session_tag = ?");
                parameters.add(searchParams.get("session_tag"));
            }
            // Note: start_time/end_time filtering will be done after parsing response headers
            
            String sql = "SELECT id, status_code, response_headers " +
                        "FROM proxy_traffic " + whereClause + 
                        " AND response_headers IS NOT NULL";
            
            try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
                for (int i = 0; i < parameters.size(); i++) {
                    stmt.setObject(i + 1, parameters.get(i));
                }
                
                ResultSet rs = stmt.executeQuery();
                while (rs.next()) {
                    String responseHeaders = rs.getString("response_headers");
                    int statusCode = rs.getInt("status_code");
                    
                    // Extract Date header from response headers
                    String actualRequestDate = extractDateFromHeaders(responseHeaders);
                    if (actualRequestDate != null) {
                        // Apply time range filtering if specified
                        if (searchParams.containsKey("start_time") || searchParams.containsKey("end_time")) {
                            try {
                                java.time.LocalDateTime requestDateTime = parseHttpDate(actualRequestDate);
                                if (requestDateTime != null) {
                                    if (searchParams.containsKey("start_time")) {
                                        java.time.LocalDateTime startTime = java.time.LocalDateTime.parse(searchParams.get("start_time").replace("T", " "), 
                                            java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
                                        if (requestDateTime.isBefore(startTime)) continue;
                                    }
                                    if (searchParams.containsKey("end_time")) {
                                        java.time.LocalDateTime endTime = java.time.LocalDateTime.parse(searchParams.get("end_time").replace("T", " "), 
                                            java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
                                        if (requestDateTime.isAfter(endTime)) continue;
                                    }
                                }
                            } catch (Exception e) {
                                logger.debug("Failed to parse date for filtering: {}", actualRequestDate);
                                continue;
                            }
                        }
                        
                        String timePeriod = formatDateForInterval(actualRequestDate, interval);
                        if (timePeriod != null) {
                            timelineMap.computeIfAbsent(timePeriod, k -> {
                                Map<String, Long> counts = new HashMap<>();
                                counts.put("total", 0L);
                                counts.put("success", 0L);
                                counts.put("error", 0L);
                                return counts;
                            });
                            
                            Map<String, Long> counts = timelineMap.get(timePeriod);
                            counts.put("total", counts.get("total") + 1);
                            
                            if (statusCode >= 200 && statusCode < 300) {
                                counts.put("success", counts.get("success") + 1);
                            } else if (statusCode >= 400) {
                                counts.put("error", counts.get("error") + 1);
                            }
                        }
                    }
                }
            }
            
        } catch (SQLException e) {
            logger.error("Failed to get traffic timeline", e);
        }
        
        // Convert map to sorted list
        List<Map<String, Object>> timeline = new ArrayList<>();
        timelineMap.entrySet().stream()
            .sorted(Map.Entry.comparingByKey())
            .forEach(entry -> {
                Map<String, Object> timePoint = new HashMap<>();
                timePoint.put("time_period", entry.getKey());
                timePoint.put("total_count", entry.getValue().get("total"));
                timePoint.put("success_count", entry.getValue().get("success"));
                timePoint.put("error_count", entry.getValue().get("error"));
                timeline.add(timePoint);
            });
        
        return timeline;
    }
    
    /**
     * Extracts the Date header from HTTP response headers.
     */
    private String extractDateFromHeaders(String responseHeaders) {
        if (responseHeaders == null || responseHeaders.isEmpty()) {
            return null;
        }
        
        // Remove array brackets if present
        String headers = responseHeaders;
        if (headers.startsWith("[") && headers.endsWith("]")) {
            headers = headers.substring(1, headers.length() - 1);
        }
        
        // Look for Date: header using regex to handle the comma-separated format properly
        java.util.regex.Pattern datePattern = java.util.regex.Pattern.compile("Date:\\s*([^,]+(?:,\\s*\\d{2}\\s+\\w{3}\\s+\\d{4}\\s+[^,]+GMT))", java.util.regex.Pattern.CASE_INSENSITIVE);
        java.util.regex.Matcher matcher = datePattern.matcher(headers);
        if (matcher.find()) {
            return matcher.group(1).trim();
        }
        
        return null;
    }
    
    /**
     * Parses HTTP date format to LocalDateTime.
     */
    private java.time.LocalDateTime parseHttpDate(String httpDate) {
        try {
            // HTTP dates are in GMT/UTC format like "Fri, 30 May 2025 19:32:36 GMT"
            java.time.format.DateTimeFormatter formatter = java.time.format.DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss zzz", java.util.Locale.ENGLISH);
            java.time.ZonedDateTime zonedDateTime = java.time.ZonedDateTime.parse(httpDate, formatter);
            return zonedDateTime.toLocalDateTime();
        } catch (Exception e) {
            logger.debug("Failed to parse HTTP date: {}", httpDate);
            return null;
        }
    }
    
    /**
     * Formats a date string according to the specified interval.
     */
    private String formatDateForInterval(String httpDate, String interval) {
        try {
            java.time.LocalDateTime dateTime = parseHttpDate(httpDate);
            if (dateTime == null) return null;
            
            switch (interval.toLowerCase()) {
                case "minute":
                    return dateTime.format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm"));
                case "hour":
                    return dateTime.format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH"));
                case "day":
                    return dateTime.format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd"));
                default:
                    return dateTime.format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH"));
            }
        } catch (Exception e) {
            logger.debug("Failed to format date for interval: {}", httpDate);
            return null;
        }
    }
    
    /**
     * Gets traffic data formatted for HAR export.
     * 
     * @param searchParams Search parameters for filtering
     * @return List of traffic records with full request/response data
     */
    public List<Map<String, Object>> getTrafficForHarExport(Map<String, String> searchParams) {
        if (shutdown.get() || connection == null) {
            return new ArrayList<>();
        }
        
        List<Map<String, Object>> harEntries = new ArrayList<>();
        
        try {
            StringBuilder sql = new StringBuilder(
                "SELECT id, timestamp, method, url, host, headers, body, " +
                "status_code, response_headers, response_body " +
                "FROM proxy_traffic WHERE 1=1"
            );
            
            List<Object> parameters = new ArrayList<>();
            
            // Apply search filters
            if (searchParams.containsKey("host")) {
                String caseClause = searchParams.containsKey("case_insensitive") && 
                                  Boolean.parseBoolean(searchParams.get("case_insensitive")) ? 
                                  "LOWER(host) LIKE LOWER(?)" : "host LIKE ?";
                sql.append(" AND ").append(caseClause);
                parameters.add("%" + searchParams.get("host") + "%");
            }
            if (searchParams.containsKey("method")) {
                sql.append(" AND method = ?");
                parameters.add(searchParams.get("method"));
            }
            if (searchParams.containsKey("session_tag")) {
                sql.append(" AND session_tag = ?");
                parameters.add(searchParams.get("session_tag"));
            }
            if (searchParams.containsKey("start_time")) {
                sql.append(" AND timestamp >= ?");
                parameters.add(parseTimestamp(searchParams.get("start_time")));
            }
            if (searchParams.containsKey("end_time")) {
                sql.append(" AND timestamp <= ?");
                parameters.add(parseTimestamp(searchParams.get("end_time")));
            }
            
            // Only include requests that have responses for valid HAR
            sql.append(" AND status_code IS NOT NULL");
            sql.append(" ORDER BY timestamp");
            
            // Apply limit if specified
            if (searchParams.containsKey("limit")) {
                sql.append(" LIMIT ?");
                parameters.add(Integer.parseInt(searchParams.get("limit")));
            }
            
            try (PreparedStatement stmt = getConnection().prepareStatement(sql.toString())) {
                for (int i = 0; i < parameters.size(); i++) {
                    stmt.setObject(i + 1, parameters.get(i));
                }
                
                ResultSet rs = stmt.executeQuery();
                while (rs.next()) {
                    Map<String, Object> entry = new HashMap<>();
                    entry.put("id", rs.getLong("id"));
                    entry.put("timestamp", rs.getTimestamp("timestamp"));
                    entry.put("method", rs.getString("method"));
                    entry.put("url", rs.getString("url"));
                    entry.put("host", rs.getString("host"));
                    entry.put("headers", rs.getString("headers"));
                    entry.put("body", rs.getString("body"));
                    entry.put("status_code", rs.getInt("status_code"));
                    entry.put("response_headers", rs.getString("response_headers"));
                    entry.put("response_body", rs.getString("response_body"));
                    harEntries.add(entry);
                }
            }
            
        } catch (SQLException e) {
            logger.error("Failed to get traffic for HAR export", e);
        }
        
        return harEntries;
    }
    
    /**
     * Imports existing proxy history from the current Burp project into the database.
     * This method extracts all proxy history items and stores them with IMPORTED source.
     * 
     * @param api The MontoyaApi instance to access proxy history
     * @param sessionTag Session tag to use for imported data
     * @return Number of records imported (not including duplicates)
     */
    public int importExistingProxyHistory(burp.api.montoya.MontoyaApi api, String sessionTag) {
        if (shutdown.get() || connection == null) {
            logger.warn("Cannot import proxy history - database not available");
            return 0;
        }

        logger.info("🔄 Starting COMPREHENSIVE MULTI-PASS import of existing proxy history...");
        
        // STRATEGY: Multiple passes with delays to capture ALL historical data
        // Burp's API buffer may only show recent data on first call, but subsequent calls
        // after delays might reveal older data as the buffer updates
        
        java.util.Set<String> seenContentHashes = new java.util.HashSet<>();
        int totalImported = 0;
        int totalErrors = 0;
        int pass = 1;
        
        try {
            // MULTI-PASS IMPORT STRATEGY
            while (pass <= 5) { // Try up to 5 passes
                logger.info("📋 IMPORT PASS {}/5: Calling api.proxy().history()...", pass);
                
                java.util.List<burp.api.montoya.proxy.ProxyHttpRequestResponse> proxyHistory = api.proxy().history();
                logger.info("📋 Pass {} returned {} proxy history items", pass, proxyHistory.size());
                
                if (proxyHistory.isEmpty()) {
                    if (pass == 1) {
                        logger.error("❌ NO PROXY HISTORY ACCESSIBLE on first pass - This indicates:");
                        logger.error("   1. Burp API buffer limitations (older history not accessible)");
                        logger.error("   2. Scope filtering excluding all historical data");
                        logger.error("   3. Project state issue preventing API access");
                        logger.error("   4. Extension loaded before proxy history populated API buffer");
                        logger.error("💡 RECOMMENDATION: Check Burp's Proxy > HTTP History tab to verify data exists");
                        return 0;
                    } else {
                        logger.info("✅ Pass {} returned no new data - import may be complete", pass);
                        break;
                    }
                }
                
                // Process this pass's data
                int passImported = 0;
                int passDuplicates = 0;
                int passErrors = 0;
                
                // Check for oldest and newest timestamps in this batch
                long oldestTimestamp = Long.MAX_VALUE;
                long newestTimestamp = 0;
                
                for (burp.api.montoya.proxy.ProxyHttpRequestResponse item : proxyHistory) {
                    try {
                        // Extract request data for deduplication
                        burp.api.montoya.http.message.requests.HttpRequest request = item.finalRequest();
                        burp.api.montoya.http.message.responses.HttpResponse response = item.originalResponse();
                        
                        String method = request.method();
                        String url = request.url();
                        String host = request.httpService().host();
                        String requestHeaders = request.headers().toString();
                        String requestBody = request.bodyToString();
                        
                        // Extract response data (if available)
                        String responseHeaders = null;
                        String responseBody = null;
                        Integer statusCode = null;
                        
                        if (response != null) {
                            statusCode = (int) response.statusCode();
                            responseHeaders = response.headers().toString();
                            responseBody = response.bodyToString();
                        }
                        
                        // Generate content hash for deduplication across passes
                        String contentHash = generateContentHash(method, url, requestHeaders, requestBody, responseHeaders, responseBody);
                        
                        if (seenContentHashes.contains(contentHash)) {
                            passDuplicates++;
                            continue; // Skip duplicate from previous pass
                        }
                        seenContentHashes.add(contentHash);
                        
                        // Track timestamp range for this pass
                        // Note: Burp doesn't expose request timestamp directly, so we use current time
                        // This is a limitation of Burp's API
                        long currentTime = System.currentTimeMillis();
                        oldestTimestamp = Math.min(oldestTimestamp, currentTime);
                        newestTimestamp = Math.max(newestTimestamp, currentTime);
                        
                        // Store in database
                        long recordId = storeRawTrafficWithSource(
                            method, url, host,
                            requestHeaders, requestBody,
                            responseHeaders, responseBody,
                            statusCode, sessionTag + "_imported_pass" + pass, 
                            TrafficSource.IMPORTED
                        );
                        
                        if (recordId > 0) {
                            passImported++;
                            totalImported++;
                            if (totalImported % 50 == 0) {
                                logger.info("📥 Imported {} total records across {} passes...", totalImported, pass);
                            }
                        }
                        
                    } catch (Exception e) {
                        passErrors++;
                        totalErrors++;
                        if (totalErrors <= 10) {
                            logger.warn("Error importing proxy history item in pass {}: {}", pass, e.getMessage());
                        }
                    }
                }
                
                logger.info("📋 Pass {} completed: {} new records, {} duplicates, {} errors", 
                           pass, passImported, passDuplicates, passErrors);
                
                // If we got very few new records on this pass, the API buffer may be exhausted
                if (passImported < 10 && pass > 1) {
                    logger.info("✅ Low new record count on pass {} - API buffer likely exhausted", pass);
                    break;
                }
                
                // Wait before next pass to let Burp's API buffer potentially refresh
                if (pass < 5) {
                    int delaySeconds = Math.min(10 * pass, 30); // Progressive delay: 10s, 20s, 30s, 30s
                    logger.info("⏱️ Waiting {} seconds before pass {}...", delaySeconds, pass + 1);
                    Thread.sleep(delaySeconds * 1000);
                }
                
                pass++;
            }
            
            // Final assessment
            logger.info("🎯 MULTI-PASS IMPORT SUMMARY:");
            logger.info("   📊 Total passes attempted: {}", pass - 1);
            logger.info("   📥 Total records imported: {}", totalImported);
            logger.info("   🔄 Total duplicates skipped: {}", seenContentHashes.size() - totalImported);
            logger.info("   ❌ Total errors: {}", totalErrors);
            
            if (totalImported < 1000) {
                logger.warn("⚠️ LOW TOTAL IMPORT COUNT: {} - This suggests Burp API limitations", totalImported);
                logger.warn("   Older data you see in Burp's UI may not be accessible via api.proxy().history()");
                logger.warn("   This is a known limitation of Burp's proxy history API buffer");
            } else {
                logger.info("✅ Successfully imported substantial proxy history: {} records", totalImported);
            }
            
            // Log the import operation
            try {
                String logSql = "INSERT INTO deduplication_log " +
                              "(operation_type, records_processed, duplicates_found, duplicates_removed, session_tag) " +
                              "VALUES (?, ?, ?, ?, ?)";
                
                try (PreparedStatement logStmt = getConnection().prepareStatement(logSql)) {
                    logStmt.setString(1, "PROXY_HISTORY_MULTIPASS_IMPORT");
                    logStmt.setInt(2, seenContentHashes.size());
                    logStmt.setInt(3, seenContentHashes.size() - totalImported);
                    logStmt.setInt(4, 0); // We skip duplicates, don't remove them
                    logStmt.setString(5, sessionTag + "_imported_multipass");
                    logStmt.executeUpdate();
                }
            } catch (SQLException e) {
                logger.debug("Failed to log import operation", e);
            }
            
            return totalImported;
            
        } catch (Exception e) {
            logger.error("❌ Failed to import existing proxy history", e);
            return 0;
        }
    }
    
    /**
     * Gets orphaned requests (requests without responses) for debugging.
     * 
     * @param limit Maximum number of orphaned requests to return
     * @return List of orphaned request records
     */
    public List<Map<String, Object>> getOrphanedRequests(int limit) {
        if (shutdown.get() || connection == null) {
            return new ArrayList<>();
        }
        
        List<Map<String, Object>> orphanedRequests = new ArrayList<>();
        
        String sql = "SELECT id, timestamp, method, url, host, session_tag " +
                    "FROM proxy_traffic " +
                    "WHERE status_code IS NULL " +
                    "ORDER BY timestamp DESC " +
                    "LIMIT ?";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setInt(1, limit);
            
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> record = new HashMap<>();
                    record.put("id", rs.getLong("id"));
                    record.put("timestamp", rs.getTimestamp("timestamp"));
                    record.put("method", rs.getString("method"));
                    record.put("url", rs.getString("url"));
                    record.put("host", rs.getString("host"));
                    record.put("session_tag", rs.getString("session_tag"));
                    orphanedRequests.add(record);
                }
            }
            
        } catch (SQLException e) {
            logger.error("Failed to get orphaned requests", e);
        }
        
        return orphanedRequests;
    }
    
    /**
     * Cache for scope checking results to avoid repeated API calls.
     * Key: URL, Value: {inScope: boolean, lastChecked: timestamp}
     */
    public void cacheScopeResult(String url, boolean inScope) {
        String sql = "INSERT OR REPLACE INTO scope_cache (url, in_scope, last_checked) VALUES (?, ?, ?)";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, url);
            stmt.setBoolean(2, inScope);
            stmt.setTimestamp(3, Timestamp.valueOf(LocalDateTime.now()));
            stmt.executeUpdate();
            
            logger.debug("Cached scope result for {}: {}", url, inScope);
            
        } catch (SQLException e) {
            logger.error("Failed to cache scope result", e);
        }
    }
    
    /**
     * Gets cached scope result if available and not stale (within 5 minutes).
     * 
     * @param url The URL to check
     * @return Map with "inScope" boolean and "cached" boolean, or null if not cached/stale
     */
    public Map<String, Object> getCachedScopeResult(String url) {
        String sql = "SELECT in_scope, last_checked FROM scope_cache WHERE url = ? AND last_checked > ?";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, url);
            // Cache valid for 5 minutes
            stmt.setTimestamp(2, Timestamp.valueOf(LocalDateTime.now().minusMinutes(5)));
            
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    Map<String, Object> result = new HashMap<>();
                    result.put("inScope", rs.getBoolean("in_scope"));
                    result.put("cached", true);
                    result.put("lastChecked", rs.getTimestamp("last_checked"));
                    return result;
                }
            }
            
        } catch (SQLException e) {
            logger.error("Failed to get cached scope result", e);
        }
        
        return null;
    }
    
    /**
     * Bulk scope checking optimized for database queries.
     * Returns URLs with their scope status from cache or fresh API calls.
     */
    public Map<String, Boolean> bulkScopeCheck(List<String> urls, burp.api.montoya.MontoyaApi api) {
        Map<String, Boolean> results = new HashMap<>();
        List<String> uncachedUrls = new ArrayList<>();
        
        // First, check cache for all URLs
        for (String url : urls) {
            Map<String, Object> cached = getCachedScopeResult(url);
            if (cached != null) {
                results.put(url, (Boolean) cached.get("inScope"));
            } else {
                uncachedUrls.add(url);
            }
        }
        
        // Check uncached URLs via API and cache results
        for (String url : uncachedUrls) {
            try {
                boolean inScope = api.scope().isInScope(url);
                results.put(url, inScope);
                cacheScopeResult(url, inScope);
            } catch (Exception e) {
                logger.warn("Failed to check scope for URL {}: {}", url, e.getMessage());
                results.put(url, false); // Default to false on error
            }
        }
        
        logger.debug("Bulk scope check: {} cached, {} API calls", results.size() - uncachedUrls.size(), uncachedUrls.size());
        return results;
    }
    
    /**
     * Generate a query plan analysis for performance optimization
     */
    public Map<String, Object> analyzeQueryPerformance(String query, Map<String, Object> params) {
        if (shutdown.get() || connection == null) {
            return new HashMap<>();
        }
        
        Map<String, Object> analysis = new HashMap<>();
        
        try {
            // Get EXPLAIN QUERY PLAN
            String explainQuery = "EXPLAIN QUERY PLAN " + query;
            
            try (PreparedStatement stmt = getConnection().prepareStatement(explainQuery)) {
                // Set parameters if provided
                if (params != null) {
                    int paramIndex = 1;
                    for (Object param : params.values()) {
                        stmt.setObject(paramIndex++, param);
                    }
                }
                
                List<Map<String, Object>> queryPlan = new ArrayList<>();
                try (ResultSet rs = stmt.executeQuery()) {
                    while (rs.next()) {
                        Map<String, Object> planStep = new HashMap<>();
                        planStep.put("selectid", rs.getInt("selectid"));
                        planStep.put("order", rs.getInt("order"));
                        planStep.put("from", rs.getInt("from"));
                        planStep.put("detail", rs.getString("detail"));
                        queryPlan.add(planStep);
                    }
                }
                
                analysis.put("query_plan", queryPlan);
                
                // Analyze for potential performance issues
                List<String> recommendations = new ArrayList<>();
                for (Map<String, Object> step : queryPlan) {
                    String detail = (String) step.get("detail");
                    if (detail.contains("SCAN TABLE")) {
                        recommendations.add("Consider adding an index to avoid table scan: " + detail);
                    }
                    if (detail.contains("TEMP B-TREE")) {
                        recommendations.add("Query requires temporary sorting, consider index optimization: " + detail);
                    }
                    if (detail.contains("USING INDEX")) {
                        recommendations.add("Using index efficiently: " + detail);
                    }
                }
                
                analysis.put("recommendations", recommendations);
                analysis.put("timestamp", System.currentTimeMillis());
                
            }
            
        } catch (SQLException e) {
            logger.error("Failed to analyze query performance", e);
            analysis.put("error", e.getMessage());
        }
        
        return analysis;
    }
    
    /**
     * Get comprehensive database performance metrics
     */
    public Map<String, Object> getDatabasePerformanceMetrics() {
        if (shutdown.get() || connection == null) {
            return new HashMap<>();
        }
        
        Map<String, Object> metrics = new HashMap<>();
        
        try (Statement stmt = getConnection().createStatement()) {
            // Basic database info
            Map<String, Object> dbInfo = new HashMap<>();
            
            try (ResultSet rs = stmt.executeQuery("PRAGMA database_list")) {
                while (rs.next()) {
                    dbInfo.put("name", rs.getString("name"));
                    dbInfo.put("file", rs.getString("file"));
                }
            }
            
            // Page and cache statistics
            Map<String, Object> cacheStats = new HashMap<>();
            cacheStats.put("page_count", getPragmaValue(stmt, "PRAGMA page_count"));
            cacheStats.put("freelist_count", getPragmaValue(stmt, "PRAGMA freelist_count"));
            cacheStats.put("cache_size", getPragmaValue(stmt, "PRAGMA cache_size"));
            cacheStats.put("cache_spill", getPragmaValue(stmt, "PRAGMA cache_spill"));
            
            // Index usage
            Map<String, Object> indexStats = new HashMap<>();
            try (ResultSet rs = stmt.executeQuery("SELECT name, sql FROM sqlite_master WHERE type='index' AND sql IS NOT NULL")) {
                List<Map<String, Object>> indexes = new ArrayList<>();
                while (rs.next()) {
                    Map<String, Object> index = new HashMap<>();
                    index.put("name", rs.getString("name"));
                    index.put("sql", rs.getString("sql"));
                    indexes.add(index);
                }
                indexStats.put("indexes", indexes);
                indexStats.put("count", indexes.size());
            }
            
            // Table statistics
            Map<String, Object> tableStats = new HashMap<>();
            String[] tables = {"traffic_meta", "traffic_requests", "traffic_responses", "proxy_traffic"};
            for (String table : tables) {
                try (ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM " + table)) {
                    if (rs.next()) {
                        tableStats.put(table + "_count", rs.getInt(1));
                    }
                } catch (SQLException e) {
                    tableStats.put(table + "_count", "N/A");
                }
            }
            
            metrics.put("database_info", dbInfo);
            metrics.put("cache_statistics", cacheStats);
            metrics.put("index_statistics", indexStats);
            metrics.put("table_statistics", tableStats);
            metrics.put("schema_version", schemaManager.getSchemaVersion(connection));
            metrics.put("normalized_schema_available", schemaManager.isNormalizedSchemaAvailable(connection));
            metrics.put("fts5_available", schemaManager.isFTS5SearchAvailable(connection));
            metrics.put("collected_at", System.currentTimeMillis());
            
        } catch (SQLException e) {
            logger.error("Failed to collect database performance metrics", e);
            metrics.put("error", e.getMessage());
        }
        
        return metrics;
    }
    
    private String getPragmaValue(Statement stmt, String pragma) {
        try (ResultSet rs = stmt.executeQuery(pragma)) {
            if (rs.next()) {
                return rs.getString(1);
            }
        } catch (SQLException e) {
            logger.debug("Failed to get pragma value for: {}", pragma);
        }
        return "unknown";
    }
    
    //=================================================================================
    // PHASE 10: Enhanced Metadata and Tagging Methods
    //=================================================================================
    
    /**
     * Update tags for a specific traffic record.
     * 
     * @param requestId The traffic_meta.id to update
     * @param tags Comma-separated tags or JSON array
     * @return true if update was successful
     */
    public boolean updateTrafficTags(long requestId, String tags) {
        String sql = "UPDATE traffic_meta SET tags = ? WHERE id = ?";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, tags);
            stmt.setLong(2, requestId);
            
            int rowsUpdated = stmt.executeUpdate();
            if (rowsUpdated > 0) {
                logger.debug("Updated tags for request ID {}: {}", requestId, tags);
                return true;
            } else {
                logger.warn("No record found for request ID: {}", requestId);
                return false;
            }
        } catch (SQLException e) {
            logger.error("Failed to update tags for request ID {}: {}", requestId, e.getMessage());
            return false;
        }
    }
    
    /**
     * Update comment for a specific traffic record.
     * 
     * @param requestId The traffic_meta.id to update
     * @param comment Analyst comment/note
     * @return true if update was successful
     */
    public boolean trafficRecordExists(long requestId) {
        String sql = "SELECT 1 FROM traffic_meta WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setLong(1, requestId);
            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            logger.error("Error checking if traffic record exists: {}", e.getMessage());
            return false;
        }
    }
    
    public boolean updateTrafficComment(long requestId, String comment) {
        String sql = "UPDATE traffic_meta SET comment = ? WHERE id = ?";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, comment);
            stmt.setLong(2, requestId);
            
            int rowsUpdated = stmt.executeUpdate();
            if (rowsUpdated > 0) {
                logger.debug("Updated comment for request ID {}: {}", requestId, comment);
                return true;
            } else {
                logger.warn("No record found for request ID: {}", requestId);
                return false;
            }
        } catch (SQLException e) {
            logger.error("Failed to update comment for request ID {}: {}", requestId, e.getMessage());
            return false;
        }
    }
    
    /**
     * Set replay lineage for a traffic record.
     * 
     * @param replayedRequestId The ID of the replayed request
     * @param originalRequestId The ID of the original request it was replayed from
     * @return true if update was successful
     */
    public boolean setReplayLineage(long replayedRequestId, long originalRequestId) {
        String sql = "UPDATE traffic_meta SET replayed_from = ? WHERE id = ?";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setLong(1, originalRequestId);
            stmt.setLong(2, replayedRequestId);
            
            int rowsUpdated = stmt.executeUpdate();
            if (rowsUpdated > 0) {
                logger.debug("Set replay lineage: {} replayed from {}", replayedRequestId, originalRequestId);
                return true;
            } else {
                logger.warn("No record found for replayed request ID: {}", replayedRequestId);
                return false;
            }
        } catch (SQLException e) {
            logger.error("Failed to set replay lineage for request ID {}: {}", replayedRequestId, e.getMessage());
            return false;
        }
    }
    
    /**
     * Get all traffic records that were replayed from a specific original request.
     * 
     * @param originalRequestId The original request ID
     * @return List of replayed traffic records
     */
    public List<Map<String, Object>> getReplayedFrom(long originalRequestId) {
        String sql = "SELECT tm.*, tr.headers as request_headers, tr.body as request_body, " +
                    "tres.status_code, tres.headers as response_headers, tres.body as response_body " +
                    "FROM traffic_meta tm " +
                    "LEFT JOIN traffic_requests tr ON tm.id = tr.traffic_meta_id " +
                    "LEFT JOIN traffic_responses tres ON tm.id = tres.traffic_meta_id " +
                    "WHERE tm.replayed_from = ? " +
                    "ORDER BY tm.timestamp DESC";
        
        List<Map<String, Object>> results = new ArrayList<>();
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setLong(1, originalRequestId);
            
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> record = new HashMap<>();
                    record.put("id", rs.getLong("id"));
                    record.put("timestamp", rs.getTimestamp("timestamp"));
                    record.put("method", rs.getString("method"));
                    record.put("url", rs.getString("url"));
                    record.put("host", rs.getString("host"));
                    record.put("session_tag", rs.getString("session_tag"));
                    record.put("tool_source", rs.getString("tool_source"));
                    record.put("tags", rs.getString("tags"));
                    record.put("comment", rs.getString("comment"));
                    record.put("replayed_from", rs.getLong("replayed_from"));
                    record.put("request_headers", rs.getString("request_headers"));
                    record.put("request_body", rs.getString("request_body"));
                    record.put("status_code", rs.getObject("status_code"));
                    record.put("response_headers", rs.getString("response_headers"));
                    record.put("response_body", rs.getString("response_body"));
                    results.add(record);
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to get replayed requests for original ID {}: {}", originalRequestId, e.getMessage());
        }
        
        return results;
    }
    
    /**
     * Search request bodies using FTS5 if available.
     * 
     * @param searchQuery The search query
     * @param limit Maximum results to return
     * @param offset Results to skip for pagination
     * @return List of matching traffic records
     */
    public List<Map<String, Object>> searchRequestBodies(String searchQuery, int limit, int offset) {
        // Check if request FTS is available
        try {
            if (!schemaManager.isRequestFTS5SearchAvailable(connection)) {
                logger.warn("Request FTS5 not available, falling back to LIKE search");
                return searchRequestBodiesLike(searchQuery, limit, offset);
            }
        } catch (SQLException e) {
            logger.warn("Error checking request FTS5 availability, falling back to LIKE search: {}", e.getMessage());
            return searchRequestBodiesLike(searchQuery, limit, offset);
        }
        
        String sql = "SELECT tm.*, tr.headers as request_headers, tr.body as request_body, " +
                    "tres.status_code, tres.headers as response_headers, tres.body as response_body " +
                    "FROM request_index ri " +
                    "JOIN traffic_meta tm ON ri.traffic_meta_id = tm.id " +
                    "LEFT JOIN traffic_requests tr ON tm.id = tr.traffic_meta_id " +
                    "LEFT JOIN traffic_responses tres ON tm.id = tres.traffic_meta_id " +
                    "WHERE request_index MATCH ? " +
                    "ORDER BY tm.timestamp DESC " +
                    "LIMIT ? OFFSET ?";
        
        List<Map<String, Object>> results = new ArrayList<>();
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, searchQuery);
            stmt.setInt(2, limit);
            stmt.setInt(3, offset);
            
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> record = new HashMap<>();
                    record.put("id", rs.getLong("id"));
                    record.put("timestamp", rs.getTimestamp("timestamp"));
                    record.put("method", rs.getString("method"));
                    record.put("url", rs.getString("url"));
                    record.put("host", rs.getString("host"));
                    record.put("session_tag", rs.getString("session_tag"));
                    record.put("tool_source", rs.getString("tool_source"));
                    record.put("tags", rs.getString("tags"));
                    record.put("comment", rs.getString("comment"));
                    record.put("replayed_from", rs.getLong("replayed_from"));
                    record.put("request_headers", rs.getString("request_headers"));
                    record.put("request_body", rs.getString("request_body"));
                    record.put("status_code", rs.getObject("status_code"));
                    record.put("response_headers", rs.getString("response_headers"));
                    record.put("response_body", rs.getString("response_body"));
                    results.add(record);
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to search request bodies with FTS5: {}", e.getMessage());
            return searchRequestBodiesLike(searchQuery, limit, offset);
        }
        
        return results;
    }
    
    /**
     * Fallback search for request bodies using LIKE.
     */
    private List<Map<String, Object>> searchRequestBodiesLike(String searchQuery, int limit, int offset) {
        String sql = "SELECT tm.*, tr.headers as request_headers, tr.body as request_body, " +
                    "tres.status_code, tres.headers as response_headers, tres.body as response_body " +
                    "FROM traffic_meta tm " +
                    "LEFT JOIN traffic_requests tr ON tm.id = tr.traffic_meta_id " +
                    "LEFT JOIN traffic_responses tres ON tm.id = tres.traffic_meta_id " +
                    "WHERE tr.body LIKE ? " +
                    "ORDER BY tm.timestamp DESC " +
                    "LIMIT ? OFFSET ?";
        
        List<Map<String, Object>> results = new ArrayList<>();
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, "%" + searchQuery + "%");
            stmt.setInt(2, limit);
            stmt.setInt(3, offset);
            
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> record = new HashMap<>();
                    record.put("id", rs.getLong("id"));
                    record.put("timestamp", rs.getTimestamp("timestamp"));
                    record.put("method", rs.getString("method"));
                    record.put("url", rs.getString("url"));
                    record.put("host", rs.getString("host"));
                    record.put("session_tag", rs.getString("session_tag"));
                    record.put("tool_source", rs.getString("tool_source"));
                    record.put("tags", rs.getString("tags"));
                    record.put("comment", rs.getString("comment"));
                    record.put("replayed_from", rs.getLong("replayed_from"));
                    record.put("request_headers", rs.getString("request_headers"));
                    record.put("request_body", rs.getString("request_body"));
                    record.put("status_code", rs.getObject("status_code"));
                    record.put("response_headers", rs.getString("response_headers"));
                    record.put("response_body", rs.getString("response_body"));
                    results.add(record);
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to search request bodies with LIKE: {}", e.getMessage());
        }
        
        return results;
    }
    
    /**
     * Save a query preset for later reuse.
     * 
     * @param name Unique name for the query
     * @param description Optional description
     * @param queryParamsJson JSON string containing query parameters
     * @param sessionTag Session tag for organization
     * @return The ID of the saved query, or -1 if failed
     */
    public long saveQuery(String name, String description, String queryParamsJson, String sessionTag) {
        logger.info("Attempting to save query: name='{}', description='{}', sessionTag='{}'", name, description, sessionTag);
        
        // Add timestamp to make name unique for test queries
        if (name.startsWith("test_")) {
            name = name + "_" + System.currentTimeMillis() + "_" + (int)(Math.random() * 10000);
        }
        
        // Check schema availability like listSavedQueries does
        try {
            boolean available = schemaManager.isSavedQueriesAvailable(connection);
            logger.info("Schema check result: saved_queries available = {}", available);
            if (!available) {
                logger.error("Saved queries feature not available - but table exists!");
                // Continue anyway since we know table exists
            }
        } catch (SQLException e) {
            logger.error("Schema availability check failed: {}", e.getMessage(), e);
            // Continue anyway
        }
        
        String sql = "INSERT INTO saved_queries (name, description, query_params, session_tag) VALUES (?, ?, ?, ?)";
        
        logger.info("About to execute SQL: {} with name='{}', description='{}', queryParamsJson='{}', sessionTag='{}'", 
                   sql, name, description, queryParamsJson, sessionTag);
        
        // Use explicit connection with autocommit
        try {
            connection.setAutoCommit(true);
            
            // First insert the record
            try (PreparedStatement stmt = connection.prepareStatement(sql)) {
                stmt.setString(1, name);
                stmt.setString(2, description);
                stmt.setString(3, queryParamsJson);
                stmt.setString(4, sessionTag);
                
                logger.info("Executing prepared statement...");
                
                int rowsInserted = stmt.executeUpdate();
                logger.info("Rows inserted: {}", rowsInserted);
                
                if (rowsInserted > 0) {
                    // Get the last inserted row ID using SQLite specific function
                    try (PreparedStatement idStmt = connection.prepareStatement("SELECT last_insert_rowid()")) {
                        try (ResultSet rs = idStmt.executeQuery()) {
                            if (rs.next()) {
                                long queryId = rs.getLong(1);
                                logger.info("Saved query '{}' with ID: {}", name, queryId);
                                return queryId;
                            }
                        }
                    }
                } else {
                    logger.warn("No rows inserted for query '{}'", name);
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to save query '{}': {} (SQL State: {}, Error Code: {})", 
                        name, e.getMessage(), e.getSQLState(), e.getErrorCode());
            logger.error("Full SQL Exception:", e);
            // Check if it's a unique constraint violation
            if (e.getMessage().contains("UNIQUE constraint failed")) {
                logger.info("Query name '{}' already exists, trying with new timestamp", name);
                // Try again with a more unique name
                String newName = name + "_retry_" + System.currentTimeMillis();
                return saveQuery(newName, description, queryParamsJson, sessionTag);
            }
        } catch (Exception e) {
            logger.error("Unexpected error saving query '{}': {}", name, e.getMessage(), e);
        }
        
        return -1;
    }
    
    /**
     * Load a saved query by name.
     * 
     * @param name The name of the saved query
     * @return Map containing query details, or null if not found
     */
    public Map<String, Object> loadQuery(String name) {
        try {
            if (!schemaManager.isSavedQueriesAvailable(connection)) {
                logger.warn("Saved queries feature not available in current schema version");
                return null;
            }
        } catch (SQLException e) {
            logger.warn("Error checking saved queries availability: {}", e.getMessage());
            return null;
        }
        
        String sql = "SELECT * FROM saved_queries WHERE name = ?";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, name);
            
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    Map<String, Object> query = new HashMap<>();
                    query.put("id", rs.getLong("id"));
                    query.put("name", rs.getString("name"));
                    query.put("description", rs.getString("description"));
                    query.put("query_params", rs.getString("query_params"));
                    query.put("created_at", rs.getTimestamp("created_at"));
                    query.put("updated_at", rs.getTimestamp("updated_at"));
                    query.put("session_tag", rs.getString("session_tag"));
                    return query;
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to load query '{}': {}", name, e.getMessage());
        }
        
        return null;
    }
    
    /**
     * List all saved queries, optionally filtered by session tag.
     * 
     * @param sessionTag Optional session tag filter (null for all)
     * @return List of saved queries
     */
    public List<Map<String, Object>> listSavedQueries(String sessionTag) {
        try {
            if (!schemaManager.isSavedQueriesAvailable(connection)) {
                logger.warn("Saved queries feature not available in current schema version");
                return new ArrayList<>();
            }
        } catch (SQLException e) {
            logger.warn("Error checking saved queries availability: {}", e.getMessage());
            return new ArrayList<>();
        }
        
        String sql = "SELECT * FROM saved_queries";
        if (sessionTag != null) {
            sql += " WHERE session_tag = ?";
        }
        sql += " ORDER BY updated_at DESC";
        
        List<Map<String, Object>> queries = new ArrayList<>();
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            if (sessionTag != null) {
                stmt.setString(1, sessionTag);
            }
            
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> query = new HashMap<>();
                    query.put("id", rs.getLong("id"));
                    query.put("name", rs.getString("name"));
                    query.put("description", rs.getString("description"));
                    query.put("query_params", rs.getString("query_params"));
                    query.put("created_at", rs.getTimestamp("created_at"));
                    query.put("updated_at", rs.getTimestamp("updated_at"));
                    query.put("session_tag", rs.getString("session_tag"));
                    queries.add(query);
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to list saved queries: {}", e.getMessage());
        }
        
        return queries;
    }
    
    /**
     * Delete a saved query by name.
     * 
     * @param name The name of the query to delete
     * @return true if deletion was successful
     */
    public boolean deleteSavedQuery(String name) {
        try {
            if (!schemaManager.isSavedQueriesAvailable(connection)) {
                logger.warn("Saved queries feature not available in current schema version");
                return false;
            }
        } catch (SQLException e) {
            logger.warn("Error checking saved queries availability: {}", e.getMessage());
            return false;
        }
        
        String sql = "DELETE FROM saved_queries WHERE name = ?";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, name);
            
            int rowsDeleted = stmt.executeUpdate();
            if (rowsDeleted > 0) {
                logger.info("Deleted saved query: {}", name);
                return true;
            } else {
                logger.warn("No saved query found with name: {}", name);
                return false;
            }
        } catch (SQLException e) {
            logger.error("Failed to delete saved query '{}': {}", name, e.getMessage());
            return false;
        }
    }
    
    /**
     * Get traffic records by IDs for replay functionality.
     * 
     * @param requestIds List of traffic_meta IDs to retrieve
     * @return List of traffic records with full request/response data
     */
    public List<Map<String, Object>> getTrafficByIds(List<Long> requestIds) {
        if (requestIds == null || requestIds.isEmpty()) {
            return new ArrayList<>();
        }
        
        // Build IN clause for the query
        StringBuilder placeholders = new StringBuilder();
        for (int i = 0; i < requestIds.size(); i++) {
            if (i > 0) placeholders.append(",");
            placeholders.append("?");
        }
        
        String sql = "SELECT tm.*, tr.headers as request_headers, tr.body as request_body, " +
                    "tres.status_code, tres.headers as response_headers, tres.body as response_body " +
                    "FROM traffic_meta tm " +
                    "LEFT JOIN traffic_requests tr ON tm.id = tr.traffic_meta_id " +
                    "LEFT JOIN traffic_responses tres ON tm.id = tres.traffic_meta_id " +
                    "WHERE tm.id IN (" + placeholders + ") " +
                    "ORDER BY tm.timestamp DESC";
        
        List<Map<String, Object>> results = new ArrayList<>();
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            // Set parameters
            for (int i = 0; i < requestIds.size(); i++) {
                stmt.setLong(i + 1, requestIds.get(i));
            }
            
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> record = new HashMap<>();
                    record.put("id", rs.getLong("id"));
                    record.put("timestamp", rs.getTimestamp("timestamp"));
                    record.put("method", rs.getString("method"));
                    record.put("url", rs.getString("url"));
                    record.put("host", rs.getString("host"));
                    record.put("session_tag", rs.getString("session_tag"));
                    record.put("tool_source", rs.getString("tool_source"));
                    record.put("tags", rs.getString("tags"));
                    record.put("comment", rs.getString("comment"));
                    record.put("replayed_from", rs.getLong("replayed_from"));
                    record.put("request_headers", rs.getString("request_headers"));
                    record.put("request_body", rs.getString("request_body"));
                    record.put("status_code", rs.getObject("status_code"));
                    record.put("response_headers", rs.getString("response_headers"));
                    record.put("response_body", rs.getString("response_body"));
                    results.add(record);
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to get traffic records by IDs: {}", e.getMessage());
        }
        
        return results;
    }
    
    /**
     * Get full request metadata by ID for curl generation.
     * 
     * @param requestId The traffic_meta ID to retrieve
     * @return Map containing full request data, or null if not found
     */
    public Map<String, Object> getFullRequestDataForCurl(long requestId) {
        String sql = "SELECT tm.*, tr.headers as request_headers, tr.body as request_body " +
                    "FROM traffic_meta tm " +
                    "LEFT JOIN traffic_requests tr ON tm.id = tr.traffic_meta_id " +
                    "WHERE tm.id = ?";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setLong(1, requestId);
            
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    Map<String, Object> record = new HashMap<>();
                    record.put("id", rs.getLong("id"));
                    record.put("timestamp", rs.getTimestamp("timestamp"));
                    record.put("method", rs.getString("method"));
                    record.put("url", rs.getString("url"));
                    record.put("host", rs.getString("host"));
                    record.put("session_tag", rs.getString("session_tag"));
                    record.put("tool_source", rs.getString("tool_source"));
                    record.put("tags", rs.getString("tags"));
                    record.put("comment", rs.getString("comment"));
                    record.put("request_headers", rs.getString("request_headers"));
                    record.put("request_body", rs.getString("request_body"));
                    
                    // Extract content type from headers for better curl generation
                    String headers = rs.getString("request_headers");
                    String contentType = extractContentType(headers);
                    record.put("content_type", contentType);
                    
                    return record;
                } else {
                    logger.warn("No request found with ID: {}", requestId);
                    return null;
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to get full request data for ID {}: {}", requestId, e.getMessage());
            return null;
        }
    }
    
    /**
     * Get top hosts or URLs by frequency for Phase 12.
     * 
     * @param limit Number of results to return
     * @param by Either "host" or "url"
     * @param sessionTag Optional session tag filter
     * @param startTime Optional start time filter
     * @param endTime Optional end time filter
     * @return List of top hosts/URLs with counts
     */
    public List<Map<String, Object>> getTopHosts(int limit, String by, String sessionTag, String startTime, String endTime) {
        if (shutdown.get() || connection == null) {
            return new ArrayList<>();
        }
        
        List<Map<String, Object>> results = new ArrayList<>();
        String column = "host".equals(by) ? "host" : "url";
        
        try {
            String sql = "SELECT " + column + " AS value, COUNT(*) AS count FROM proxy_traffic " +
                        "GROUP BY " + column + " ORDER BY count DESC LIMIT " + limit;
            
            try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
                try (ResultSet rs = stmt.executeQuery()) {
                    while (rs.next()) {
                        Map<String, Object> result = new HashMap<>();
                        result.put("value", rs.getString("value"));
                        result.put("count", rs.getLong("count"));
                        results.add(result);
                    }
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to get top hosts: {}", e.getMessage(), e);
        }
        
        return results;
    }
    
    /**
     * Get histogram of request counts over time for Phase 12.
     * 
     * @param interval Time interval: "minute", "hour", or "day"
     * @param sessionTag Optional session tag filter
     * @param method Optional HTTP method filter
     * @param statusCode Optional status code filter
     * @param startTime Optional start time filter
     * @param endTime Optional end time filter
     * @return List of histogram buckets with counts
     */
    public List<Map<String, Object>> getHistogram(String interval, String sessionTag, String method, 
                                                  String statusCode, String startTime, String endTime) {
        if (shutdown.get() || connection == null) {
            return new ArrayList<>();
        }
        
        List<Map<String, Object>> results = new ArrayList<>();
        
        try {
            // Determine SQL date format based on interval
            String dateFormat;
            switch (interval.toLowerCase()) {
                case "minute":
                    dateFormat = "%Y-%m-%dT%H:%M:00Z";
                    break;
                case "hour":
                    dateFormat = "%Y-%m-%dT%H:00:00Z";
                    break;
                case "day":
                    dateFormat = "%Y-%m-%dT00:00:00Z";
                    break;
                default:
                    dateFormat = "%Y-%m-%dT%H:00:00Z"; // Default to hour
                    break;
            }
            
            String sql = "SELECT strftime('" + dateFormat + "', timestamp/1000, 'unixepoch') AS bucket, " +
                        "COUNT(*) AS count FROM proxy_traffic " +
                        "GROUP BY bucket ORDER BY bucket ASC";
            
            try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
                try (ResultSet rs = stmt.executeQuery()) {
                    while (rs.next()) {
                        Map<String, Object> result = new HashMap<>();
                        result.put("bucket", rs.getString("bucket"));
                        result.put("count", rs.getLong("count"));
                        results.add(result);
                    }
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to get histogram: {}", e.getMessage(), e);
        }
        
        return results;
    }
    
    /**
     * Enhanced search with regex support for Phase 3 Task 12.
     * 
     * @param searchParams Search parameters including regex patterns
     * @return List of matching traffic records
     */
    public List<Map<String, Object>> searchTrafficWithRegex(Map<String, String> searchParams) {
        if (shutdown.get() || connection == null) {
            return new ArrayList<>();
        }
        
        // Use enhanced search if regex parameters are present
        boolean useRegex = Boolean.parseBoolean(searchParams.getOrDefault("use_regex", "false"));
        if (!useRegex && !hasRegexParams(searchParams)) {
            // Fallback to standard search
            return searchTraffic(searchParams);
        }
        
        StringBuilder sql = new StringBuilder("SELECT * FROM proxy_traffic WHERE 1=1");
        List<Object> params = new ArrayList<>();
        
        // Determine case sensitivity
        boolean caseInsensitive = Boolean.parseBoolean(searchParams.getOrDefault("case_insensitive", "false"));
        
        // Add regex filters
        if (searchParams.containsKey("url_regex")) {
            sql.append(" AND url REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("url_regex") : searchParams.get("url_regex"));
        }
        
        if (searchParams.containsKey("method_regex")) {
            sql.append(" AND method REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("method_regex") : searchParams.get("method_regex"));
        }
        
        if (searchParams.containsKey("host_regex")) {
            sql.append(" AND host REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("host_regex") : searchParams.get("host_regex"));
        }
        
        if (searchParams.containsKey("headers_regex")) {
            sql.append(" AND headers REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("headers_regex") : searchParams.get("headers_regex"));
        }
        
        if (searchParams.containsKey("body_regex")) {
            sql.append(" AND body REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("body_regex") : searchParams.get("body_regex"));
        }
        
        if (searchParams.containsKey("response_headers_regex")) {
            sql.append(" AND response_headers REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("response_headers_regex") : searchParams.get("response_headers_regex"));
        }
        
        if (searchParams.containsKey("response_body_regex")) {
            sql.append(" AND response_body REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("response_body_regex") : searchParams.get("response_body_regex"));
        }
        
        if (searchParams.containsKey("session_tag_regex")) {
            sql.append(" AND session_tag REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("session_tag_regex") : searchParams.get("session_tag_regex"));
        }
        
        // Add standard filters (still supported alongside regex)
        if (searchParams.containsKey("status_code")) {
            sql.append(" AND status_code = ?");
            params.add(Integer.parseInt(searchParams.get("status_code")));
        }
        
        // Add time-range filters
        if (searchParams.containsKey("start_time")) {
            sql.append(" AND timestamp >= ?");
            params.add(parseTimestamp(searchParams.get("start_time")));
        }
        
        if (searchParams.containsKey("end_time")) {
            sql.append(" AND timestamp <= ?");
            params.add(parseTimestamp(searchParams.get("end_time")));
        }
        
        // Add ordering and limits
        sql.append(" ORDER BY timestamp DESC");
        
        if (searchParams.containsKey("limit")) {
            sql.append(" LIMIT ?");
            params.add(Integer.parseInt(searchParams.get("limit")));
        }
        
        if (searchParams.containsKey("offset")) {
            sql.append(" OFFSET ?");
            params.add(Integer.parseInt(searchParams.get("offset")));
        }
        
        List<Map<String, Object>> results = new ArrayList<>();
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql.toString())) {
            for (int i = 0; i < params.size(); i++) {
                stmt.setObject(i + 1, params.get(i));
            }
            
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> record = new HashMap<>();
                    record.put("id", rs.getLong("id"));
                    record.put("timestamp", rs.getTimestamp("timestamp"));
                    record.put("method", rs.getString("method"));
                    record.put("url", rs.getString("url"));
                    record.put("host", rs.getString("host"));
                    record.put("headers", rs.getString("headers"));
                    record.put("body", rs.getString("body"));
                    record.put("status_code", rs.getObject("status_code"));
                    record.put("response_headers", rs.getString("response_headers"));
                    record.put("response_body", rs.getString("response_body"));
                    record.put("session_tag", rs.getString("session_tag"));
                    results.add(record);
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to search traffic with regex: {}", e.getMessage(), e);
            // Fallback to standard search on regex error
            logger.info("Falling back to standard search due to regex error");
            return searchTraffic(searchParams);
        }
        
        return results;
    }
    
    /**
     * Check if search parameters contain regex patterns.
     */
    private boolean hasRegexParams(Map<String, String> searchParams) {
        return searchParams.containsKey("url_regex") || 
               searchParams.containsKey("method_regex") ||
               searchParams.containsKey("host_regex") ||
               searchParams.containsKey("headers_regex") ||
               searchParams.containsKey("body_regex") ||
               searchParams.containsKey("response_headers_regex") ||
               searchParams.containsKey("response_body_regex") ||
               searchParams.containsKey("session_tag_regex");
    }
    
    /**
     * Get count for regex search queries.
     */
    public long getRegexSearchCount(Map<String, String> searchParams) {
        if (shutdown.get() || connection == null) {
            return 0;
        }
        
        // Use standard count if no regex
        boolean useRegex = Boolean.parseBoolean(searchParams.getOrDefault("use_regex", "false"));
        if (!useRegex && !hasRegexParams(searchParams)) {
            return getSearchCount(searchParams);
        }
        
        StringBuilder sql = new StringBuilder("SELECT COUNT(*) FROM proxy_traffic WHERE 1=1");
        List<Object> params = new ArrayList<>();
        
        boolean caseInsensitive = Boolean.parseBoolean(searchParams.getOrDefault("case_insensitive", "false"));
        
        // Add same regex filters as main search
        if (searchParams.containsKey("url_regex")) {
            sql.append(" AND url REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("url_regex") : searchParams.get("url_regex"));
        }
        
        if (searchParams.containsKey("method_regex")) {
            sql.append(" AND method REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("method_regex") : searchParams.get("method_regex"));
        }
        
        if (searchParams.containsKey("host_regex")) {
            sql.append(" AND host REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("host_regex") : searchParams.get("host_regex"));
        }
        
        if (searchParams.containsKey("headers_regex")) {
            sql.append(" AND headers REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("headers_regex") : searchParams.get("headers_regex"));
        }
        
        if (searchParams.containsKey("body_regex")) {
            sql.append(" AND body REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("body_regex") : searchParams.get("body_regex"));
        }
        
        if (searchParams.containsKey("response_headers_regex")) {
            sql.append(" AND response_headers REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("response_headers_regex") : searchParams.get("response_headers_regex"));
        }
        
        if (searchParams.containsKey("response_body_regex")) {
            sql.append(" AND response_body REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("response_body_regex") : searchParams.get("response_body_regex"));
        }
        
        if (searchParams.containsKey("session_tag_regex")) {
            sql.append(" AND session_tag REGEXP ?");
            params.add(caseInsensitive ? "(?i)" + searchParams.get("session_tag_regex") : searchParams.get("session_tag_regex"));
        }
        
        // Add standard filters
        if (searchParams.containsKey("status_code")) {
            sql.append(" AND status_code = ?");
            params.add(Integer.parseInt(searchParams.get("status_code")));
        }
        
        if (searchParams.containsKey("start_time")) {
            sql.append(" AND timestamp >= ?");
            params.add(parseTimestamp(searchParams.get("start_time")));
        }
        
        if (searchParams.containsKey("end_time")) {
            sql.append(" AND timestamp <= ?");
            params.add(parseTimestamp(searchParams.get("end_time")));
        }
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql.toString())) {
            for (int i = 0; i < params.size(); i++) {
                stmt.setObject(i + 1, params.get(i));
            }
            
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getLong(1);
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to get regex search count: {}", e.getMessage(), e);
            return getSearchCount(searchParams);
        }
        
        return 0;
    }
    
    /**
     * Bulk tagging operation for Phase 3 Task 12.
     * 
     * @param requestIds List of request IDs to tag
     * @param tags Comma-separated tags to add
     * @return Number of records updated
     */
    public int bulkAddTags(List<Long> requestIds, String tags) {
        if (shutdown.get() || connection == null || requestIds.isEmpty()) {
            return 0;
        }
        
        String placeholders = String.join(",", Collections.nCopies(requestIds.size(), "?"));
        String sql = "UPDATE proxy_traffic SET tags = CASE " +
                    "WHEN tags IS NULL OR tags = '' THEN ? " +
                    "ELSE tags || ',' || ? " +
                    "END WHERE id IN (" + placeholders + ")";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, tags);
            stmt.setString(2, tags);
            
            for (int i = 0; i < requestIds.size(); i++) {
                stmt.setLong(i + 3, requestIds.get(i));
            }
            
            int updated = stmt.executeUpdate();
            logger.info("Bulk tagged {} records with tags: {}", updated, tags);
            return updated;
            
        } catch (SQLException e) {
            logger.error("Failed to bulk add tags: {}", e.getMessage(), e);
            return 0;
        }
    }
    
    /**
     * Bulk commenting operation for Phase 3 Task 12.
     * 
     * @param requestIds List of request IDs to comment
     * @param comment Comment to add
     * @return Number of records updated
     */
    public int bulkAddComments(List<Long> requestIds, String comment) {
        if (shutdown.get() || connection == null || requestIds.isEmpty()) {
            return 0;
        }
        
        String placeholders = String.join(",", Collections.nCopies(requestIds.size(), "?"));
        String sql = "UPDATE proxy_traffic SET comment = CASE " +
                    "WHEN comment IS NULL OR comment = '' THEN ? " +
                    "ELSE comment || '\\n---\\n' || ? " +
                    "END WHERE id IN (" + placeholders + ")";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, comment);
            stmt.setString(2, comment);
            
            for (int i = 0; i < requestIds.size(); i++) {
                stmt.setLong(i + 3, requestIds.get(i));
            }
            
            int updated = stmt.executeUpdate();
            logger.info("Bulk commented {} records with comment: {}", updated, comment);
            return updated;
            
        } catch (SQLException e) {
            logger.error("Failed to bulk add comments: {}", e.getMessage(), e);
            return 0;
        }
    }
    
    /**
     * Remove tags from multiple records for Phase 3 Task 12.
     * 
     * @param requestIds List of request IDs to update
     * @param tagsToRemove Comma-separated tags to remove
     * @return Number of records updated
     */
    public int bulkRemoveTags(List<Long> requestIds, String tagsToRemove) {
        if (shutdown.get() || connection == null || requestIds.isEmpty()) {
            return 0;
        }
        
        String[] tagsArray = tagsToRemove.split(",");
        String placeholders = String.join(",", Collections.nCopies(requestIds.size(), "?"));
        
        StringBuilder sql = new StringBuilder("UPDATE proxy_traffic SET tags = ");
        
        // Build REPLACE chain for each tag to remove
        sql.append("REPLACE(");
        for (int i = 0; i < tagsArray.length; i++) {
            if (i > 0) {
                sql.append("REPLACE(");
            }
            sql.append("COALESCE(tags, '')");
        }
        
        // Add the REPLACE operations
        for (int i = 0; i < tagsArray.length; i++) {
            sql.append(", ?, '')");
            if (i < tagsArray.length - 1) {
                sql.append(")");
            }
        }
        
        sql.append(" WHERE id IN (").append(placeholders).append(")");
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql.toString())) {
            int paramIndex = 1;
            
            // Set tag parameters
            for (String tag : tagsArray) {
                stmt.setString(paramIndex++, tag.trim());
            }
            
            // Set ID parameters
            for (Long requestId : requestIds) {
                stmt.setLong(paramIndex++, requestId);
            }
            
            int updated = stmt.executeUpdate();
            logger.info("Bulk removed tags '{}' from {} records", tagsToRemove, updated);
            return updated;
            
        } catch (SQLException e) {
            logger.error("Failed to bulk remove tags: {}", e.getMessage(), e);
            return 0;
        }
    }
    
    /**
     * Clear comments from multiple records for Phase 3 Task 12.
     * 
     * @param requestIds List of request IDs to update
     * @return Number of records updated
     */
    public int bulkClearComments(List<Long> requestIds) {
        if (shutdown.get() || connection == null || requestIds.isEmpty()) {
            return 0;
        }
        
        String placeholders = String.join(",", Collections.nCopies(requestIds.size(), "?"));
        String sql = "UPDATE proxy_traffic SET comment = NULL WHERE id IN (" + placeholders + ")";
        
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            for (int i = 0; i < requestIds.size(); i++) {
                stmt.setLong(i + 1, requestIds.get(i));
            }
            
            int updated = stmt.executeUpdate();
            logger.info("Bulk cleared comments from {} records", updated);
            return updated;
            
        } catch (SQLException e) {
            logger.error("Failed to bulk clear comments: {}", e.getMessage(), e);
            return 0;
        }
    }
} 