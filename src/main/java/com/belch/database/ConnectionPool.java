package com.belch.database;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Simple connection pool implementation for SQLite database connections.
 * Provides connection reuse and management for improved performance.
 */
public class ConnectionPool {
    
    private static final Logger logger = LoggerFactory.getLogger(ConnectionPool.class);
    
    private final String jdbcUrl;
    private final int maxPoolSize;
    private final int minPoolSize;
    private final long connectionTimeoutMs;
    
    private final BlockingQueue<Connection> availableConnections;
    private final AtomicInteger currentPoolSize = new AtomicInteger(0);
    private final AtomicInteger activeConnections = new AtomicInteger(0);
    private final AtomicBoolean isShutdown = new AtomicBoolean(false);
    
    // Connection pool statistics
    private final AtomicInteger totalConnectionsCreated = new AtomicInteger(0);
    private final AtomicInteger totalConnectionsReused = new AtomicInteger(0);
    private final AtomicInteger connectionTimeouts = new AtomicInteger(0);
    
    // Default configuration
    private static final int DEFAULT_MAX_POOL_SIZE = 10;
    private static final int DEFAULT_MIN_POOL_SIZE = 2;
    private static final long DEFAULT_CONNECTION_TIMEOUT_MS = 5000; // 5 seconds
    
    /**
     * Create a connection pool with default settings
     */
    public ConnectionPool(String jdbcUrl) {
        this(jdbcUrl, DEFAULT_MAX_POOL_SIZE, DEFAULT_MIN_POOL_SIZE, DEFAULT_CONNECTION_TIMEOUT_MS);
    }
    
    /**
     * Create a connection pool with custom settings
     */
    public ConnectionPool(String jdbcUrl, int maxPoolSize, int minPoolSize, long connectionTimeoutMs) {
        this.jdbcUrl = jdbcUrl;
        this.maxPoolSize = maxPoolSize;
        this.minPoolSize = minPoolSize;
        this.connectionTimeoutMs = connectionTimeoutMs;
        this.availableConnections = new LinkedBlockingQueue<>(maxPoolSize);
        
        initializePool();
    }
    
    /**
     * Initialize the connection pool with minimum connections
     */
    private void initializePool() {
        logger.info("Initializing connection pool (min: {}, max: {}) for: {}", 
            minPoolSize, maxPoolSize, jdbcUrl);
        
        try {
            // Create minimum number of connections
            for (int i = 0; i < minPoolSize; i++) {
                Connection conn = createNewConnection();
                if (conn != null) {
                    availableConnections.offer(conn);
                    currentPoolSize.incrementAndGet();
                }
            }
            
            logger.info("Connection pool initialized with {} connections", currentPoolSize.get());
            
        } catch (Exception e) {
            logger.error("Failed to initialize connection pool", e);
        }
    }
    
    /**
     * Get a connection from the pool
     */
    public Connection getConnection() throws SQLException {
        if (isShutdown.get()) {
            throw new SQLException("Connection pool is shutdown");
        }
        
        try {
            // Try to get an available connection
            Connection conn = availableConnections.poll(connectionTimeoutMs, TimeUnit.MILLISECONDS);
            
            if (conn != null) {
                // Check if connection is still valid
                if (isConnectionValid(conn)) {
                    activeConnections.incrementAndGet();
                    totalConnectionsReused.incrementAndGet();
                    logger.debug("Reused connection from pool");
                    return new PooledConnection(conn, this);
                } else {
                    // Connection is invalid, close it and create a new one
                    closeConnectionSilently(conn);
                    currentPoolSize.decrementAndGet();
                }
            }
            
            // No available connection or invalid connection, create new one if pool not full
            if (currentPoolSize.get() < maxPoolSize) {
                Connection newConn = createNewConnection();
                if (newConn != null) {
                    currentPoolSize.incrementAndGet();
                    activeConnections.incrementAndGet();
                    totalConnectionsCreated.incrementAndGet();
                    logger.debug("Created new connection for pool");
                    return new PooledConnection(newConn, this);
                }
            }
            
            // Pool is full and no connections available
            connectionTimeouts.incrementAndGet();
            throw new SQLException("Connection pool exhausted - timeout waiting for connection");
            
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SQLException("Interrupted while waiting for connection", e);
        }
    }
    
    /**
     * Return a connection to the pool
     */
    void returnConnection(Connection connection) {
        if (isShutdown.get()) {
            closeConnectionSilently(connection);
            return;
        }
        
        if (isConnectionValid(connection)) {
            if (availableConnections.offer(connection)) {
                activeConnections.decrementAndGet();
                logger.debug("Returned connection to pool");
            } else {
                // Pool is full, close the connection
                closeConnectionSilently(connection);
                currentPoolSize.decrementAndGet();
                logger.debug("Pool full, closed excess connection");
            }
        } else {
            // Connection is invalid, close it
            closeConnectionSilently(connection);
            currentPoolSize.decrementAndGet();
            activeConnections.decrementAndGet();
            logger.debug("Closed invalid connection");
        }
    }
    
    /**
     * Create a new database connection
     */
    private Connection createNewConnection() {
        try {
            Connection conn = DriverManager.getConnection(jdbcUrl);
            
            // Configure connection for SQLite
            conn.setAutoCommit(true);
            
            // SQLite-specific optimizations
            try (java.sql.Statement stmt = conn.createStatement()) {
                stmt.execute("PRAGMA journal_mode=WAL");
                stmt.execute("PRAGMA synchronous=FULL");
                stmt.execute("PRAGMA busy_timeout=10000");
                stmt.execute("PRAGMA temp_store=MEMORY");
                stmt.execute("PRAGMA mmap_size=268435456"); // 256MB
            }
            
            return conn;
            
        } catch (SQLException e) {
            logger.error("Failed to create new database connection", e);
            return null;
        }
    }
    
    /**
     * Check if a connection is still valid
     */
    private boolean isConnectionValid(Connection connection) {
        try {
            return connection != null && !connection.isClosed() && connection.isValid(1);
        } catch (SQLException e) {
            return false;
        }
    }
    
    /**
     * Close a connection without throwing exceptions
     */
    private void closeConnectionSilently(Connection connection) {
        if (connection != null) {
            try {
                connection.close();
            } catch (SQLException e) {
                logger.debug("Error closing connection: {}", e.getMessage());
            }
        }
    }
    
    /**
     * Get connection pool statistics
     */
    public ConnectionPoolStats getStats() {
        return new ConnectionPoolStats(
            currentPoolSize.get(),
            activeConnections.get(),
            availableConnections.size(),
            totalConnectionsCreated.get(),
            totalConnectionsReused.get(),
            connectionTimeouts.get(),
            maxPoolSize,
            minPoolSize
        );
    }
    
    /**
     * Check if the pool is healthy
     */
    public boolean isHealthy() {
        return !isShutdown.get() && 
               currentPoolSize.get() > 0 && 
               activeConnections.get() < maxPoolSize;
    }
    
    /**
     * Shutdown the connection pool
     */
    public void shutdown() {
        if (isShutdown.getAndSet(true)) {
            return; // Already shutdown
        }
        
        logger.info("Shutting down connection pool");
        
        // Close all available connections
        Connection conn;
        while ((conn = availableConnections.poll()) != null) {
            closeConnectionSilently(conn);
            currentPoolSize.decrementAndGet();
        }
        
        logger.info("Connection pool shutdown completed");
    }
    
    /**
     * Connection pool statistics
     */
    public static class ConnectionPoolStats {
        private final int currentPoolSize;
        private final int activeConnections;
        private final int availableConnections;
        private final int totalConnectionsCreated;
        private final int totalConnectionsReused;
        private final int connectionTimeouts;
        private final int maxPoolSize;
        private final int minPoolSize;
        
        public ConnectionPoolStats(int currentPoolSize, int activeConnections, int availableConnections,
                                 int totalConnectionsCreated, int totalConnectionsReused, 
                                 int connectionTimeouts, int maxPoolSize, int minPoolSize) {
            this.currentPoolSize = currentPoolSize;
            this.activeConnections = activeConnections;
            this.availableConnections = availableConnections;
            this.totalConnectionsCreated = totalConnectionsCreated;
            this.totalConnectionsReused = totalConnectionsReused;
            this.connectionTimeouts = connectionTimeouts;
            this.maxPoolSize = maxPoolSize;
            this.minPoolSize = minPoolSize;
        }
        
        // Getters
        public int getCurrentPoolSize() { return currentPoolSize; }
        public int getActiveConnections() { return activeConnections; }
        public int getAvailableConnections() { return availableConnections; }
        public int getTotalConnectionsCreated() { return totalConnectionsCreated; }
        public int getTotalConnectionsReused() { return totalConnectionsReused; }
        public int getConnectionTimeouts() { return connectionTimeouts; }
        public int getMaxPoolSize() { return maxPoolSize; }
        public int getMinPoolSize() { return minPoolSize; }
        
        public double getPoolUtilization() {
            return maxPoolSize > 0 ? (double) currentPoolSize / maxPoolSize : 0.0;
        }
        
        public double getReuseRate() {
            int totalConnections = totalConnectionsCreated + totalConnectionsReused;
            return totalConnections > 0 ? (double) totalConnectionsReused / totalConnections : 0.0;
        }
    }
}