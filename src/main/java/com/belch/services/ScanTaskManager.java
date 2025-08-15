package com.belch.services;

import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.Crawl;
import burp.api.montoya.scanner.ScanTask;
import com.belch.database.DatabaseService;
import com.belch.websocket.WebSocketManager;
import com.belch.websocket.WebSocketEvent;
import com.belch.websocket.WebSocketEventType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Manages scanner tasks including audits and crawls with database persistence and WebSocket updates.
 * Provides task registration, tracking, status monitoring, and lifecycle management.
 */
public class ScanTaskManager {
    
    private static final Logger logger = LoggerFactory.getLogger(ScanTaskManager.class);
    
    private final DatabaseService databaseService;
    private final WebSocketManager webSocketManager;
    
    // In-memory task tracking
    private final Map<String, TaskInfo> activeTasks = new ConcurrentHashMap<>();
    private final Map<String, Audit> activeAudits = new ConcurrentHashMap<>();
    private final Map<String, Crawl> activeCrawls = new ConcurrentHashMap<>();
    
    // Background monitoring
    private final ScheduledExecutorService taskMonitor = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "ScanTaskMonitor");
        t.setDaemon(true);
        return t;
    });
    
    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private final AtomicBoolean shutdown = new AtomicBoolean(false);
    
    // Task status monitoring interval (seconds)
    private static final int MONITOR_INTERVAL = 10;
    
    /**
     * Represents task information for tracking
     */
    public static class TaskInfo {
        private final String taskId;
        private final TaskType taskType;
        private final String status;
        private final Instant createdAt;
        private final Instant updatedAt;
        private final Map<String, Object> config;
        private final String sessionTag;
        private Map<String, Object> results;
        private String errorMessage;
        
        public TaskInfo(String taskId, TaskType taskType, String status, 
                       Map<String, Object> config, String sessionTag) {
            this.taskId = taskId;
            this.taskType = taskType;
            this.status = status;
            this.createdAt = Instant.now();
            this.updatedAt = Instant.now();
            this.config = config != null ? new HashMap<>(config) : new HashMap<>();
            this.sessionTag = sessionTag;
        }
        
        // Getters
        public String getTaskId() { return taskId; }
        public TaskType getTaskType() { return taskType; }
        public String getStatus() { return status; }
        public Instant getCreatedAt() { return createdAt; }
        public Instant getUpdatedAt() { return updatedAt; }
        public Map<String, Object> getConfig() { return config; }
        public String getSessionTag() { return sessionTag; }
        public Map<String, Object> getResults() { return results; }
        public String getErrorMessage() { return errorMessage; }
        
        public void setResults(Map<String, Object> results) { this.results = results; }
        public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
    }
    
    /**
     * Task types supported by the manager
     */
    public enum TaskType {
        AUDIT, CRAWL, CRAWL_AND_AUDIT
    }
    
    /**
     * Task status values
     */
    public static class TaskStatus {
        public static final String PENDING = "PENDING";
        public static final String RUNNING = "RUNNING";
        public static final String COMPLETED = "COMPLETED";
        public static final String FAILED = "FAILED";
        public static final String CANCELLED = "CANCELLED";
    }
    
    public ScanTaskManager(DatabaseService databaseService, WebSocketManager webSocketManager) {
        this.databaseService = databaseService;
        this.webSocketManager = webSocketManager;
    }
    
    /**
     * Initialize the task manager and start monitoring
     */
    public void initialize() {
        if (initialized.getAndSet(true)) {
            logger.warn("ScanTaskManager already initialized");
            return;
        }
        
        if (databaseService == null || !databaseService.isInitialized()) {
            logger.error("Cannot initialize ScanTaskManager - database service not available");
            throw new IllegalStateException("DatabaseService is required for ScanTaskManager");
        }
        
        try {
            // Ensure database tables exist
            createDatabaseTables();
            
            // Load existing tasks from database
            loadExistingTasks();
            
            // Start task monitoring
            startTaskMonitoring();
            
            logger.info("ScanTaskManager initialized successfully");
            
        } catch (Exception e) {
            logger.error("Failed to initialize ScanTaskManager", e);
            initialized.set(false);
            throw new RuntimeException("Failed to initialize ScanTaskManager", e);
        }
    }
    
    /**
     * Register a new audit task
     */
    public String registerAudit(Audit audit, Map<String, Object> config, String sessionTag) {
        if (shutdown.get()) {
            throw new IllegalStateException("ScanTaskManager is shut down");
        }
        
        String taskId = generateTaskId();
        TaskInfo taskInfo = new TaskInfo(taskId, TaskType.AUDIT, TaskStatus.PENDING, config, sessionTag);
        
        try {
            // Store in database
            persistTask(taskInfo);
            
            // Track in memory
            activeTasks.put(taskId, taskInfo);
            activeAudits.put(taskId, audit);
            
            logger.info("Registered audit task: {} (session: {})", taskId, sessionTag);
            
            // Broadcast task registration
            broadcastTaskEvent(taskId, "TASK_REGISTERED", null);
            
            return taskId;
            
        } catch (Exception e) {
            logger.error("Failed to register audit task", e);
            throw new RuntimeException("Failed to register audit task", e);
        }
    }
    
    /**
     * Register a new crawl task
     */
    public String registerCrawl(Crawl crawl, Map<String, Object> config, String sessionTag) {
        if (shutdown.get()) {
            throw new IllegalStateException("ScanTaskManager is shut down");
        }
        
        String taskId = generateTaskId();
        TaskInfo taskInfo = new TaskInfo(taskId, TaskType.CRAWL, TaskStatus.PENDING, config, sessionTag);
        
        try {
            // Store in database
            persistTask(taskInfo);
            
            // Track in memory
            activeTasks.put(taskId, taskInfo);
            activeCrawls.put(taskId, crawl);
            
            logger.info("Registered crawl task: {} (session: {})", taskId, sessionTag);
            
            // Broadcast task registration
            broadcastTaskEvent(taskId, "TASK_REGISTERED", null);
            
            return taskId;
            
        } catch (Exception e) {
            logger.error("Failed to register crawl task", e);
            throw new RuntimeException("Failed to register crawl task", e);
        }
    }
    
    /**
     * Get task status and details
     */
    public Map<String, Object> getTaskStatus(String taskId) {
        TaskInfo taskInfo = activeTasks.get(taskId);
        if (taskInfo == null) {
            // Try to load from database
            taskInfo = loadTaskFromDatabase(taskId);
        }
        
        if (taskInfo == null) {
            return null;
        }
        
        Map<String, Object> status = new HashMap<>();
        status.put("task_id", taskInfo.getTaskId());
        status.put("task_type", taskInfo.getTaskType().toString());
        status.put("status", taskInfo.getStatus());
        status.put("created_at", taskInfo.getCreatedAt().toEpochMilli());
        status.put("updated_at", taskInfo.getUpdatedAt().toEpochMilli());
        status.put("config", taskInfo.getConfig());
        status.put("session_tag", taskInfo.getSessionTag());
        
        if (taskInfo.getResults() != null) {
            status.put("results", taskInfo.getResults());
        }
        
        if (taskInfo.getErrorMessage() != null) {
            status.put("error_message", taskInfo.getErrorMessage());
        }
        
        // Add live progress information if task is active
        if (TaskStatus.RUNNING.equals(taskInfo.getStatus())) {
            Map<String, Object> progress = getLiveProgress(taskId, taskInfo.getTaskType());
            if (progress != null) {
                status.put("progress", progress);
            }
        }
        
        return status;
    }
    
    /**
     * Cancel a task
     */
    public boolean cancelTask(String taskId) {
        TaskInfo taskInfo = activeTasks.get(taskId);
        if (taskInfo == null) {
            return false;
        }
        
        try {
            // Cancel the underlying task
            if (taskInfo.getTaskType() == TaskType.AUDIT) {
                // Note: Montoya API doesn't provide direct cancel method for audits
                logger.warn("Audit cancellation not directly supported by Montoya API");
            } else if (taskInfo.getTaskType() == TaskType.CRAWL) {
                // Note: Montoya API doesn't provide direct cancel method for crawls
                logger.warn("Crawl cancellation not directly supported by Montoya API");
            }
            
            // Update task status
            updateTaskStatus(taskId, TaskStatus.CANCELLED, null, "Task cancelled by user");
            
            // Remove from active tracking
            activeTasks.remove(taskId);
            activeAudits.remove(taskId);
            activeCrawls.remove(taskId);
            
            logger.info("Cancelled task: {}", taskId);
            
            // Broadcast cancellation
            broadcastTaskEvent(taskId, "TASK_CANCELLED", null);
            
            return true;
            
        } catch (Exception e) {
            logger.error("Failed to cancel task: {}", taskId, e);
            return false;
        }
    }
    
    /**
     * List all tasks with optional filtering
     */
    public List<Map<String, Object>> listTasks(String status, TaskType taskType, String sessionTag, int limit, int offset) {
        List<Map<String, Object>> tasks = new ArrayList<>();
        
        try (Connection conn = databaseService.getConnection()) {
            StringBuilder sql = new StringBuilder("SELECT * FROM scan_tasks WHERE 1=1");
            List<Object> params = new ArrayList<>();
            
            if (status != null) {
                sql.append(" AND status = ?");
                params.add(status);
            }
            
            if (taskType != null) {
                sql.append(" AND task_type = ?");
                params.add(taskType.toString());
            }
            
            if (sessionTag != null) {
                sql.append(" AND session_tag = ?");
                params.add(sessionTag);
            }
            
            sql.append(" ORDER BY created_at DESC LIMIT ? OFFSET ?");
            params.add(limit);
            params.add(offset);
            
            try (PreparedStatement stmt = conn.prepareStatement(sql.toString())) {
                for (int i = 0; i < params.size(); i++) {
                    stmt.setObject(i + 1, params.get(i));
                }
                
                try (ResultSet rs = stmt.executeQuery()) {
                    while (rs.next()) {
                        Map<String, Object> task = new HashMap<>();
                        task.put("task_id", rs.getString("id"));
                        task.put("task_type", rs.getString("task_type"));
                        task.put("status", rs.getString("status"));
                        task.put("created_at", rs.getTimestamp("created_at").toInstant().toEpochMilli());
                        task.put("updated_at", rs.getTimestamp("updated_at").toInstant().toEpochMilli());
                        task.put("session_tag", rs.getString("session_tag"));
                        
                        String configJson = rs.getString("config");
                        if (configJson != null && !configJson.isEmpty()) {
                            // Parse JSON config if needed
                            task.put("config", configJson);
                        }
                        
                        String resultsJson = rs.getString("results");
                        if (resultsJson != null && !resultsJson.isEmpty()) {
                            task.put("results", resultsJson);
                        }
                        
                        String errorMessage = rs.getString("error_message");
                        if (errorMessage != null) {
                            task.put("error_message", errorMessage);
                        }
                        
                        tasks.add(task);
                    }
                }
            }
            
        } catch (SQLException e) {
            logger.error("Failed to list tasks", e);
            throw new RuntimeException("Failed to list tasks", e);
        }
        
        return tasks;
    }
    
    /**
     * Shutdown the task manager
     */
    public void shutdown() {
        if (shutdown.getAndSet(true)) {
            return;
        }
        
        logger.info("ScanTaskManager shutting down");
        
        // Stop task monitoring
        taskMonitor.shutdown();
        try {
            if (!taskMonitor.awaitTermination(5, TimeUnit.SECONDS)) {
                taskMonitor.shutdownNow();
            }
        } catch (InterruptedException e) {
            taskMonitor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        
        // Clear in-memory tracking
        activeTasks.clear();
        activeAudits.clear();
        activeCrawls.clear();
        
        logger.info("ScanTaskManager shutdown completed");
    }
    
    // Private helper methods
    
    private void createDatabaseTables() throws SQLException {
        try (Connection conn = databaseService.getConnection()) {
            // Create scan_tasks table
            String createTasksTable = "CREATE TABLE IF NOT EXISTS scan_tasks (" +
                "id TEXT PRIMARY KEY," +
                "task_type TEXT NOT NULL," +
                "status TEXT NOT NULL," +
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP," +
                "updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP," +
                "started_at TIMESTAMP," +
                "completed_at TIMESTAMP," +
                "config TEXT," +
                "results TEXT," +
                "error_message TEXT," +
                "session_tag TEXT" +
                ")";
            
            try (PreparedStatement stmt = conn.prepareStatement(createTasksTable)) {
                stmt.executeUpdate();
            }
            
            // Create scan_metrics table
            String createMetricsTable = "CREATE TABLE IF NOT EXISTS scan_metrics (" +
                "scan_task_id TEXT PRIMARY KEY," +
                "duration_seconds INTEGER," +
                "requests_made INTEGER," +
                "insertion_points_tested INTEGER," +
                "issues_found INTEGER," +
                "errors_encountered INTEGER," +
                "FOREIGN KEY (scan_task_id) REFERENCES scan_tasks(id)" +
                ")";
            
            try (PreparedStatement stmt = conn.prepareStatement(createMetricsTable)) {
                stmt.executeUpdate();
            }
            
            logger.debug("Database tables created successfully");
        }
    }
    
    private void loadExistingTasks() {
        // Load active tasks from database on startup
        List<Map<String, Object>> activeDatabaseTasks = listTasks(TaskStatus.RUNNING, null, null, 100, 0);
        logger.info("Loaded {} active tasks from database", activeDatabaseTasks.size());
    }
    
    private void startTaskMonitoring() {
        // DISABLED: Task monitoring causes UnsupportedOperationException issues with Burp API
        logger.info("Task monitoring DISABLED due to Burp API compatibility issues");
        logger.info("Task status will be available through direct API calls only");
    }
    
    private void monitorActiveTasks() {
        for (Map.Entry<String, TaskInfo> entry : activeTasks.entrySet()) {
            String taskId = entry.getKey();
            TaskInfo taskInfo = entry.getValue();
            
            try {
                // Check task progress and update status
                Map<String, Object> progress = getLiveProgress(taskId, taskInfo.getTaskType());
                if (progress != null) {
                    // Broadcast progress update
                    broadcastTaskEvent(taskId, "TASK_PROGRESS", progress);
                }
                
            } catch (Exception e) {
                logger.debug("Error monitoring task {}: {}", taskId, e.getMessage());
            }
        }
    }
    
    private Map<String, Object> getLiveProgress(String taskId, TaskType taskType) {
        Map<String, Object> progress = new HashMap<>();
        
        try {
            if (taskType == TaskType.AUDIT) {
                Audit audit = activeAudits.get(taskId);
                if (audit != null) {
                    // Handle statusMessage() method that may not be implemented
                    try {
                        progress.put("status_message", audit.statusMessage());
                    } catch (Exception e) {
                        // Catch all exceptions including UnsupportedOperationException
                        progress.put("status_message", "Audit in progress");
                        logger.debug("Audit statusMessage() not available: {}", e.getMessage());
                    }
                    
                    try {
                        progress.put("request_count", audit.requestCount());
                    } catch (UnsupportedOperationException e) {
                        progress.put("request_count", 0);
                    } catch (Exception e) {
                        progress.put("request_count", "Unavailable");
                    }
                    
                    try {
                        progress.put("insertion_points", audit.insertionPointCount());
                    } catch (UnsupportedOperationException e) {
                        progress.put("insertion_points", 0);
                    } catch (Exception e) {
                        progress.put("insertion_points", "Unavailable");
                    }
                    
                    // Handle issues() method that may not be implemented
                    try {
                        progress.put("issues_found", audit.issues().size());
                    } catch (Exception e) {
                        // Catch all exceptions including UnsupportedOperationException
                        progress.put("issues_found", "API not available");
                        logger.debug("Audit issues() not available: {}", e.getMessage());
                    }
                    
                    try {
                        progress.put("error_count", audit.errorCount());
                    } catch (UnsupportedOperationException e) {
                        progress.put("error_count", 0);
                    } catch (Exception e) {
                        progress.put("error_count", "Unavailable");
                    }
                }
            } else if (taskType == TaskType.CRAWL) {
                Crawl crawl = activeCrawls.get(taskId);
                if (crawl != null) {
                    // Handle statusMessage() method that may not be implemented
                    try {
                        progress.put("status_message", crawl.statusMessage());
                    } catch (Exception e) {
                        // Catch all exceptions including UnsupportedOperationException
                        progress.put("status_message", "Crawl in progress");
                        logger.debug("Crawl statusMessage() not available: {}", e.getMessage());
                    }
                    
                    try {
                        progress.put("request_count", crawl.requestCount());
                    } catch (UnsupportedOperationException e) {
                        progress.put("request_count", 0);
                    } catch (Exception e) {
                        progress.put("request_count", "Unavailable");
                    }
                    
                    try {
                        progress.put("error_count", crawl.errorCount());
                    } catch (UnsupportedOperationException e) {
                        progress.put("error_count", 0);
                    } catch (Exception e) {
                        progress.put("error_count", "Unavailable");
                    }
                    // Note: requestsQueued() method not available in this API version
                }
            }
            
            progress.put("timestamp", System.currentTimeMillis());
            return progress;
            
        } catch (Exception e) {
            logger.debug("Failed to get live progress for task {}: {}", taskId, e.getMessage());
            return null;
        }
    }
    
    private void persistTask(TaskInfo taskInfo) throws SQLException {
        try (Connection conn = databaseService.getConnection()) {
            String sql = "INSERT INTO scan_tasks (id, task_type, status, created_at, updated_at, config, session_tag) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?)";
            
            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                stmt.setString(1, taskInfo.getTaskId());
                stmt.setString(2, taskInfo.getTaskType().toString());
                stmt.setString(3, taskInfo.getStatus());
                stmt.setTimestamp(4, java.sql.Timestamp.from(taskInfo.getCreatedAt()));
                stmt.setTimestamp(5, java.sql.Timestamp.from(taskInfo.getUpdatedAt()));
                stmt.setString(6, taskInfo.getConfig().toString()); // Simple string representation
                stmt.setString(7, taskInfo.getSessionTag());
                
                stmt.executeUpdate();
            }
        }
    }
    
    private void updateTaskStatus(String taskId, String newStatus, Map<String, Object> results, String errorMessage) {
        try (Connection conn = databaseService.getConnection()) {
            String sql = "UPDATE scan_tasks " +
                "SET status = ?, updated_at = ?, results = ?, error_message = ? " +
                "WHERE id = ?";
            
            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                stmt.setString(1, newStatus);
                stmt.setTimestamp(2, java.sql.Timestamp.from(Instant.now()));
                stmt.setString(3, results != null ? results.toString() : null);
                stmt.setString(4, errorMessage);
                stmt.setString(5, taskId);
                
                stmt.executeUpdate();
            }
            
            // Update in-memory task if it exists
            TaskInfo taskInfo = activeTasks.get(taskId);
            if (taskInfo != null) {
                if (results != null) {
                    taskInfo.setResults(results);
                }
                if (errorMessage != null) {
                    taskInfo.setErrorMessage(errorMessage);
                }
            }
            
        } catch (SQLException e) {
            logger.error("Failed to update task status for {}", taskId, e);
        }
    }
    
    private TaskInfo loadTaskFromDatabase(String taskId) {
        try (Connection conn = databaseService.getConnection()) {
            String sql = "SELECT * FROM scan_tasks WHERE id = ?";
            
            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                stmt.setString(1, taskId);
                
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        TaskType taskType = TaskType.valueOf(rs.getString("task_type"));
                        String status = rs.getString("status");
                        String sessionTag = rs.getString("session_tag");
                        
                        // Parse config (simplified)
                        Map<String, Object> config = new HashMap<>();
                        String configStr = rs.getString("config");
                        if (configStr != null) {
                            config.put("raw_config", configStr);
                        }
                        
                        return new TaskInfo(taskId, taskType, status, config, sessionTag);
                    }
                }
            }
            
        } catch (SQLException e) {
            logger.error("Failed to load task from database: {}", taskId, e);
        }
        
        return null;
    }
    
    private void broadcastTaskEvent(String taskId, String eventType, Map<String, Object> data) {
        if (webSocketManager == null) {
            return;
        }
        
        try {
            Map<String, Object> eventData = new HashMap<>();
            eventData.put("task_id", taskId);
            eventData.put("event_type", eventType);
            eventData.put("timestamp", System.currentTimeMillis());
            
            if (data != null) {
                eventData.putAll(data);
            }
            
            WebSocketEvent event = new WebSocketEvent(WebSocketEventType.SCAN_PROGRESS, null);
            event.addData("scan_event", eventData);
            
            webSocketManager.broadcast(event);
            
        } catch (Exception e) {
            logger.debug("Failed to broadcast task event: {}", e.getMessage());
        }
    }
    
    private String generateTaskId() {
        return "task_" + System.currentTimeMillis() + "_" + (int)(Math.random() * 10000);
    }
    
    public boolean isReady() {
        return initialized.get() && !shutdown.get() && databaseService != null;
    }
    
    public int getActiveTaskCount() {
        return activeTasks.size();
    }
}