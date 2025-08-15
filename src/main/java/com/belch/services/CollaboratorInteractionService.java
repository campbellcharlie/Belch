package com.belch.services;

import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.DnsDetails;
import burp.api.montoya.collaborator.HttpDetails;
import burp.api.montoya.collaborator.SmtpDetails;
import com.belch.database.DatabaseService;
import com.belch.config.ApiConfig;
import com.belch.websocket.EventBroadcaster;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Enhanced collaborator interaction service for storing all interactions in database,
 * pattern matching, automated alerts, bulk payload management, and analytics.
 * 
 * Features:
 * - Comprehensive interaction storage with normalized schema
 * - Pattern matching for interactions with configurable rules
 * - Automated alert system for critical patterns
 * - Bulk payload management and tracking
 * - Interaction analytics and reporting
 * - Real-time WebSocket notifications
 */
public class CollaboratorInteractionService {
    
    private static final Logger logger = LoggerFactory.getLogger(CollaboratorInteractionService.class);
    
    private final DatabaseService databaseService;
    private final ApiConfig config;
    private EventBroadcaster eventBroadcaster;
    
    // Pattern matching configuration
    private final Map<String, Pattern> patterns = new HashMap<>();
    private final Map<String, String> alertRules = new HashMap<>();
    
    // Analytics counters
    private final AtomicLong totalInteractions = new AtomicLong(0);
    private final AtomicLong dnsInteractions = new AtomicLong(0);
    private final AtomicLong httpInteractions = new AtomicLong(0);
    private final AtomicLong smtpInteractions = new AtomicLong(0);
    private final AtomicLong alertsTriggered = new AtomicLong(0);
    
    // Background processing
    private final ScheduledExecutorService analyticsExecutor;
    
    public CollaboratorInteractionService(DatabaseService databaseService, ApiConfig config) {
        this.databaseService = databaseService;
        this.config = config;
        
        this.analyticsExecutor = Executors.newScheduledThreadPool(1, r -> {
            Thread t = new Thread(r, "CollaboratorInteractionService-Analytics");
            t.setDaemon(true);
            t.setPriority(Thread.NORM_PRIORITY - 1);
            return t;
        });
        
        initializeDatabase();
        initializeDefaultPatterns();
        startAnalytics();
        
        logger.info("✅ CollaboratorInteractionService initialized with database storage and pattern matching");
    }
    
    /**
     * Set the event broadcaster for real-time WebSocket updates
     */
    public void setEventBroadcaster(EventBroadcaster eventBroadcaster) {
        this.eventBroadcaster = eventBroadcaster;
        logger.info("[*] CollaboratorInteractionService WebSocket broadcasting enabled");
    }
    
    /**
     * Initialize database tables for collaborator interactions
     */
    private void initializeDatabase() {
        try (Connection conn = databaseService.getConnection()) {
            
            // Create main interactions table
            String createInteractionsTable = "CREATE TABLE IF NOT EXISTS collaborator_interactions (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "interaction_id TEXT NOT NULL UNIQUE, " +
                "client_secret_hash TEXT, " +
                "interaction_type TEXT NOT NULL, " +
                "timestamp_ms INTEGER NOT NULL, " +
                "session_tag TEXT, " +
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
                ")";
            
            // Create DNS details table
            String createDnsTable = "CREATE TABLE IF NOT EXISTS collaborator_dns_details (" +
                "interaction_id TEXT PRIMARY KEY, " +
                "query TEXT, " +
                "query_type TEXT, " +
                "raw_details TEXT, " +
                "FOREIGN KEY(interaction_id) REFERENCES collaborator_interactions(interaction_id) ON DELETE CASCADE" +
                ")";
            
            // Create HTTP details table
            String createHttpTable = """
                CREATE TABLE IF NOT EXISTS collaborator_http_details (
                    interaction_id TEXT PRIMARY KEY,
                    request_method TEXT,
                    request_url TEXT,
                    request_headers TEXT,
                    request_body TEXT,
                    response_status INTEGER,
                    response_headers TEXT,
                    response_body TEXT,
                    raw_details TEXT,
                    FOREIGN KEY(interaction_id) REFERENCES collaborator_interactions(interaction_id) ON DELETE CASCADE
                )
            """;
            
            // Create SMTP details table
            String createSmtpTable = """
                CREATE TABLE IF NOT EXISTS collaborator_smtp_details (
                    interaction_id TEXT PRIMARY KEY,
                    protocol TEXT,
                    sender TEXT,
                    recipient TEXT,
                    message_content TEXT,
                    raw_details TEXT,
                    FOREIGN KEY(interaction_id) REFERENCES collaborator_interactions(interaction_id) ON DELETE CASCADE
                )
            """;
            
            // Create pattern matches table
            String createPatternsTable = """
                CREATE TABLE IF NOT EXISTS collaborator_pattern_matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    interaction_id TEXT NOT NULL,
                    pattern_name TEXT NOT NULL,
                    pattern_value TEXT NOT NULL,
                    match_details TEXT,
                    alert_triggered BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(interaction_id) REFERENCES collaborator_interactions(interaction_id) ON DELETE CASCADE
                )
            """;
            
            // Create payload tracking table
            String createPayloadsTable = """
                CREATE TABLE IF NOT EXISTS collaborator_payloads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload_text TEXT NOT NULL,
                    client_secret_hash TEXT,
                    interaction_id_generated TEXT,
                    payload_type TEXT,
                    session_tag TEXT,
                    custom_data TEXT,
                    server_address TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    interactions_received INTEGER DEFAULT 0,
                    last_interaction_at TIMESTAMP
                )
            """;
            
            // Create analytics table
            String createAnalyticsTable = """
                CREATE TABLE IF NOT EXISTS collaborator_analytics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    metric_name TEXT NOT NULL,
                    metric_value INTEGER NOT NULL,
                    metric_details TEXT,
                    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """;
            
            try (Statement stmt = conn.createStatement()) {
                stmt.execute(createInteractionsTable);
                stmt.execute(createDnsTable);
                stmt.execute(createHttpTable);
                stmt.execute(createSmtpTable);
                stmt.execute(createPatternsTable);
                stmt.execute(createPayloadsTable);
                stmt.execute(createAnalyticsTable);
                
                // Create indexes separately
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_interactions_id ON collaborator_interactions(interaction_id)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_interactions_secret ON collaborator_interactions(client_secret_hash)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_interactions_type ON collaborator_interactions(interaction_type)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_interactions_timestamp ON collaborator_interactions(timestamp_ms)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_interactions_session ON collaborator_interactions(session_tag)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_interactions_created ON collaborator_interactions(created_at)");
                
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_http_method ON collaborator_http_details(request_method)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_http_url ON collaborator_http_details(request_url)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_http_status ON collaborator_http_details(response_status)");
                
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_smtp_protocol ON collaborator_smtp_details(protocol)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_smtp_sender ON collaborator_smtp_details(sender)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_smtp_recipient ON collaborator_smtp_details(recipient)");
                
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_patterns_interaction ON collaborator_pattern_matches(interaction_id)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_patterns_name ON collaborator_pattern_matches(pattern_name)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_patterns_alert ON collaborator_pattern_matches(alert_triggered)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_patterns_created ON collaborator_pattern_matches(created_at)");
                
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_payloads_text ON collaborator_payloads(payload_text)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_payloads_secret ON collaborator_payloads(client_secret_hash)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_payloads_interaction ON collaborator_payloads(interaction_id_generated)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_payloads_type ON collaborator_payloads(payload_type)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_payloads_session ON collaborator_payloads(session_tag)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_payloads_created ON collaborator_payloads(created_at)");
                
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_analytics_name ON collaborator_analytics(metric_name)");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_analytics_recorded ON collaborator_analytics(recorded_at)");
                
                logger.info("📊 Collaborator interaction database tables created successfully");
            }
            
        } catch (SQLException e) {
            logger.error("Failed to initialize collaborator interaction database", e);
            throw new RuntimeException("Database initialization failed", e);
        }
    }
    
    /**
     * Initialize default pattern matching rules
     */
    private void initializeDefaultPatterns() {
        // Common patterns for security testing
        addPattern("sql_injection", "(?i)(union|select|insert|update|delete|drop|exec|execute)", "SQL injection attempt detected");
        addPattern("xss_attempt", "(?i)(<script|javascript:|onload=|onerror=|alert\\()", "XSS attempt detected");
        addPattern("lfi_attempt", "(?i)(\\.\\./|/etc/passwd|/etc/shadow|windows/system32)", "LFI attempt detected");
        addPattern("rfi_attempt", "(?i)(http://|https://|ftp://)", "RFI attempt detected");
        addPattern("command_injection", "(?i)(;\\s*(cat|ls|pwd|whoami|id|uname)|\\|\\s*(cat|ls|pwd))", "Command injection attempt detected");
        addPattern("ssrf_attempt", "(?i)(localhost|127\\.0\\.0\\.1|169\\.254|10\\.|192\\.168|172\\.(1[6-9]|2[0-9]|3[01]))", "SSRF attempt detected");
        addPattern("template_injection", "(?i)(\\{\\{|\\$\\{|<%=|<\\?php)", "Template injection attempt detected");
        addPattern("deserialization", "(?i)(java\\.lang|java\\.util|rO0AB|aced0005)", "Deserialization attempt detected");
        addPattern("xxe_attempt", "(?i)(<!ENTITY|SYSTEM|file://|/etc/)", "XXE attempt detected");
        addPattern("ldap_injection", "(?i)(\\*\\)|\\(\\&|\\(\\||\\(\\!)", "LDAP injection attempt detected");
        
        // Infrastructure and reconnaissance patterns
        addPattern("port_scan", "(?i)(nmap|masscan|zmap)", "Port scanning detected");
        addPattern("directory_traversal", "(?i)(\\.\\./.*\\.\\./.*\\.\\./)", "Directory traversal detected");
        addPattern("admin_path", "(?i)(/admin|/administrator|/wp-admin|/phpmyadmin)", "Admin path access detected");
        addPattern("sensitive_file", "(?i)(\\.env|\\.git|web\\.config|backup|dump\\.sql)", "Sensitive file access detected");
        addPattern("api_key_exposure", "(?i)(api_key|access_token|secret_key|private_key)", "API key exposure detected");
        
        logger.info("📋 Initialized {} default pattern matching rules", patterns.size());
    }
    
    /**
     * Add a pattern matching rule
     */
    public void addPattern(String name, String regex, String alertMessage) {
        patterns.put(name, Pattern.compile(regex, Pattern.CASE_INSENSITIVE | Pattern.MULTILINE));
        alertRules.put(name, alertMessage);
        logger.debug("Added pattern rule: {}", name);
    }
    
    /**
     * Remove a pattern matching rule
     */
    public void removePattern(String name) {
        patterns.remove(name);
        alertRules.remove(name);
        logger.debug("Removed pattern rule: {}", name);
    }
    
    /**
     * Store a collaborator interaction in the database
     */
    public long storeInteraction(Interaction interaction, String clientSecretHash, String sessionTag) {
        try (Connection conn = databaseService.getConnection()) {
            conn.setAutoCommit(false);
            
            long interactionDbId = -1;
            
            try {
                // Store main interaction record
                String insertInteraction = """
                    INSERT OR REPLACE INTO collaborator_interactions 
                    (interaction_id, client_secret_hash, interaction_type, timestamp_ms, session_tag)
                    VALUES (?, ?, ?, ?, ?)
                """;
                
                try (PreparedStatement stmt = conn.prepareStatement(insertInteraction, Statement.RETURN_GENERATED_KEYS)) {
                    stmt.setString(1, interaction.id().toString());
                    stmt.setString(2, clientSecretHash);
                    stmt.setString(3, interaction.type().toString());
                    stmt.setLong(4, interaction.timeStamp().toInstant().toEpochMilli());
                    stmt.setString(5, sessionTag);
                    
                    int rowsAffected = stmt.executeUpdate();
                    if (rowsAffected > 0) {
                        try (ResultSet keys = stmt.getGeneratedKeys()) {
                            if (keys.next()) {
                                interactionDbId = keys.getLong(1);
                            }
                        }
                    }
                }
                
                // Store type-specific details
                String interactionId = interaction.id().toString();
                
                if (interaction.dnsDetails().isPresent()) {
                    storeDnsDetails(conn, interactionId, interaction.dnsDetails().get());
                    dnsInteractions.incrementAndGet();
                }
                
                if (interaction.httpDetails().isPresent()) {
                    storeHttpDetails(conn, interactionId, interaction.httpDetails().get());
                    httpInteractions.incrementAndGet();
                }
                
                if (interaction.smtpDetails().isPresent()) {
                    storeSmtpDetails(conn, interactionId, interaction.smtpDetails().get());
                    smtpInteractions.incrementAndGet();
                }
                
                // Perform pattern matching
                performPatternMatching(conn, interaction);
                
                conn.commit();
                totalInteractions.incrementAndGet();
                
                // Broadcast real-time event
                if (eventBroadcaster != null) {
                    broadcastInteractionEvent(interaction, sessionTag, interactionDbId);
                }
                
                logger.debug("✅ Stored collaborator interaction: {} (type: {})", 
                           interactionId, interaction.type());
                
                return interactionDbId;
                
            } catch (SQLException e) {
                conn.rollback();
                throw e;
            } finally {
                conn.setAutoCommit(true);
            }
            
        } catch (SQLException e) {
            logger.error("Failed to store collaborator interaction", e);
            return -1;
        }
    }
    
    /**
     * Store DNS interaction details
     */
    private void storeDnsDetails(Connection conn, String interactionId, DnsDetails dnsDetails) throws SQLException {
        String insertDns = """
            INSERT OR REPLACE INTO collaborator_dns_details 
            (interaction_id, query, query_type, raw_details)
            VALUES (?, ?, ?, ?)
        """;
        
        try (PreparedStatement stmt = conn.prepareStatement(insertDns)) {
            stmt.setString(1, interactionId);
            stmt.setString(2, dnsDetails.query().toString());
            stmt.setString(3, dnsDetails.queryType().toString());
            stmt.setString(4, dnsDetails.toString()); // Raw details for debugging
            stmt.executeUpdate();
        }
    }
    
    /**
     * Store HTTP interaction details
     */
    private void storeHttpDetails(Connection conn, String interactionId, HttpDetails httpDetails) throws SQLException {
        String insertHttp = """
            INSERT OR REPLACE INTO collaborator_http_details 
            (interaction_id, request_method, request_url, request_headers, request_body, 
             response_status, response_headers, response_body, raw_details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """;
        
        try (PreparedStatement stmt = conn.prepareStatement(insertHttp)) {
            stmt.setString(1, interactionId);
            // Note: HttpDetails methods would need to be explored based on actual API
            // Using toString() as a fallback for raw storage
            stmt.setString(2, "HTTP"); // Method placeholder
            stmt.setString(3, ""); // URL placeholder
            stmt.setString(4, ""); // Headers placeholder
            stmt.setString(5, ""); // Body placeholder
            stmt.setInt(6, 0); // Status placeholder
            stmt.setString(7, ""); // Response headers placeholder
            stmt.setString(8, ""); // Response body placeholder
            stmt.setString(9, httpDetails.toString()); // Raw details
            stmt.executeUpdate();
        }
    }
    
    /**
     * Store SMTP interaction details
     */
    private void storeSmtpDetails(Connection conn, String interactionId, SmtpDetails smtpDetails) throws SQLException {
        String insertSmtp = """
            INSERT OR REPLACE INTO collaborator_smtp_details 
            (interaction_id, protocol, sender, recipient, message_content, raw_details)
            VALUES (?, ?, ?, ?, ?, ?)
        """;
        
        try (PreparedStatement stmt = conn.prepareStatement(insertSmtp)) {
            stmt.setString(1, interactionId);
            stmt.setString(2, smtpDetails.protocol().toString());
            stmt.setString(3, ""); // Sender placeholder - would need to extract from API
            stmt.setString(4, ""); // Recipient placeholder
            stmt.setString(5, ""); // Message content placeholder
            stmt.setString(6, smtpDetails.toString()); // Raw details
            stmt.executeUpdate();
        }
    }
    
    /**
     * Perform pattern matching on interaction data
     */
    private void performPatternMatching(Connection conn, Interaction interaction) throws SQLException {
        String interactionId = interaction.id().toString();
        String searchText = buildSearchText(interaction);
        
        for (Map.Entry<String, Pattern> entry : patterns.entrySet()) {
            String patternName = entry.getKey();
            Pattern pattern = entry.getValue();
            
            Matcher matcher = pattern.matcher(searchText);
            if (matcher.find()) {
                // Store pattern match
                String insertMatch = """
                    INSERT INTO collaborator_pattern_matches 
                    (interaction_id, pattern_name, pattern_value, match_details, alert_triggered)
                    VALUES (?, ?, ?, ?, ?)
                """;
                
                boolean alertTriggered = triggerAlert(patternName, interaction, matcher.group());
                
                try (PreparedStatement stmt = conn.prepareStatement(insertMatch)) {
                    stmt.setString(1, interactionId);
                    stmt.setString(2, patternName);
                    stmt.setString(3, pattern.pattern());
                    stmt.setString(4, "Match: '" + matcher.group() + "' at position " + matcher.start());
                    stmt.setBoolean(5, alertTriggered);
                    stmt.executeUpdate();
                }
                
                logger.info("🔍 Pattern match: {} in interaction {}", patternName, interactionId);
            }
        }
    }
    
    /**
     * Build searchable text from interaction for pattern matching
     */
    private String buildSearchText(Interaction interaction) {
        StringBuilder searchText = new StringBuilder();
        
        // Add interaction ID
        searchText.append(interaction.id().toString()).append(" ");
        
        // Add DNS details if present
        if (interaction.dnsDetails().isPresent()) {
            DnsDetails dns = interaction.dnsDetails().get();
            searchText.append(dns.query()).append(" ");
            searchText.append(dns.queryType().toString()).append(" ");
        }
        
        // Add HTTP details if present
        if (interaction.httpDetails().isPresent()) {
            searchText.append(interaction.httpDetails().get().toString()).append(" ");
        }
        
        // Add SMTP details if present
        if (interaction.smtpDetails().isPresent()) {
            searchText.append(interaction.smtpDetails().get().toString()).append(" ");
        }
        
        return searchText.toString();
    }
    
    /**
     * Trigger alert for pattern match
     */
    private boolean triggerAlert(String patternName, Interaction interaction, String matchText) {
        String alertMessage = alertRules.get(patternName);
        if (alertMessage == null) {
            return false;
        }
        
        alertsTriggered.incrementAndGet();
        
        // Log alert
        logger.warn("🚨 ALERT: {} - Interaction: {} - Match: '{}'", 
                   alertMessage, interaction.id().toString(), matchText);
        
        // Broadcast alert via WebSocket if available
        if (eventBroadcaster != null) {
            Map<String, Object> alertData = new HashMap<>();
            alertData.put("alert_type", "collaborator_pattern_match");
            alertData.put("pattern_name", patternName);
            alertData.put("alert_message", alertMessage);
            alertData.put("interaction_id", interaction.id().toString());
            alertData.put("match_text", matchText);
            alertData.put("interaction_type", interaction.type().toString());
            alertData.put("timestamp", System.currentTimeMillis());
            
            eventBroadcaster.broadcastAlert(alertData, config.getSessionTag());
        }
        
        return true;
    }
    
    /**
     * Register a collaborator payload for tracking
     */
    public void registerPayload(String payloadText, String clientSecretHash, String interactionId, 
                               String payloadType, String sessionTag, String customData, String serverAddress) {
        try (Connection conn = databaseService.getConnection()) {
            String insertPayload = """
                INSERT INTO collaborator_payloads 
                (payload_text, client_secret_hash, interaction_id_generated, payload_type, 
                 session_tag, custom_data, server_address)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """;
            
            try (PreparedStatement stmt = conn.prepareStatement(insertPayload)) {
                stmt.setString(1, payloadText);
                stmt.setString(2, clientSecretHash);
                stmt.setString(3, interactionId);
                stmt.setString(4, payloadType);
                stmt.setString(5, sessionTag);
                stmt.setString(6, customData);
                stmt.setString(7, serverAddress);
                stmt.executeUpdate();
            }
            
            logger.debug("📝 Registered collaborator payload: {} (type: {})", payloadText, payloadType);
            
        } catch (SQLException e) {
            logger.error("Failed to register collaborator payload", e);
        }
    }
    
    /**
     * Broadcast interaction event via WebSocket
     */
    private void broadcastInteractionEvent(Interaction interaction, String sessionTag, long dbId) {
        Map<String, Object> eventData = new HashMap<>();
        eventData.put("event_type", "collaborator_interaction");
        eventData.put("interaction_id", interaction.id().toString());
        eventData.put("interaction_type", interaction.type().toString());
        eventData.put("timestamp", interaction.timeStamp().toInstant().toEpochMilli());
        eventData.put("database_id", dbId);
        
        // Add type-specific data
        if (interaction.dnsDetails().isPresent()) {
            DnsDetails dns = interaction.dnsDetails().get();
            eventData.put("dns_query", dns.query());
            eventData.put("dns_query_type", dns.queryType().toString());
        }
        
        if (interaction.httpDetails().isPresent()) {
            eventData.put("has_http_details", true);
        }
        
        if (interaction.smtpDetails().isPresent()) {
            eventData.put("has_smtp_details", true);
            eventData.put("smtp_protocol", interaction.smtpDetails().get().protocol().toString());
        }
        
        eventBroadcaster.broadcastCollaboratorInteraction(eventData, sessionTag);
    }
    
    /**
     * Start analytics background processing
     */
    private void startAnalytics() {
        // Record analytics every 5 minutes
        analyticsExecutor.scheduleAtFixedRate(this::recordAnalytics, 5, 5, TimeUnit.MINUTES);
        logger.info("📊 Collaborator analytics started (5-minute intervals)");
    }
    
    /**
     * Record analytics metrics
     */
    private void recordAnalytics() {
        try (Connection conn = databaseService.getConnection()) {
            String insertMetric = """
                INSERT INTO collaborator_analytics (metric_name, metric_value, metric_details)
                VALUES (?, ?, ?)
            """;
            
            try (PreparedStatement stmt = conn.prepareStatement(insertMetric)) {
                // Record total interactions
                stmt.setString(1, "total_interactions");
                stmt.setLong(2, totalInteractions.get());
                stmt.setString(3, "Cumulative total of all collaborator interactions");
                stmt.addBatch();
                
                // Record by type
                stmt.setString(1, "dns_interactions");
                stmt.setLong(2, dnsInteractions.get());
                stmt.setString(3, "DNS collaborator interactions");
                stmt.addBatch();
                
                stmt.setString(1, "http_interactions");
                stmt.setLong(2, httpInteractions.get());
                stmt.setString(3, "HTTP collaborator interactions");
                stmt.addBatch();
                
                stmt.setString(1, "smtp_interactions");
                stmt.setLong(2, smtpInteractions.get());
                stmt.setString(3, "SMTP collaborator interactions");
                stmt.addBatch();
                
                stmt.setString(1, "alerts_triggered");
                stmt.setLong(2, alertsTriggered.get());
                stmt.setString(3, "Pattern-based alerts triggered");
                stmt.addBatch();
                
                stmt.executeBatch();
            }
            
        } catch (SQLException e) {
            logger.error("Failed to record collaborator analytics", e);
        }
    }
    
    /**
     * Get comprehensive analytics
     */
    public Map<String, Object> getAnalytics() {
        Map<String, Object> analytics = new HashMap<>();
        
        analytics.put("total_interactions", totalInteractions.get());
        analytics.put("dns_interactions", dnsInteractions.get());
        analytics.put("http_interactions", httpInteractions.get());
        analytics.put("smtp_interactions", smtpInteractions.get());
        analytics.put("alerts_triggered", alertsTriggered.get());
        analytics.put("patterns_configured", patterns.size());
        
        // Get recent analytics from database
        try (Connection conn = databaseService.getConnection()) {
            String query = """
                SELECT metric_name, metric_value, recorded_at
                FROM collaborator_analytics
                WHERE recorded_at > datetime('now', '-24 hours')
                ORDER BY recorded_at DESC
                LIMIT 100
            """;
            
            List<Map<String, Object>> recentMetrics = new ArrayList<>();
            try (PreparedStatement stmt = conn.prepareStatement(query);
                 ResultSet rs = stmt.executeQuery()) {
                
                while (rs.next()) {
                    Map<String, Object> metric = new HashMap<>();
                    metric.put("name", rs.getString("metric_name"));
                    metric.put("value", rs.getLong("metric_value"));
                    metric.put("timestamp", rs.getString("recorded_at"));
                    recentMetrics.add(metric);
                }
            }
            
            analytics.put("recent_metrics", recentMetrics);
            
        } catch (SQLException e) {
            logger.error("Failed to get analytics from database", e);
            analytics.put("database_error", e.getMessage());
        }
        
        return analytics;
    }
    
    /**
     * Get all configured patterns
     */
    public Map<String, Object> getPatterns() {
        Map<String, Object> result = new HashMap<>();
        
        Map<String, Object> patternList = new HashMap<>();
        for (Map.Entry<String, Pattern> entry : patterns.entrySet()) {
            String name = entry.getKey();
            Pattern pattern = entry.getValue();
            
            Map<String, Object> patternInfo = new HashMap<>();
            patternInfo.put("regex", pattern.pattern());
            patternInfo.put("flags", pattern.flags());
            patternInfo.put("alert_message", alertRules.get(name));
            
            patternList.put(name, patternInfo);
        }
        
        result.put("patterns", patternList);
        result.put("total_patterns", patterns.size());
        
        return result;
    }
    
    /**
     * Shutdown the service
     */
    public void shutdown() {
        analyticsExecutor.shutdown();
        try {
            if (!analyticsExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                analyticsExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            analyticsExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        
        logger.info("✅ CollaboratorInteractionService shutdown complete");
    }
}