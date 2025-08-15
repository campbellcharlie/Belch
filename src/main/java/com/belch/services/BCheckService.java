package com.belch.services;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.bchecks.BCheckImportResult;
import burp.api.montoya.scanner.bchecks.BChecks;
import com.belch.config.ApiConfig;
import com.belch.database.DatabaseService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Phase 3 Task 14: Custom Scan Checks & BChecks Integration
 * 
 * Provides BChecks management functionality including:
 * - Import and manage BCheck scripts
 * - Track BCheck execution status
 * - Security validation of BCheck scripts
 * - BCheck metadata and storage
 */
public class BCheckService {
    
    private static final Logger logger = LoggerFactory.getLogger(BCheckService.class);
    
    private final MontoyaApi api;
    private final ApiConfig config;
    private final DatabaseService databaseService;
    private final BChecks bChecks;
    
    // BCheck metadata storage
    private final Map<String, BCheckMetadata> bCheckMetadata = new ConcurrentHashMap<>();
    private final AtomicLong importCounter = new AtomicLong(0);
    
    // Security validation patterns - prevent malicious scripts
    private static final List<String> PROHIBITED_PATTERNS = List.of(
        "System\\.exit",
        "Runtime\\.getRuntime",
        "ProcessBuilder",
        "java\\.lang\\.reflect",
        "java\\.io\\.File",
        "java\\.nio\\.file",
        "javax\\.script",
        "nashorn",
        "rhino"
    );
    
    // Maximum BCheck script size (1MB)
    private static final int MAX_SCRIPT_SIZE = 1024 * 1024;
    
    public BCheckService(MontoyaApi api, ApiConfig config, DatabaseService databaseService) {
        this.api = api;
        this.config = config;
        this.databaseService = databaseService;
        this.bChecks = api.scanner().bChecks();
        
        createDatabaseTables();
        loadExistingBChecks();
        
        logger.info("[*] BCheck Service initialized");
    }
    
    /**
     * Import a BCheck script with security validation.
     */
    public Map<String, Object> importBCheck(String script, String name, String description, boolean enabled) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            // Security validation
            Map<String, Object> validation = validateBCheckSecurity(script);
            if (!(Boolean) validation.get("valid")) {
                result.put("success", false);
                result.put("error", "Security validation failed");
                result.put("validation_errors", validation.get("errors"));
                return result;
            }
            
            // Size validation
            if (script.length() > MAX_SCRIPT_SIZE) {
                result.put("success", false);
                result.put("error", "Script too large");
                result.put("max_size_bytes", MAX_SCRIPT_SIZE);
                return result;
            }
            
            // Import using Montoya API
            BCheckImportResult importResult = bChecks.importBCheck(script, enabled);
            
            // Generate BCheck ID
            String bcheckId = generateBCheckId(script, name);
            
            // Create metadata
            BCheckMetadata metadata = new BCheckMetadata(
                bcheckId, name, description, script, enabled,
                importResult.status() == BCheckImportResult.Status.LOADED_WITHOUT_ERRORS,
                importResult.importErrors()
            );
            
            // Store metadata
            bCheckMetadata.put(bcheckId, metadata);
            persistBCheckMetadata(metadata);
            
            importCounter.incrementAndGet();
            
            result.put("success", true);
            result.put("bcheck_id", bcheckId);
            result.put("name", name);
            result.put("status", importResult.status().toString());
            result.put("enabled", enabled);
            result.put("import_successful", metadata.isImportSuccessful());
            
            if (!importResult.importErrors().isEmpty()) {
                result.put("import_errors", importResult.importErrors());
                result.put("warning", "BCheck imported with errors");
            }
            
            logger.info("Successfully imported BCheck: {} ({})", name, bcheckId);
            
        } catch (Exception e) {
            logger.error("Failed to import BCheck: {}", e.getMessage(), e);
            result.put("success", false);
            result.put("error", "Import failed: " + e.getMessage());
        }
        
        return result;
    }
    
    /**
     * Import BCheck from file.
     */
    public Map<String, Object> importBCheckFromFile(String filePath, String name, String description, boolean enabled) {
        try {
            Path path = Paths.get(filePath);
            if (!Files.exists(path)) {
                return Map.of(
                    "success", false,
                    "error", "File not found: " + filePath
                );
            }
            
            String script = Files.readString(path, StandardCharsets.UTF_8);
            return importBCheck(script, name != null ? name : path.getFileName().toString(), description, enabled);
            
        } catch (Exception e) {
            logger.error("Failed to read BCheck file: {}", e.getMessage(), e);
            return Map.of(
                "success", false,
                "error", "Failed to read file: " + e.getMessage()
            );
        }
    }
    
    /**
     * Get all imported BChecks.
     */
    public Map<String, Object> getBChecks() {
        Map<String, Object> result = new HashMap<>();
        
        List<Map<String, Object>> bchecksList = new ArrayList<>();
        for (BCheckMetadata metadata : bCheckMetadata.values()) {
            Map<String, Object> bcheckInfo = new HashMap<>();
            bcheckInfo.put("id", metadata.getId());
            bcheckInfo.put("name", metadata.getName());
            bcheckInfo.put("description", metadata.getDescription());
            bcheckInfo.put("enabled", metadata.isEnabled());
            bcheckInfo.put("import_successful", metadata.isImportSuccessful());
            bcheckInfo.put("created_at", metadata.getCreatedAt());
            bcheckInfo.put("script_hash", metadata.getScriptHash());
            bcheckInfo.put("script_size", metadata.getScript().length());
            
            if (!metadata.getImportErrors().isEmpty()) {
                bcheckInfo.put("import_errors", metadata.getImportErrors());
            }
            
            bchecksList.add(bcheckInfo);
        }
        
        result.put("bchecks", bchecksList);
        result.put("total_bchecks", bCheckMetadata.size());
        result.put("total_imports", importCounter.get());
        result.put("enabled_count", bCheckMetadata.values().stream()
            .mapToLong(m -> m.isEnabled() ? 1 : 0).sum());
        result.put("successful_imports", bCheckMetadata.values().stream()
            .mapToLong(m -> m.isImportSuccessful() ? 1 : 0).sum());
        
        return result;
    }
    
    /**
     * Get specific BCheck details.
     */
    public Map<String, Object> getBCheck(String bcheckId) {
        BCheckMetadata metadata = bCheckMetadata.get(bcheckId);
        if (metadata == null) {
            return Map.of(
                "success", false,
                "error", "BCheck not found",
                "bcheck_id", bcheckId
            );
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("success", true);
        result.put("id", metadata.getId());
        result.put("name", metadata.getName());
        result.put("description", metadata.getDescription());
        result.put("enabled", metadata.isEnabled());
        result.put("import_successful", metadata.isImportSuccessful());
        result.put("created_at", metadata.getCreatedAt());
        result.put("script_hash", metadata.getScriptHash());
        result.put("script_size", metadata.getScript().length());
        result.put("script", metadata.getScript());
        
        if (!metadata.getImportErrors().isEmpty()) {
            result.put("import_errors", metadata.getImportErrors());
        }
        
        return result;
    }
    
    /**
     * Delete a BCheck.
     */
    public Map<String, Object> deleteBCheck(String bcheckId) {
        BCheckMetadata metadata = bCheckMetadata.remove(bcheckId);
        if (metadata == null) {
            return Map.of(
                "success", false,
                "error", "BCheck not found",
                "bcheck_id", bcheckId
            );
        }
        
        // Remove from database
        deleteBCheckFromDatabase(bcheckId);
        
        logger.info("Deleted BCheck: {} ({})", metadata.getName(), bcheckId);
        
        return Map.of(
            "success", true,
            "bcheck_id", bcheckId,
            "name", metadata.getName(),
            "message", "BCheck deleted successfully"
        );
    }
    
    /**
     * Validate BCheck security.
     */
    public Map<String, Object> validateBCheckSecurity(String script) {
        Map<String, Object> result = new HashMap<>();
        List<String> errors = new ArrayList<>();
        
        // Check for prohibited patterns
        for (String pattern : PROHIBITED_PATTERNS) {
            if (script.matches("(?s).*" + pattern + ".*")) {
                errors.add("Script contains prohibited pattern: " + pattern);
            }
        }
        
        // Check for suspicious imports
        if (script.contains("import java.lang.reflect") || 
            script.contains("import java.io") ||
            script.contains("import java.nio.file")) {
            errors.add("Script contains potentially dangerous imports");
        }
        
        // Check for file system access
        if (script.contains("new File(") || 
            script.contains("Files.") ||
            script.contains("Paths.")) {
            errors.add("Script attempts file system access");
        }
        
        // Check for network access beyond HTTP requests
        if (script.contains("Socket") || 
            script.contains("ServerSocket") ||
            script.contains("URLConnection")) {
            errors.add("Script attempts unauthorized network access");
        }
        
        // Basic size check
        if (script.length() > MAX_SCRIPT_SIZE) {
            errors.add("Script exceeds maximum size limit");
        }
        
        boolean valid = errors.isEmpty();
        
        result.put("valid", valid);
        result.put("errors", errors);
        result.put("script_size", script.length());
        result.put("max_size", MAX_SCRIPT_SIZE);
        
        if (valid) {
            result.put("message", "BCheck script passed security validation");
        } else {
            result.put("message", "BCheck script failed security validation");
        }
        
        return result;
    }
    
    /**
     * Get BCheck statistics.
     */
    public Map<String, Object> getBCheckStats() {
        Map<String, Object> stats = new HashMap<>();
        
        long totalBChecks = bCheckMetadata.size();
        long enabledBChecks = bCheckMetadata.values().stream()
            .mapToLong(m -> m.isEnabled() ? 1 : 0).sum();
        long successfulImports = bCheckMetadata.values().stream()
            .mapToLong(m -> m.isImportSuccessful() ? 1 : 0).sum();
        long failedImports = totalBChecks - successfulImports;
        
        stats.put("total_bchecks", totalBChecks);
        stats.put("enabled_bchecks", enabledBChecks);
        stats.put("disabled_bchecks", totalBChecks - enabledBChecks);
        stats.put("successful_imports", successfulImports);
        stats.put("failed_imports", failedImports);
        stats.put("total_imports_attempted", importCounter.get());
        
        // Script size statistics
        OptionalDouble avgSize = bCheckMetadata.values().stream()
            .mapToInt(m -> m.getScript().length())
            .average();
        
        stats.put("average_script_size", avgSize.isPresent() ? (int) avgSize.getAsDouble() : 0);
        stats.put("max_script_size_limit", MAX_SCRIPT_SIZE);
        
        return stats;
    }
    
    private void createDatabaseTables() {
        try (Connection conn = databaseService.getConnection()) {
            String createBChecksTable = "CREATE TABLE IF NOT EXISTS bchecks (" +
                "id TEXT PRIMARY KEY, " +
                "name TEXT NOT NULL, " +
                "description TEXT, " +
                "script TEXT NOT NULL, " +
                "script_hash TEXT NOT NULL, " +
                "enabled BOOLEAN NOT NULL, " +
                "import_successful BOOLEAN NOT NULL, " +
                "import_errors TEXT, " +
                "created_at TEXT NOT NULL" +
                ")";
            
            try (Statement stmt = conn.createStatement()) {
                stmt.execute(createBChecksTable);
            }
            logger.debug("BChecks database tables created successfully");
            
        } catch (Exception e) {
            logger.error("Failed to create BChecks database tables", e);
        }
    }
    
    private void loadExistingBChecks() {
        try (Connection conn = databaseService.getConnection()) {
            String selectBChecks = "SELECT * FROM bchecks";
            List<Map<String, Object>> rows = new ArrayList<>();
            
            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery(selectBChecks)) {
                
                while (rs.next()) {
                    Map<String, Object> row = new HashMap<>();
                    row.put("id", rs.getString("id"));
                    row.put("name", rs.getString("name"));
                    row.put("description", rs.getString("description"));
                    row.put("script", rs.getString("script"));
                    row.put("enabled", rs.getBoolean("enabled"));
                    row.put("import_successful", rs.getBoolean("import_successful"));
                    row.put("import_errors", rs.getString("import_errors"));
                    row.put("created_at", rs.getString("created_at"));
                    row.put("script_hash", rs.getString("script_hash"));
                    rows.add(row);
                }
            }
            
            for (Map<String, Object> row : rows) {
                BCheckMetadata metadata = new BCheckMetadata(
                    (String) row.get("id"),
                    (String) row.get("name"),
                    (String) row.get("description"),
                    (String) row.get("script"),
                    (Boolean) row.get("enabled"),
                    (Boolean) row.get("import_successful"),
                    parseImportErrors((String) row.get("import_errors"))
                );
                metadata.setCreatedAt((String) row.get("created_at"));
                metadata.setScriptHash((String) row.get("script_hash"));
                
                bCheckMetadata.put(metadata.getId(), metadata);
            }
            
            logger.info("Loaded {} existing BChecks from database", bCheckMetadata.size());
            
        } catch (Exception e) {
            logger.error("Failed to load existing BChecks", e);
        }
    }
    
    private void persistBCheckMetadata(BCheckMetadata metadata) {
        try (Connection conn = databaseService.getConnection()) {
            String insertBCheck = "INSERT OR REPLACE INTO bchecks " +
                "(id, name, description, script, script_hash, enabled, import_successful, import_errors, created_at) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
            
            try (PreparedStatement stmt = conn.prepareStatement(insertBCheck)) {
                stmt.setString(1, metadata.getId());
                stmt.setString(2, metadata.getName());
                stmt.setString(3, metadata.getDescription());
                stmt.setString(4, metadata.getScript());
                stmt.setString(5, metadata.getScriptHash());
                stmt.setBoolean(6, metadata.isEnabled());
                stmt.setBoolean(7, metadata.isImportSuccessful());
                stmt.setString(8, String.join(";", metadata.getImportErrors()));
                stmt.setString(9, metadata.getCreatedAt());
                stmt.executeUpdate();
            }
            
        } catch (Exception e) {
            logger.error("Failed to persist BCheck metadata for {}", metadata.getId(), e);
        }
    }
    
    private void deleteBCheckFromDatabase(String bcheckId) {
        try (Connection conn = databaseService.getConnection()) {
            String deleteBCheck = "DELETE FROM bchecks WHERE id = ?";
            try (PreparedStatement stmt = conn.prepareStatement(deleteBCheck)) {
                stmt.setString(1, bcheckId);
                stmt.executeUpdate();
            }
        } catch (Exception e) {
            logger.error("Failed to delete BCheck from database: {}", bcheckId, e);
        }
    }
    
    private String generateBCheckId(String script, String name) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            String input = script + name + System.currentTimeMillis();
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            
            return "bcheck_" + hexString.toString().substring(0, 16);
            
        } catch (Exception e) {
            logger.error("Failed to generate BCheck ID", e);
            return "bcheck_" + System.currentTimeMillis() + "_" + (int)(Math.random() * 1000);
        }
    }
    
    private String generateScriptHash(String script) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(script.getBytes(StandardCharsets.UTF_8));
            
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
            logger.error("Failed to generate script hash", e);
            return "unknown_hash";
        }
    }
    
    private List<String> parseImportErrors(String errorsString) {
        if (errorsString == null || errorsString.trim().isEmpty()) {
            return new ArrayList<>();
        }
        return Arrays.asList(errorsString.split(";"));
    }
    
    /**
     * BCheck metadata class.
     */
    private static class BCheckMetadata {
        private final String id;
        private final String name;
        private final String description;
        private final String script;
        private final boolean enabled;
        private final boolean importSuccessful;
        private final List<String> importErrors;
        private String createdAt;
        private String scriptHash;
        
        public BCheckMetadata(String id, String name, String description, String script, 
                             boolean enabled, boolean importSuccessful, List<String> importErrors) {
            this.id = id;
            this.name = name;
            this.description = description;
            this.script = script;
            this.enabled = enabled;
            this.importSuccessful = importSuccessful;
            this.importErrors = new ArrayList<>(importErrors);
            this.createdAt = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
            this.scriptHash = generateScriptHash(script);
        }
        
        private String generateScriptHash(String script) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hash = md.digest(script.getBytes(StandardCharsets.UTF_8));
                
                StringBuilder hexString = new StringBuilder();
                for (byte b : hash) {
                    String hex = Integer.toHexString(0xff & b);
                    if (hex.length() == 1) {
                        hexString.append('0');
                    }
                    hexString.append(hex);
                }
                
                return hexString.toString().substring(0, 16);
                
            } catch (Exception e) {
                return "unknown";
            }
        }
        
        // Getters
        public String getId() { return id; }
        public String getName() { return name; }
        public String getDescription() { return description; }
        public String getScript() { return script; }
        public boolean isEnabled() { return enabled; }
        public boolean isImportSuccessful() { return importSuccessful; }
        public List<String> getImportErrors() { return importErrors; }
        public String getCreatedAt() { return createdAt; }
        public String getScriptHash() { return scriptHash; }
        
        // Setters for loading from database
        public void setCreatedAt(String createdAt) { this.createdAt = createdAt; }
        public void setScriptHash(String scriptHash) { this.scriptHash = scriptHash; }
    }
}