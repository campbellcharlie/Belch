package com.belch.services;

import io.javalin.Javalin;
import io.javalin.http.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Phase 3 Task 13: API Versioning Strategy
 * 
 * Provides API versioning support with:
 * - URL-based versioning (/v1/, /v2/)
 * - Header-based versioning (API-Version: v1)
 * - Query parameter versioning (?version=v1)
 * - Version deprecation warnings
 * - Backward compatibility handling
 */
public class ApiVersioningService {
    
    private static final Logger logger = LoggerFactory.getLogger(ApiVersioningService.class);
    
    private static final String CURRENT_VERSION = "v2";
    private static final String LEGACY_VERSION = "v1";
    private static final List<String> SUPPORTED_VERSIONS = List.of("v1", "v2");
    
    private final Map<String, VersionInfo> versionInfo;
    private final Map<String, Long> versionUsageStats;
    private final Pattern versionPattern = Pattern.compile("^/v(\\d+)(?:\\.\\d+)?/(.*)");
    
    public ApiVersioningService() {
        this.versionInfo = new ConcurrentHashMap<>();
        this.versionUsageStats = new ConcurrentHashMap<>();
        
        initializeVersionInfo();
        initializeUsageStats();
        
        logger.info("[*] API Versioning Service initialized - Current: {}, Supported: {}", 
                   CURRENT_VERSION, SUPPORTED_VERSIONS);
    }
    
    /**
     * Extract version from request context.
     */
    public String extractVersion(Context ctx) {
        // 1. URL path versioning (highest priority)
        String path = ctx.path();
        Matcher matcher = versionPattern.matcher(path);
        if (matcher.matches()) {
            String version = "v" + matcher.group(1);
            if (SUPPORTED_VERSIONS.contains(version)) {
                recordVersionUsage(version);
                return version;
            }
        }
        
        // 2. Header-based versioning
        String headerVersion = ctx.header("API-Version");
        if (headerVersion != null && SUPPORTED_VERSIONS.contains(headerVersion)) {
            recordVersionUsage(headerVersion);
            return headerVersion;
        }
        
        // 3. Query parameter versioning
        String queryVersion = ctx.queryParam("version");
        if (queryVersion != null && SUPPORTED_VERSIONS.contains(queryVersion)) {
            recordVersionUsage(queryVersion);
            return queryVersion;
        }
        
        // 4. Accept header versioning (application/vnd.belch.v1+json)
        String acceptHeader = ctx.header("Accept");
        if (acceptHeader != null) {
            Pattern acceptPattern = Pattern.compile("application/vnd\\.belch\\.(v\\d+)\\+json");
            Matcher acceptMatcher = acceptPattern.matcher(acceptHeader);
            if (acceptMatcher.find()) {
                String version = acceptMatcher.group(1);
                if (SUPPORTED_VERSIONS.contains(version)) {
                    recordVersionUsage(version);
                    return version;
                }
            }
        }
        
        // Default to current version
        recordVersionUsage(CURRENT_VERSION);
        return CURRENT_VERSION;
    }
    
    /**
     * Get unversioned path from versioned URL.
     */
    public String getUnversionedPath(String path) {
        Matcher matcher = versionPattern.matcher(path);
        if (matcher.matches()) {
            return "/" + matcher.group(2);
        }
        return path;
    }
    
    /**
     * Add version-specific headers to response.
     */
    public void addVersionHeaders(Context ctx, String version) {
        ctx.header("API-Version", version);
        ctx.header("API-Current-Version", CURRENT_VERSION);
        ctx.header("API-Supported-Versions", String.join(",", SUPPORTED_VERSIONS));
        
        // Add deprecation warning for legacy versions
        if (LEGACY_VERSION.equals(version)) {
            ctx.header("API-Deprecation-Warning", 
                "Version " + version + " is deprecated. Please migrate to " + CURRENT_VERSION);
            ctx.header("Sunset", "2025-12-31"); // RFC 8594 sunset header
        }
    }
    
    /**
     * Check if version is supported.
     */
    public boolean isVersionSupported(String version) {
        return SUPPORTED_VERSIONS.contains(version);
    }
    
    /**
     * Get version compatibility info.
     */
    public Map<String, Object> getVersionCompatibility(String requestedVersion, String endpoint) {
        Map<String, Object> compatibility = new HashMap<>();
        
        VersionInfo vInfo = versionInfo.get(requestedVersion);
        if (vInfo == null) {
            compatibility.put("supported", false);
            compatibility.put("error", "Version not supported");
            compatibility.put("supported_versions", SUPPORTED_VERSIONS);
            return compatibility;
        }
        
        compatibility.put("supported", true);
        compatibility.put("version", requestedVersion);
        compatibility.put("is_current", CURRENT_VERSION.equals(requestedVersion));
        compatibility.put("is_deprecated", vInfo.isDeprecated());
        compatibility.put("deprecation_date", vInfo.getDeprecationDate());
        compatibility.put("sunset_date", vInfo.getSunsetDate());
        
        // Check endpoint-specific compatibility
        if (vInfo.hasEndpointChanges(endpoint)) {
            compatibility.put("endpoint_changes", vInfo.getEndpointChanges(endpoint));
        }
        
        if (vInfo.isDeprecated()) {
            compatibility.put("migration_guide", vInfo.getMigrationGuide());
            compatibility.put("recommended_version", CURRENT_VERSION);
        }
        
        return compatibility;
    }
    
    /**
     * Get API version information.
     */
    public Map<String, Object> getVersionInfo() {
        Map<String, Object> info = new HashMap<>();
        info.put("current_version", CURRENT_VERSION);
        info.put("supported_versions", SUPPORTED_VERSIONS);
        
        Map<String, Object> versions = new HashMap<>();
        for (Map.Entry<String, VersionInfo> entry : versionInfo.entrySet()) {
            versions.put(entry.getKey(), entry.getValue().toMap());
        }
        info.put("version_details", versions);
        
        return info;
    }
    
    /**
     * Get version usage statistics.
     */
    public Map<String, Object> getVersionStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("usage_by_version", new HashMap<>(versionUsageStats));
        
        long totalUsage = versionUsageStats.values().stream().mapToLong(Long::longValue).sum();
        stats.put("total_requests", totalUsage);
        
        Map<String, Double> percentages = new HashMap<>();
        for (Map.Entry<String, Long> entry : versionUsageStats.entrySet()) {
            double percentage = totalUsage > 0 ? (entry.getValue() * 100.0) / totalUsage : 0.0;
            percentages.put(entry.getKey(), Math.round(percentage * 100.0) / 100.0);
        }
        stats.put("usage_percentages", percentages);
        
        return stats;
    }
    
    /**
     * Transform response for version compatibility.
     */
    public Object transformResponse(Object response, String version, String endpoint) {
        if (CURRENT_VERSION.equals(version)) {
            return response; // No transformation needed for current version
        }
        
        VersionInfo vInfo = versionInfo.get(version);
        if (vInfo != null && vInfo.hasResponseTransformer(endpoint)) {
            return vInfo.transformResponse(endpoint, response);
        }
        
        return response;
    }
    
    /**
     * Register versioned routes in Javalin.
     */
    public void registerVersionedRoutes(Javalin app) {
        // Version info endpoint
        app.get("/api/version", ctx -> {
            String version = extractVersion(ctx);
            addVersionHeaders(ctx, version);
            
            Map<String, Object> versionResponse = getVersionInfo();
            versionResponse.put("requested_version", version);
            versionResponse.put("compatibility", getVersionCompatibility(version, "/api/version"));
            
            ctx.json(versionResponse);
        });
        
        // Version compatibility check endpoint
        app.get("/api/version/compatibility", ctx -> {
            String version = ctx.queryParam("version");
            String endpoint = ctx.queryParam("endpoint");
            
            if (version == null) {
                ctx.status(400).json(Map.of(
                    "error", "Missing version parameter",
                    "supported_versions", SUPPORTED_VERSIONS
                ));
                return;
            }
            
            Map<String, Object> compatibility = getVersionCompatibility(version, endpoint);
            ctx.json(compatibility);
        });
        
        // Version usage statistics
        app.get("/api/version/stats", ctx -> {
            String version = extractVersion(ctx);
            addVersionHeaders(ctx, version);
            ctx.json(getVersionStats());
        });
        
        // Version migration guide
        app.get("/api/version/migration/{fromVersion}/{toVersion}", ctx -> {
            String fromVersion = ctx.pathParam("fromVersion");
            String toVersion = ctx.pathParam("toVersion");
            
            Map<String, Object> migrationGuide = generateMigrationGuide(fromVersion, toVersion);
            ctx.json(migrationGuide);
        });
        
        logger.info("Version management routes registered");
    }
    
    private void initializeVersionInfo() {
        // V1 - Legacy version (deprecated)
        VersionInfo v1 = new VersionInfo("v1", "Legacy API version", true, 
                                        "2024-06-01", "2025-12-31");
        v1.addEndpointChange("/proxy/search", "Response format changed: 'results' array structure updated");
        v1.addEndpointChange("/scanner/audit", "New required parameter: 'audit_config'");
        v1.setMigrationGuide("Migrate to v2 for improved response formats and new features");
        
        // V2 - Current version
        VersionInfo v2 = new VersionInfo("v2", "Current API version with enhanced features", false, 
                                        null, null);
        v2.addFeature("Enhanced proxy traffic filtering with regex support");
        v2.addFeature("Webhook notifications for real-time events");
        v2.addFeature("Interactive documentation with code examples");
        v2.addFeature("Bulk operations for traffic management");
        
        versionInfo.put("v1", v1);
        versionInfo.put("v2", v2);
    }
    
    private void initializeUsageStats() {
        for (String version : SUPPORTED_VERSIONS) {
            versionUsageStats.put(version, 0L);
        }
    }
    
    private void recordVersionUsage(String version) {
        versionUsageStats.computeIfPresent(version, (k, v) -> v + 1);
    }
    
    private Map<String, Object> generateMigrationGuide(String fromVersion, String toVersion) {
        Map<String, Object> guide = new HashMap<>();
        guide.put("from_version", fromVersion);
        guide.put("to_version", toVersion);
        
        if ("v1".equals(fromVersion) && "v2".equals(toVersion)) {
            List<Map<String, Object>> changes = new ArrayList<>();
            
            changes.add(Map.of(
                "endpoint", "/proxy/search",
                "change_type", "response_format",
                "description", "Response now includes pagination and enhanced metadata",
                "breaking_change", false,
                "action_required", "Update client code to handle new response structure"
            ));
            
            changes.add(Map.of(
                "endpoint", "/proxy/bulk/*",
                "change_type", "new_endpoints",
                "description", "New bulk operations for tagging and commenting",
                "breaking_change", false,
                "action_required", "Optional - migrate individual operations to bulk for better performance"
            ));
            
            changes.add(Map.of(
                "endpoint", "/webhooks",
                "change_type", "new_feature",
                "description", "Webhook support for real-time notifications",
                "breaking_change", false,
                "action_required", "Optional - register webhooks for event notifications"
            ));
            
            guide.put("changes", changes);
            guide.put("migration_steps", List.of(
                "Update API base URL to include /v2/ prefix",
                "Update response parsing for modified endpoints",
                "Test with new response formats",
                "Consider using new bulk operations for improved performance",
                "Register webhooks if real-time notifications are needed"
            ));
            
            guide.put("compatibility_notes", 
                "V1 endpoints remain accessible but are deprecated. " +
                "Plan migration before sunset date: 2025-12-31");
        } else {
            guide.put("error", "Migration guide not available for specified versions");
        }
        
        return guide;
    }
    
    /**
     * Version information class.
     */
    private static class VersionInfo {
        private final String version;
        private final String description;
        private final boolean deprecated;
        private final String deprecationDate;
        private final String sunsetDate;
        private final Map<String, String> endpointChanges;
        private final List<String> features;
        private String migrationGuide;
        
        public VersionInfo(String version, String description, boolean deprecated, 
                          String deprecationDate, String sunsetDate) {
            this.version = version;
            this.description = description;
            this.deprecated = deprecated;
            this.deprecationDate = deprecationDate;
            this.sunsetDate = sunsetDate;
            this.endpointChanges = new HashMap<>();
            this.features = new ArrayList<>();
        }
        
        public void addEndpointChange(String endpoint, String change) {
            endpointChanges.put(endpoint, change);
        }
        
        public void addFeature(String feature) {
            features.add(feature);
        }
        
        public void setMigrationGuide(String guide) {
            this.migrationGuide = guide;
        }
        
        public boolean hasEndpointChanges(String endpoint) {
            return endpointChanges.containsKey(endpoint);
        }
        
        public String getEndpointChanges(String endpoint) {
            return endpointChanges.get(endpoint);
        }
        
        public boolean hasResponseTransformer(String endpoint) {
            return false; // Simplified - could implement actual transformers
        }
        
        public Object transformResponse(String endpoint, Object response) {
            return response; // Simplified - could implement actual transformations
        }
        
        public Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("version", version);
            map.put("description", description);
            map.put("deprecated", deprecated);
            map.put("deprecation_date", deprecationDate);
            map.put("sunset_date", sunsetDate);
            map.put("features", features);
            if (migrationGuide != null) {
                map.put("migration_guide", migrationGuide);
            }
            return map;
        }
        
        // Getters
        public boolean isDeprecated() { return deprecated; }
        public String getDeprecationDate() { return deprecationDate; }
        public String getSunsetDate() { return sunsetDate; }
        public String getMigrationGuide() { return migrationGuide; }
    }
}