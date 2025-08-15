package com.belch.models;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

/**
 * Enhanced scan request model that supports advanced scanning configurations.
 * Provides comprehensive options for audit and crawl operations.
 */
public class ScanRequest {
    
    // Basic request information
    @JsonProperty("method")
    private String method = "GET";
    
    @JsonProperty("url")
    private String url;
    
    @JsonProperty("urls")
    private List<String> urls;
    
    @JsonProperty("headers")
    private String headers = "";
    
    @JsonProperty("body")
    private String body = "";
    
    @JsonProperty("session_tag")
    private String sessionTag;
    
    // Audit configuration
    @JsonProperty("audit_config")
    private String auditConfig = "LEGACY_ACTIVE_AUDIT_CHECKS";
    
    @JsonProperty("scan_type")
    private ScanType scanType = ScanType.AUDIT;
    
    // Advanced audit configuration
    // Note: Custom insertion point filtering is not supported in this version
    
    @JsonProperty("scan_optimization")
    private ScanOptimization scanOptimization;
    
    @JsonProperty("crawl_configuration")
    private CrawlConfig crawlConfiguration;
    
    @JsonProperty("timeout_seconds")
    private Integer timeoutSeconds;
    
    @JsonProperty("max_depth")
    private Integer maxDepth;
    
    @JsonProperty("follow_redirects")
    private Boolean followRedirects = true;
    
    @JsonProperty("custom_headers")
    private Map<String, String> customHeaders;
    
    @JsonProperty("authentication")
    private AuthenticationConfig authentication;
    
    @JsonProperty("scope_restrictions")
    private ScopeConfig scopeRestrictions;
    
    /**
     * Enum for different types of scans
     */
    public enum ScanType {
        AUDIT,          // Active scanning for vulnerabilities
        CRAWL,          // Content discovery
        PASSIVE,        // Passive analysis only
        COMBINED        // Both crawl and audit
    }
    
    /**
     * Scan optimization strategies
     */
    public static class ScanOptimization {
        @JsonProperty("strategy")
        private OptimizationStrategy strategy = OptimizationStrategy.BALANCED;
        
        @JsonProperty("max_concurrent_requests")
        private Integer maxConcurrentRequests;
        
        @JsonProperty("delay_between_requests")
        private Integer delayBetweenRequests;
        
        @JsonProperty("smart_duplicate_detection")
        private Boolean smartDuplicateDetection = true;
        
        // Note: Priority insertion point configuration is not supported
        
        public enum OptimizationStrategy {
            FAST,           // Minimal checks, fast scanning
            BALANCED,       // Standard balance of speed and coverage
            THOROUGH,       // Comprehensive but slower scanning
            CUSTOM          // User-defined parameters
        }
        
        // Getters and setters
        public OptimizationStrategy getStrategy() { return strategy; }
        public void setStrategy(OptimizationStrategy strategy) { this.strategy = strategy; }
        
        public Integer getMaxConcurrentRequests() { return maxConcurrentRequests; }
        public void setMaxConcurrentRequests(Integer maxConcurrentRequests) { this.maxConcurrentRequests = maxConcurrentRequests; }
        
        public Integer getDelayBetweenRequests() { return delayBetweenRequests; }
        public void setDelayBetweenRequests(Integer delayBetweenRequests) { this.delayBetweenRequests = delayBetweenRequests; }
        
        public Boolean getSmartDuplicateDetection() { return smartDuplicateDetection; }
        public void setSmartDuplicateDetection(Boolean smartDuplicateDetection) { this.smartDuplicateDetection = smartDuplicateDetection; }
        
    }
    
    /**
     * Crawl-specific configuration
     */
    public static class CrawlConfig {
        @JsonProperty("max_link_depth")
        private Integer maxLinkDepth = 3;
        
        @JsonProperty("seed_urls")
        private List<String> seedUrls;
        
        @JsonProperty("crawl_strategy")
        private CrawlStrategy crawlStrategy = CrawlStrategy.MOST_COMPLETE;
        
        @JsonProperty("forms_handling")
        private FormsHandling formsHandling = FormsHandling.SUBMIT_FORMS;
        
        @JsonProperty("javascript_analysis")
        private Boolean javascriptAnalysis = true;
        
        @JsonProperty("max_crawl_requests")
        private Integer maxCrawlRequests;
        
        public enum CrawlStrategy {
            FASTEST,        // Quick discovery
            MOST_COMPLETE,  // Thorough crawling
            CUSTOM          // User-defined
        }
        
        public enum FormsHandling {
            IGNORE_FORMS,
            SUBMIT_FORMS,
            PROMPT_FOR_FORMS
        }
        
        // Getters and setters
        public Integer getMaxLinkDepth() { return maxLinkDepth; }
        public void setMaxLinkDepth(Integer maxLinkDepth) { this.maxLinkDepth = maxLinkDepth; }
        
        public List<String> getSeedUrls() { return seedUrls; }
        public void setSeedUrls(List<String> seedUrls) { this.seedUrls = seedUrls; }
        
        public CrawlStrategy getCrawlStrategy() { return crawlStrategy; }
        public void setCrawlStrategy(CrawlStrategy crawlStrategy) { this.crawlStrategy = crawlStrategy; }
        
        public FormsHandling getFormsHandling() { return formsHandling; }
        public void setFormsHandling(FormsHandling formsHandling) { this.formsHandling = formsHandling; }
        
        public Boolean getJavascriptAnalysis() { return javascriptAnalysis; }
        public void setJavascriptAnalysis(Boolean javascriptAnalysis) { this.javascriptAnalysis = javascriptAnalysis; }
        
        public Integer getMaxCrawlRequests() { return maxCrawlRequests; }
        public void setMaxCrawlRequests(Integer maxCrawlRequests) { this.maxCrawlRequests = maxCrawlRequests; }
    }
    
    /**
     * Authentication configuration for scanning
     */
    public static class AuthenticationConfig {
        @JsonProperty("auth_type")
        private AuthType authType;
        
        @JsonProperty("username")
        private String username;
        
        @JsonProperty("password")
        private String password;
        
        @JsonProperty("bearer_token")
        private String bearerToken;
        
        @JsonProperty("session_cookies")
        private Map<String, String> sessionCookies;
        
        @JsonProperty("custom_auth_headers")
        private Map<String, String> customAuthHeaders;
        
        public enum AuthType {
            NONE,
            BASIC,
            BEARER_TOKEN,
            SESSION_COOKIES,
            CUSTOM_HEADERS
        }
        
        // Getters and setters
        public AuthType getAuthType() { return authType; }
        public void setAuthType(AuthType authType) { this.authType = authType; }
        
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
        
        public String getBearerToken() { return bearerToken; }
        public void setBearerToken(String bearerToken) { this.bearerToken = bearerToken; }
        
        public Map<String, String> getSessionCookies() { return sessionCookies; }
        public void setSessionCookies(Map<String, String> sessionCookies) { this.sessionCookies = sessionCookies; }
        
        public Map<String, String> getCustomAuthHeaders() { return customAuthHeaders; }
        public void setCustomAuthHeaders(Map<String, String> customAuthHeaders) { this.customAuthHeaders = customAuthHeaders; }
    }
    
    /**
     * Scope configuration for limiting scan coverage
     */
    public static class ScopeConfig {
        @JsonProperty("include_patterns")
        private List<String> includePatterns;
        
        @JsonProperty("exclude_patterns")
        private List<String> excludePatterns;
        
        @JsonProperty("include_file_extensions")
        private List<String> includeFileExtensions;
        
        @JsonProperty("exclude_file_extensions")
        private List<String> excludeFileExtensions;
        
        @JsonProperty("max_response_size")
        private Long maxResponseSize;
        
        @JsonProperty("include_status_codes")
        private List<Integer> includeStatusCodes;
        
        @JsonProperty("exclude_status_codes")
        private List<Integer> excludeStatusCodes;
        
        // Getters and setters
        public List<String> getIncludePatterns() { return includePatterns; }
        public void setIncludePatterns(List<String> includePatterns) { this.includePatterns = includePatterns; }
        
        public List<String> getExcludePatterns() { return excludePatterns; }
        public void setExcludePatterns(List<String> excludePatterns) { this.excludePatterns = excludePatterns; }
        
        public List<String> getIncludeFileExtensions() { return includeFileExtensions; }
        public void setIncludeFileExtensions(List<String> includeFileExtensions) { this.includeFileExtensions = includeFileExtensions; }
        
        public List<String> getExcludeFileExtensions() { return excludeFileExtensions; }
        public void setExcludeFileExtensions(List<String> excludeFileExtensions) { this.excludeFileExtensions = excludeFileExtensions; }
        
        public Long getMaxResponseSize() { return maxResponseSize; }
        public void setMaxResponseSize(Long maxResponseSize) { this.maxResponseSize = maxResponseSize; }
        
        public List<Integer> getIncludeStatusCodes() { return includeStatusCodes; }
        public void setIncludeStatusCodes(List<Integer> includeStatusCodes) { this.includeStatusCodes = includeStatusCodes; }
        
        public List<Integer> getExcludeStatusCodes() { return excludeStatusCodes; }
        public void setExcludeStatusCodes(List<Integer> excludeStatusCodes) { this.excludeStatusCodes = excludeStatusCodes; }
    }
    
    // Main getters and setters
    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }
    
    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }
    
    public List<String> getUrls() { return urls; }
    public void setUrls(List<String> urls) { this.urls = urls; }
    
    public String getHeaders() { return headers; }
    public void setHeaders(String headers) { this.headers = headers; }
    
    public String getBody() { return body; }
    public void setBody(String body) { this.body = body; }
    
    public String getSessionTag() { return sessionTag; }
    public void setSessionTag(String sessionTag) { this.sessionTag = sessionTag; }
    
    public String getAuditConfig() { return auditConfig; }
    public void setAuditConfig(String auditConfig) { this.auditConfig = auditConfig; }
    
    public ScanType getScanType() { return scanType; }
    public void setScanType(ScanType scanType) { this.scanType = scanType; }
    
    
    public ScanOptimization getScanOptimization() { return scanOptimization; }
    public void setScanOptimization(ScanOptimization scanOptimization) { this.scanOptimization = scanOptimization; }
    
    public CrawlConfig getCrawlConfiguration() { return crawlConfiguration; }
    public void setCrawlConfiguration(CrawlConfig crawlConfiguration) { this.crawlConfiguration = crawlConfiguration; }
    
    public Integer getTimeoutSeconds() { return timeoutSeconds; }
    public void setTimeoutSeconds(Integer timeoutSeconds) { this.timeoutSeconds = timeoutSeconds; }
    
    public Integer getMaxDepth() { return maxDepth; }
    public void setMaxDepth(Integer maxDepth) { this.maxDepth = maxDepth; }
    
    public Boolean getFollowRedirects() { return followRedirects; }
    public void setFollowRedirects(Boolean followRedirects) { this.followRedirects = followRedirects; }
    
    public Map<String, String> getCustomHeaders() { return customHeaders; }
    public void setCustomHeaders(Map<String, String> customHeaders) { this.customHeaders = customHeaders; }
    
    public AuthenticationConfig getAuthentication() { return authentication; }
    public void setAuthentication(AuthenticationConfig authentication) { this.authentication = authentication; }
    
    public ScopeConfig getScopeRestrictions() { return scopeRestrictions; }
    public void setScopeRestrictions(ScopeConfig scopeRestrictions) { this.scopeRestrictions = scopeRestrictions; }
    
    /**
     * Validates the scan request and returns a list of validation errors
     */
    public java.util.List<String> validate() {
        java.util.List<String> errors = new java.util.ArrayList<>();
        
        // Basic validation
        if (url == null && (urls == null || urls.isEmpty())) {
            errors.add("Either 'url' or 'urls' must be provided");
        }
        
        if (method == null || method.trim().isEmpty()) {
            errors.add("HTTP method is required");
        }
        
        // Validate audit configuration
        if (auditConfig != null) {
            try {
                burp.api.montoya.scanner.BuiltInAuditConfiguration.valueOf(auditConfig);
            } catch (IllegalArgumentException e) {
                errors.add("Invalid audit configuration: " + auditConfig);
            }
        }
        
        // Validate timeout
        if (timeoutSeconds != null && timeoutSeconds <= 0) {
            errors.add("Timeout must be positive");
        }
        
        // Validate max depth
        if (maxDepth != null && maxDepth < 0) {
            errors.add("Max depth cannot be negative");
        }
        
        return errors;
    }
    
    /**
     * Creates a copy of this scan request with backward compatibility
     */
    public ScanRequest createBackwardCompatibleCopy() {
        ScanRequest copy = new ScanRequest();
        copy.setMethod(this.method);
        copy.setUrl(this.url);
        copy.setUrls(this.urls);
        copy.setHeaders(this.headers);
        copy.setBody(this.body);
        copy.setSessionTag(this.sessionTag);
        copy.setAuditConfig(this.auditConfig);
        // Only copy basic fields for backward compatibility
        return copy;
    }
}