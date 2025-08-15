package com.belch.services;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.*;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointType;
import com.belch.config.ApiConfig;
import com.belch.database.DatabaseService;
import com.belch.models.ScanRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Enhanced scanner service that provides advanced scanning capabilities
 * with support for complex configurations, optimization strategies, and monitoring.
 */
public class EnhancedScannerService {
    
    private static final Logger logger = LoggerFactory.getLogger(EnhancedScannerService.class);
    
    private final MontoyaApi api;
    private final DatabaseService databaseService;
    private final ApiConfig config;
    private final ScanTaskManager scanTaskManager;
    private final ScheduledExecutorService executorService;
    
    // Cache for scan configurations and results
    private final Map<String, ScanRequest> activeScanConfigs = new HashMap<>();
    private final Map<String, ScanStatistics> scanStatistics = new HashMap<>();
    
    /**
     * Constructor for EnhancedScannerService
     */
    public EnhancedScannerService(MontoyaApi api, DatabaseService databaseService, 
                                  ApiConfig config, ScanTaskManager scanTaskManager) {
        this.api = api;
        this.databaseService = databaseService;
        this.config = config;
        this.scanTaskManager = scanTaskManager;
        this.executorService = Executors.newScheduledThreadPool(4);
        
        logger.info("Enhanced Scanner Service initialized");
    }
    
    /**
     * Execute an enhanced scan based on the provided configuration
     */
    public CompletableFuture<ScanResult> executeEnhancedScan(ScanRequest scanRequest) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Validate scan request
                List<String> validationErrors = scanRequest.validate();
                if (!validationErrors.isEmpty()) {
                    throw new IllegalArgumentException("Scan validation failed: " + String.join(", ", validationErrors));
                }
                
                // Generate scan ID
                String scanId = generateScanId();
                activeScanConfigs.put(scanId, scanRequest);
                
                // Apply optimization strategies
                ScanRequest optimizedRequest = applyOptimizations(scanRequest);
                
                // Execute based on scan type
                switch (scanRequest.getScanType()) {
                    case AUDIT:
                        return executeAuditScan(scanId, optimizedRequest);
                    case CRAWL:
                        return executeCrawlScan(scanId, optimizedRequest);
                    case PASSIVE:
                        return executePassiveScan(scanId, optimizedRequest);
                    case COMBINED:
                        return executeCombinedScan(scanId, optimizedRequest);
                    default:
                        throw new IllegalArgumentException("Unsupported scan type: " + scanRequest.getScanType());
                }
                
            } catch (Exception e) {
                logger.error("Enhanced scan execution failed", e);
                throw new RuntimeException("Scan execution failed: " + e.getMessage(), e);
            }
        });
    }
    
    /**
     * Execute audit scan with advanced configuration
     */
    private ScanResult executeAuditScan(String scanId, ScanRequest scanRequest) {
        logger.info("Starting enhanced audit scan: {}", scanId);
        
        // Create audit configuration
        BuiltInAuditConfiguration builtInConfig = BuiltInAuditConfiguration.valueOf(
            scanRequest.getAuditConfig()
        );
        AuditConfiguration auditConfig = AuditConfiguration.auditConfiguration(builtInConfig);
        
        // Start audit
        Audit audit = api.scanner().startAudit(auditConfig);
        
        // Process URLs
        List<String> targetUrls = getTargetUrls(scanRequest);
        ScanStatistics stats = new ScanStatistics(scanId);
        stats.setTotalTargets(targetUrls.size());
        scanStatistics.put(scanId, stats);
        
        for (String url : targetUrls) {
            try {
                // Create HTTP request with custom configuration
                HttpRequest httpRequest = createHttpRequest(url, scanRequest);
                
                // Note: Custom insertion point filtering is not supported in this version
                // All insertion points are scanned using Burp's default behavior
                
                // Add request to audit
                audit.addRequest(httpRequest);
                
                // Store in database
                long scanRecordId = databaseService.storeRawTraffic(
                    "ENHANCED_AUDIT", url, extractHostFromUrl(url),
                    buildEnhancedHeaders(scanRequest),
                    scanRequest.getBody(), "", "", null, 
                    scanRequest.getSessionTag()
                );
                
                stats.incrementProcessedTargets();
                
                // Register with task manager
                if (scanTaskManager != null && scanTaskManager.isReady()) {
                    Map<String, Object> taskConfig = createTaskConfig(scanRequest, url, scanRecordId);
                    scanTaskManager.registerAudit(audit, taskConfig, scanRequest.getSessionTag());
                }
                
            } catch (Exception e) {
                logger.warn("Failed to process URL for audit scan: {}", url, e);
                stats.incrementFailedTargets();
            }
        }
        
        return new ScanResult(scanId, ScanResult.Status.STARTED, stats);
    }
    
    /**
     * Execute crawl scan with advanced configuration
     */
    private ScanResult executeCrawlScan(String scanId, ScanRequest scanRequest) {
        logger.info("Starting enhanced crawl scan: {}", scanId);
        
        try {
            // Create crawl configuration
            List<String> seedUrls = scanRequest.getCrawlConfiguration() != null ? 
                scanRequest.getCrawlConfiguration().getSeedUrls() : getTargetUrls(scanRequest);
            
            if (seedUrls.isEmpty()) {
                throw new IllegalArgumentException("No seed URLs provided for crawl");
            }
            
            CrawlConfiguration crawlConfig = CrawlConfiguration.crawlConfiguration(
                seedUrls.toArray(new String[0])
            );
            
            // Start crawl
            Crawl crawl = api.scanner().startCrawl(crawlConfig);
            
            ScanStatistics stats = new ScanStatistics(scanId);
            stats.setTotalTargets(seedUrls.size());
            scanStatistics.put(scanId, stats);
            
            // Register with task manager
            if (scanTaskManager != null && scanTaskManager.isReady()) {
                Map<String, Object> taskConfig = createCrawlTaskConfig(scanRequest, seedUrls);
                scanTaskManager.registerCrawl(crawl, taskConfig, scanRequest.getSessionTag());
            }
            
            return new ScanResult(scanId, ScanResult.Status.STARTED, stats);
            
        } catch (Exception e) {
            logger.error("Failed to start enhanced crawl scan", e);
            throw new RuntimeException("Crawl scan failed: " + e.getMessage(), e);
        }
    }
    
    /**
     * Execute passive scan (analysis only)
     */
    private ScanResult executePassiveScan(String scanId, ScanRequest scanRequest) {
        logger.info("Starting enhanced passive scan: {}", scanId);
        
        // For passive scanning, we analyze without active probing
        // This would typically involve registering passive scan checks
        ScanStatistics stats = new ScanStatistics(scanId);
        List<String> targetUrls = getTargetUrls(scanRequest);
        stats.setTotalTargets(targetUrls.size());
        
        // Process each URL for passive analysis
        for (String url : targetUrls) {
            try {
                // Store in database for passive analysis
                long scanRecordId = databaseService.storeRawTraffic(
                    "ENHANCED_PASSIVE", url, extractHostFromUrl(url),
                    buildEnhancedHeaders(scanRequest),
                    scanRequest.getBody(), "", "", null, 
                    scanRequest.getSessionTag()
                );
                
                stats.incrementProcessedTargets();
                
            } catch (Exception e) {
                logger.warn("Failed to process URL for passive scan: {}", url, e);
                stats.incrementFailedTargets();
            }
        }
        
        scanStatistics.put(scanId, stats);
        return new ScanResult(scanId, ScanResult.Status.COMPLETED, stats);
    }
    
    /**
     * Execute combined crawl and audit scan
     */
    private ScanResult executeCombinedScan(String scanId, ScanRequest scanRequest) {
        logger.info("Starting enhanced combined scan: {}", scanId);
        
        // First perform crawl, then audit the discovered content
        ScanResult crawlResult = executeCrawlScan(scanId + "_crawl", scanRequest);
        
        // Wait a bit for crawl to discover content, then start audit
        executorService.schedule(() -> {
            try {
                ScanRequest auditRequest = scanRequest.createBackwardCompatibleCopy();
                auditRequest.setScanType(ScanRequest.ScanType.AUDIT);
                executeAuditScan(scanId + "_audit", auditRequest);
            } catch (Exception e) {
                logger.error("Failed to start audit phase of combined scan", e);
            }
        }, 30, TimeUnit.SECONDS);
        
        return crawlResult;
    }
    
    /**
     * Apply optimization strategies to scan request
     */
    private ScanRequest applyOptimizations(ScanRequest scanRequest) {
        if (scanRequest.getScanOptimization() == null) {
            return scanRequest;
        }
        
        ScanRequest.ScanOptimization optimization = scanRequest.getScanOptimization();
        
        // Apply optimization strategy
        switch (optimization.getStrategy()) {
            case FAST:
                return applyFastOptimizations(scanRequest);
            case THOROUGH:
                return applyThoroughOptimizations(scanRequest);
            case BALANCED:
            default:
                return applyBalancedOptimizations(scanRequest);
        }
    }
    
    /**
     * Apply fast optimization strategy
     */
    private ScanRequest applyFastOptimizations(ScanRequest scanRequest) {
        // Note: Insertion point configuration is not supported
        // Burp's default insertion points are used for all scans
        
        // Set shorter timeout
        if (scanRequest.getTimeoutSeconds() == null) {
            scanRequest.setTimeoutSeconds(300); // 5 minutes
        }
        
        return scanRequest;
    }
    
    /**
     * Apply thorough optimization strategy
     */
    private ScanRequest applyThoroughOptimizations(ScanRequest scanRequest) {
        // Note: Insertion point configuration is not supported
        // Burp's default insertion points are used for all scans
        
        // Set longer timeout
        if (scanRequest.getTimeoutSeconds() == null) {
            scanRequest.setTimeoutSeconds(3600); // 1 hour
        }
        
        return scanRequest;
    }
    
    /**
     * Apply balanced optimization strategy
     */
    private ScanRequest applyBalancedOptimizations(ScanRequest scanRequest) {
        // Default balanced configuration
        if (scanRequest.getTimeoutSeconds() == null) {
            scanRequest.setTimeoutSeconds(1800); // 30 minutes
        }
        
        return scanRequest;
    }
    
    
    /**
     * Create HTTP request with custom configuration
     */
    private HttpRequest createHttpRequest(String url, ScanRequest scanRequest) {
        // Create basic HTTP request (following existing pattern)
        HttpRequest httpRequest = HttpRequest.httpRequestFromUrl(url)
            .withMethod(scanRequest.getMethod());
        
        // Add body if present
        if (scanRequest.getBody() != null && !scanRequest.getBody().isEmpty()) {
            httpRequest = httpRequest.withBody(scanRequest.getBody());
        }
        
        // Note: Custom headers and authentication would need to be implemented
        // using the available Montoya API methods. The current API may have
        // limitations on runtime header modification.
        
        return httpRequest;
    }
    
    
    /**
     * Get scan statistics for a scan ID
     */
    public ScanStatistics getScanStatistics(String scanId) {
        return scanStatistics.get(scanId);
    }
    
    /**
     * Get active scan configurations
     */
    public Map<String, ScanRequest> getActiveScanConfigs() {
        return new HashMap<>(activeScanConfigs);
    }
    
    /**
     * Cancel a scan
     */
    public boolean cancelScan(String scanId) {
        activeScanConfigs.remove(scanId);
        scanStatistics.remove(scanId);
        
        // Cancel through task manager if available
        if (scanTaskManager != null && scanTaskManager.isReady()) {
            try {
                return scanTaskManager.cancelTask(scanId);
            } catch (Exception e) {
                logger.warn("Failed to cancel scan through task manager", e);
            }
        }
        
        return true;
    }
    
    // Helper methods
    
    private String generateScanId() {
        return "enhanced_scan_" + System.currentTimeMillis() + "_" + 
               Integer.toHexString(new Random().nextInt());
    }
    
    private List<String> getTargetUrls(ScanRequest scanRequest) {
        List<String> urls = new ArrayList<>();
        
        if (scanRequest.getUrl() != null) {
            urls.add(scanRequest.getUrl());
        }
        
        if (scanRequest.getUrls() != null) {
            urls.addAll(scanRequest.getUrls());
        }
        
        return urls;
    }
    
    private String extractHostFromUrl(String url) {
        try {
            return new java.net.URL(url).getHost();
        } catch (Exception e) {
            return "unknown";
        }
    }
    
    private String buildEnhancedHeaders(ScanRequest scanRequest) {
        StringBuilder headers = new StringBuilder();
        
        if (scanRequest.getHeaders() != null && !scanRequest.getHeaders().isEmpty()) {
            headers.append(scanRequest.getHeaders()).append("\n");
        }
        
        headers.append("Scan-Type: ").append(scanRequest.getScanType()).append("\n");
        headers.append("Audit-Config: ").append(scanRequest.getAuditConfig()).append("\n");
        
        if (scanRequest.getScanOptimization() != null) {
            headers.append("Optimization-Strategy: ")
                   .append(scanRequest.getScanOptimization().getStrategy()).append("\n");
        }
        
        return headers.toString();
    }
    
    private Map<String, Object> createTaskConfig(ScanRequest scanRequest, String url, long scanRecordId) {
        Map<String, Object> taskConfig = new HashMap<>();
        taskConfig.put("scan_type", "enhanced_audit");
        taskConfig.put("target_url", url);
        taskConfig.put("method", scanRequest.getMethod());
        taskConfig.put("audit_config", scanRequest.getAuditConfig());
        taskConfig.put("scan_record_id", scanRecordId);
        taskConfig.put("optimization_strategy", 
            scanRequest.getScanOptimization() != null ? 
                scanRequest.getScanOptimization().getStrategy().toString() : "BALANCED");
        return taskConfig;
    }
    
    private Map<String, Object> createCrawlTaskConfig(ScanRequest scanRequest, List<String> seedUrls) {
        Map<String, Object> taskConfig = new HashMap<>();
        taskConfig.put("scan_type", "enhanced_crawl");
        taskConfig.put("seed_urls", seedUrls);
        taskConfig.put("crawl_strategy", 
            scanRequest.getCrawlConfiguration() != null ? 
                scanRequest.getCrawlConfiguration().getCrawlStrategy().toString() : "MOST_COMPLETE");
        return taskConfig;
    }
    
    /**
     * Shutdown the service
     */
    public void shutdown() {
        try {
            executorService.shutdown();
            if (!executorService.awaitTermination(30, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }
        
        logger.info("Enhanced Scanner Service shutdown completed");
    }
    
    /**
     * Scan result class
     */
    public static class ScanResult {
        private final String scanId;
        private final Status status;
        private final ScanStatistics statistics;
        
        public ScanResult(String scanId, Status status, ScanStatistics statistics) {
            this.scanId = scanId;
            this.status = status;
            this.statistics = statistics;
        }
        
        public enum Status {
            STARTED, RUNNING, COMPLETED, FAILED, CANCELLED
        }
        
        public String getScanId() { return scanId; }
        public Status getStatus() { return status; }
        public ScanStatistics getStatistics() { return statistics; }
    }
    
    /**
     * Scan statistics tracking
     */
    public static class ScanStatistics {
        private final String scanId;
        private final long startTime;
        private int totalTargets;
        private int processedTargets;
        private int failedTargets;
        
        public ScanStatistics(String scanId) {
            this.scanId = scanId;
            this.startTime = System.currentTimeMillis();
        }
        
        public String getScanId() { return scanId; }
        public long getStartTime() { return startTime; }
        public int getTotalTargets() { return totalTargets; }
        public int getProcessedTargets() { return processedTargets; }
        public int getFailedTargets() { return failedTargets; }
        
        public void setTotalTargets(int totalTargets) { this.totalTargets = totalTargets; }
        public void incrementProcessedTargets() { this.processedTargets++; }
        public void incrementFailedTargets() { this.failedTargets++; }
        
        public double getProgressPercentage() {
            return totalTargets > 0 ? (double) processedTargets / totalTargets * 100 : 0;
        }
    }
}