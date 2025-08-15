package com.belch.services;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.ReportFormat;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.belch.config.ApiConfig;
import com.belch.database.DatabaseService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Service for generating various types of scan reports with support for
 * templates, storage, and multiple output formats.
 */
public class ReportGenerationService {
    
    private static final Logger logger = LoggerFactory.getLogger(ReportGenerationService.class);
    
    private final MontoyaApi api;
    private final DatabaseService databaseService;
    private final ApiConfig config;
    private final ObjectMapper objectMapper;
    
    // Report storage
    private final String reportsDirectory;
    
    // Template cache
    private final Map<String, String> templateCache = new HashMap<>();
    
    /**
     * Constructor for ReportGenerationService
     */
    public ReportGenerationService(MontoyaApi api, DatabaseService databaseService, ApiConfig config) {
        this.api = api;
        this.databaseService = databaseService;
        this.config = config;
        this.objectMapper = new ObjectMapper();
        
        // Initialize reports directory
        this.reportsDirectory = System.getProperty("user.home") + File.separator + ".belch" + File.separator + "reports";
        initializeReportsDirectory();
        
        logger.info("Report Generation Service initialized");
    }
    
    /**
     * Generate a report with specified configuration
     */
    public ReportResult generateReport(ReportRequest reportRequest) {
        try {
            logger.info("Generating report: {}", reportRequest.getReportName());
            
            // Get issues based on filters
            List<AuditIssue> issues = getFilteredIssues(reportRequest);
            
            // Validate we have issues to report
            if (issues.isEmpty() && !reportRequest.isIncludeEmptyReport()) {
                throw new IllegalStateException("No issues found matching the specified criteria");
            }
            
            // Generate report based on format
            ReportResult result;
            switch (reportRequest.getFormat()) {
                case HTML:
                    result = generateHtmlReport(reportRequest, issues);
                    break;
                case XML:
                    result = generateXmlReport(reportRequest, issues);
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported report format: " + reportRequest.getFormat());
            }
            
            // Store report if requested
            if (reportRequest.isStoreReport()) {
                storeReport(result);
            }
            
            // Save metadata to database
            saveReportMetadata(result, reportRequest);
            
            logger.info("Report generated successfully: {}", result.getReportId());
            return result;
            
        } catch (Exception e) {
            logger.error("Failed to generate report", e);
            throw new RuntimeException("Report generation failed: " + e.getMessage(), e);
        }
    }
    
    /**
     * Generate HTML report using Burp's built-in generator with custom template
     */
    private ReportResult generateHtmlReport(ReportRequest reportRequest, List<AuditIssue> issues) throws IOException {
        String reportId = generateReportId(reportRequest, "html");
        Path tempReportPath = Paths.get(reportsDirectory, reportId + "_temp.html");
        
        // Use Burp's native report generation
        api.scanner().generateReport(issues, ReportFormat.HTML, tempReportPath);
        
        // Read the generated report
        String reportContent = Files.readString(tempReportPath);
        
        // Apply custom template if specified
        if (reportRequest.getTemplateName() != null) {
            reportContent = applyTemplate(reportContent, reportRequest, issues);
        }
        
        // Create final report
        Path finalReportPath = Paths.get(reportsDirectory, reportId + ".html");
        Files.writeString(finalReportPath, reportContent);
        
        // Clean up temp file
        Files.deleteIfExists(tempReportPath);
        
        return new ReportResult(
            reportId,
            finalReportPath.toString(),
            ReportFormat.HTML,
            reportContent,
            issues.size(),
            System.currentTimeMillis()
        );
    }
    
    /**
     * Generate XML report using Burp's built-in generator
     */
    private ReportResult generateXmlReport(ReportRequest reportRequest, List<AuditIssue> issues) throws IOException {
        String reportId = generateReportId(reportRequest, "xml");
        Path reportPath = Paths.get(reportsDirectory, reportId + ".xml");
        
        // Use Burp's native report generation
        api.scanner().generateReport(issues, ReportFormat.XML, reportPath);
        
        // Read the generated report
        String reportContent = Files.readString(reportPath);
        
        return new ReportResult(
            reportId,
            reportPath.toString(),
            ReportFormat.XML,
            reportContent,
            issues.size(),
            System.currentTimeMillis()
        );
    }
    
    /**
     * Get filtered issues based on report request criteria
     */
    private List<AuditIssue> getFilteredIssues(ReportRequest reportRequest) {
        List<AuditIssue> allIssues = api.siteMap().issues();
        
        return allIssues.stream()
            .filter(issue -> matchesFilters(issue, reportRequest))
            .collect(Collectors.toList());
    }
    
    /**
     * Check if an issue matches the report filters
     */
    private boolean matchesFilters(AuditIssue issue, ReportRequest reportRequest) {
        // Severity filter
        if (reportRequest.getSeverityFilter() != null && 
            !reportRequest.getSeverityFilter().isEmpty()) {
            
            String issueSeverity = issue.severity().toString();
            if (!reportRequest.getSeverityFilter().contains(issueSeverity)) {
                return false;
            }
        }
        
        // Confidence filter
        if (reportRequest.getConfidenceFilter() != null && 
            !reportRequest.getConfidenceFilter().isEmpty()) {
            
            String issueConfidence = issue.confidence().toString();
            if (!reportRequest.getConfidenceFilter().contains(issueConfidence)) {
                return false;
            }
        }
        
        // URL filter
        if (reportRequest.getUrlPattern() != null && 
            !reportRequest.getUrlPattern().isEmpty()) {
            
            String issueUrl = issue.baseUrl();
            if (!issueUrl.matches(reportRequest.getUrlPattern())) {
                return false;
            }
        }
        
        // Issue type filter
        if (reportRequest.getIssueTypeFilter() != null && 
            !reportRequest.getIssueTypeFilter().isEmpty()) {
            
            String issueType = issue.definition().name();
            if (!reportRequest.getIssueTypeFilter().contains(issueType)) {
                return false;
            }
        }
        
        // Session tag filter (custom metadata)
        if (reportRequest.getSessionTagFilter() != null && 
            !reportRequest.getSessionTagFilter().isEmpty()) {
            
            // This would require custom tracking of session tags with issues
            // For now, we'll skip this filter as it requires database integration
        }
        
        return true;
    }
    
    /**
     * Apply custom template to report content
     */
    private String applyTemplate(String reportContent, ReportRequest reportRequest, List<AuditIssue> issues) {
        try {
            String template = getTemplate(reportRequest.getTemplateName());
            
            // Replace template variables
            Map<String, String> variables = createTemplateVariables(reportRequest, issues);
            
            String processedContent = template;
            for (Map.Entry<String, String> entry : variables.entrySet()) {
                processedContent = processedContent.replace("{{" + entry.getKey() + "}}", entry.getValue());
            }
            
            // Insert original content
            processedContent = processedContent.replace("{{REPORT_CONTENT}}", reportContent);
            
            return processedContent;
            
        } catch (Exception e) {
            logger.warn("Failed to apply template, using original content", e);
            return reportContent;
        }
    }
    
    /**
     * Create template variables for report generation
     */
    private Map<String, String> createTemplateVariables(ReportRequest reportRequest, List<AuditIssue> issues) {
        Map<String, String> variables = new HashMap<>();
        
        variables.put("REPORT_NAME", reportRequest.getReportName());
        variables.put("GENERATION_DATE", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
        variables.put("TOTAL_ISSUES", String.valueOf(issues.size()));
        variables.put("SESSION_TAG", config.getSessionTag());
        
        // Issue severity breakdown
        Map<String, Long> severityCounts = issues.stream()
            .collect(Collectors.groupingBy(
                issue -> issue.severity().toString(),
                Collectors.counting()
            ));
        
        variables.put("HIGH_SEVERITY_COUNT", String.valueOf(severityCounts.getOrDefault("HIGH", 0L)));
        variables.put("MEDIUM_SEVERITY_COUNT", String.valueOf(severityCounts.getOrDefault("MEDIUM", 0L)));
        variables.put("LOW_SEVERITY_COUNT", String.valueOf(severityCounts.getOrDefault("LOW", 0L)));
        variables.put("INFO_SEVERITY_COUNT", String.valueOf(severityCounts.getOrDefault("INFO", 0L)));
        
        // Issue confidence breakdown
        Map<String, Long> confidenceCounts = issues.stream()
            .collect(Collectors.groupingBy(
                issue -> issue.confidence().toString(),
                Collectors.counting()
            ));
        
        variables.put("CERTAIN_CONFIDENCE_COUNT", String.valueOf(confidenceCounts.getOrDefault("CERTAIN", 0L)));
        variables.put("FIRM_CONFIDENCE_COUNT", String.valueOf(confidenceCounts.getOrDefault("FIRM", 0L)));
        variables.put("TENTATIVE_CONFIDENCE_COUNT", String.valueOf(confidenceCounts.getOrDefault("TENTATIVE", 0L)));
        
        return variables;
    }
    
    /**
     * Get template content from cache or file
     */
    private String getTemplate(String templateName) throws IOException {
        if (templateCache.containsKey(templateName)) {
            return templateCache.get(templateName);
        }
        
        // Try to load from templates directory
        Path templatePath = Paths.get(reportsDirectory, "templates", templateName + ".html");
        
        if (Files.exists(templatePath)) {
            String templateContent = Files.readString(templatePath);
            templateCache.put(templateName, templateContent);
            return templateContent;
        }
        
        // Use default template if not found
        return getDefaultTemplate();
    }
    
    /**
     * Get default HTML report template
     */
    private String getDefaultTemplate() {
        StringBuilder template = new StringBuilder();
        template.append("<!DOCTYPE html>\n");
        template.append("<html>\n");
        template.append("<head>\n");
        template.append("    <title>{{REPORT_NAME}} - Security Scan Report</title>\n");
        template.append("    <style>\n");
        template.append("        body { font-family: Arial, sans-serif; margin: 20px; }\n");
        template.append("        .header { background-color: #f5f5f5; padding: 20px; border-radius: 5px; margin-bottom: 20px; }\n");
        template.append("        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }\n");
        template.append("        .summary-item { background-color: #e9ecef; padding: 15px; border-radius: 5px; text-align: center; }\n");
        template.append("        .severity-high { color: #dc3545; font-weight: bold; }\n");
        template.append("        .severity-medium { color: #fd7e14; font-weight: bold; }\n");
        template.append("        .severity-low { color: #ffc107; font-weight: bold; }\n");
        template.append("        .severity-info { color: #17a2b8; font-weight: bold; }\n");
        template.append("    </style>\n");
        template.append("</head>\n");
        template.append("<body>\n");
        template.append("    <div class=\"header\">\n");
        template.append("        <h1>{{REPORT_NAME}}</h1>\n");
        template.append("        <p>Generated on: {{GENERATION_DATE}}</p>\n");
        template.append("        <p>Session: {{SESSION_TAG}}</p>\n");
        template.append("        <p>Total Issues Found: {{TOTAL_ISSUES}}</p>\n");
        template.append("    </div>\n");
        template.append("    \n");
        template.append("    <div class=\"summary\">\n");
        template.append("        <div class=\"summary-item\">\n");
        template.append("            <h3 class=\"severity-high\">High Severity</h3>\n");
        template.append("            <p>{{HIGH_SEVERITY_COUNT}} issues</p>\n");
        template.append("        </div>\n");
        template.append("        <div class=\"summary-item\">\n");
        template.append("            <h3 class=\"severity-medium\">Medium Severity</h3>\n");
        template.append("            <p>{{MEDIUM_SEVERITY_COUNT}} issues</p>\n");
        template.append("        </div>\n");
        template.append("        <div class=\"summary-item\">\n");
        template.append("            <h3 class=\"severity-low\">Low Severity</h3>\n");
        template.append("            <p>{{LOW_SEVERITY_COUNT}} issues</p>\n");
        template.append("        </div>\n");
        template.append("        <div class=\"summary-item\">\n");
        template.append("            <h3 class=\"severity-info\">Informational</h3>\n");
        template.append("            <p>{{INFO_SEVERITY_COUNT}} issues</p>\n");
        template.append("        </div>\n");
        template.append("    </div>\n");
        template.append("    \n");
        template.append("    <div class=\"report-content\">\n");
        template.append("        {{REPORT_CONTENT}}\n");
        template.append("    </div>\n");
        template.append("</body>\n");
        template.append("</html>\n");
        return template.toString();
    }
    
    /**
     * Store report to file system
     */
    private void storeReport(ReportResult reportResult) throws IOException {
        // Report is already saved to file during generation
        logger.info("Report stored: {}", reportResult.getFilePath());
    }
    
    /**
     * Save report metadata to database
     */
    private void saveReportMetadata(ReportResult reportResult, ReportRequest reportRequest) {
        try {
            // Store report metadata in database for tracking
            String metadata = String.format(
                "Report-Name: %s\nFormat: %s\nIssue-Count: %d\nGeneration-Time: %d\nFile-Path: %s",
                reportRequest.getReportName(),
                reportResult.getFormat(),
                reportResult.getIssueCount(),
                reportResult.getGenerationTime(),
                reportResult.getFilePath()
            );
            
            databaseService.storeRawTraffic(
                "REPORT_GENERATION",
                "report://" + reportResult.getReportId(),
                "localhost",
                metadata,
                reportRequest.toString(),
                "",
                "",
                null,
                config.getSessionTag()
            );
            
        } catch (Exception e) {
            logger.warn("Failed to save report metadata to database", e);
        }
    }
    
    /**
     * List available reports
     */
    public List<ReportSummary> listReports() {
        try {
            List<ReportSummary> reports = new ArrayList<>();
            Path reportsDir = Paths.get(reportsDirectory);
            
            if (Files.exists(reportsDir)) {
                Files.list(reportsDir)
                    .filter(path -> path.toString().endsWith(".html") || path.toString().endsWith(".xml"))
                    .forEach(path -> {
                        try {
                            ReportSummary summary = new ReportSummary();
                            summary.setFileName(path.getFileName().toString());
                            summary.setFilePath(path.toString());
                            summary.setSize(Files.size(path));
                            summary.setLastModified(Files.getLastModifiedTime(path).toMillis());
                            
                            // Extract format from extension
                            if (path.toString().endsWith(".html")) {
                                summary.setFormat(ReportFormat.HTML);
                            } else if (path.toString().endsWith(".xml")) {
                                summary.setFormat(ReportFormat.XML);
                            }
                            
                            reports.add(summary);
                        } catch (IOException e) {
                            logger.warn("Failed to get info for report: {}", path, e);
                        }
                    });
            }
            
            return reports.stream()
                .sorted((a, b) -> Long.compare(b.getLastModified(), a.getLastModified()))
                .collect(Collectors.toList());
                
        } catch (Exception e) {
            logger.error("Failed to list reports", e);
            return new ArrayList<>();
        }
    }
    
    /**
     * Get report content by ID or filename
     */
    public String getReportContent(String reportId) throws IOException {
        Path reportPath = Paths.get(reportsDirectory, reportId);
        
        if (!Files.exists(reportPath)) {
            // Try with common extensions
            reportPath = Paths.get(reportsDirectory, reportId + ".html");
            if (!Files.exists(reportPath)) {
                reportPath = Paths.get(reportsDirectory, reportId + ".xml");
            }
        }
        
        if (!Files.exists(reportPath)) {
            throw new FileNotFoundException("Report not found: " + reportId);
        }
        
        return Files.readString(reportPath);
    }
    
    /**
     * Delete a report
     */
    public boolean deleteReport(String reportId) {
        try {
            Path reportPath = Paths.get(reportsDirectory, reportId);
            
            if (!Files.exists(reportPath)) {
                // Try with common extensions
                reportPath = Paths.get(reportsDirectory, reportId + ".html");
                if (!Files.exists(reportPath)) {
                    reportPath = Paths.get(reportsDirectory, reportId + ".xml");
                }
            }
            
            if (Files.exists(reportPath)) {
                Files.delete(reportPath);
                logger.info("Report deleted: {}", reportPath);
                return true;
            }
            
            return false;
            
        } catch (Exception e) {
            logger.error("Failed to delete report: {}", reportId, e);
            return false;
        }
    }
    
    // Helper methods
    
    /**
     * Initialize reports directory
     */
    private void initializeReportsDirectory() {
        try {
            Path reportsDir = Paths.get(reportsDirectory);
            Files.createDirectories(reportsDir);
            
            // Create templates subdirectory
            Path templatesDir = Paths.get(reportsDirectory, "templates");
            Files.createDirectories(templatesDir);
            
            logger.info("Reports directory initialized: {}", reportsDirectory);
            
        } catch (Exception e) {
            logger.error("Failed to initialize reports directory", e);
        }
    }
    
    /**
     * Generate unique report ID
     */
    private String generateReportId(ReportRequest reportRequest, String extension) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        String cleanName = reportRequest.getReportName().replaceAll("[^a-zA-Z0-9]", "_");
        return String.format("%s_%s_%s", cleanName, timestamp, extension);
    }
    
    // Inner classes for request/response models
    
    /**
     * Report generation request
     */
    public static class ReportRequest {
        private String reportName;
        private ReportFormat format = ReportFormat.HTML;
        private List<String> severityFilter;
        private List<String> confidenceFilter;
        private List<String> issueTypeFilter;
        private String urlPattern;
        private String sessionTagFilter;
        private String templateName;
        private boolean storeReport = true;
        private boolean includeEmptyReport = false;
        
        // Getters and setters
        public String getReportName() { return reportName; }
        public void setReportName(String reportName) { this.reportName = reportName; }
        
        public ReportFormat getFormat() { return format; }
        public void setFormat(ReportFormat format) { this.format = format; }
        
        public List<String> getSeverityFilter() { return severityFilter; }
        public void setSeverityFilter(List<String> severityFilter) { this.severityFilter = severityFilter; }
        
        public List<String> getConfidenceFilter() { return confidenceFilter; }
        public void setConfidenceFilter(List<String> confidenceFilter) { this.confidenceFilter = confidenceFilter; }
        
        public List<String> getIssueTypeFilter() { return issueTypeFilter; }
        public void setIssueTypeFilter(List<String> issueTypeFilter) { this.issueTypeFilter = issueTypeFilter; }
        
        public String getUrlPattern() { return urlPattern; }
        public void setUrlPattern(String urlPattern) { this.urlPattern = urlPattern; }
        
        public String getSessionTagFilter() { return sessionTagFilter; }
        public void setSessionTagFilter(String sessionTagFilter) { this.sessionTagFilter = sessionTagFilter; }
        
        public String getTemplateName() { return templateName; }
        public void setTemplateName(String templateName) { this.templateName = templateName; }
        
        public boolean isStoreReport() { return storeReport; }
        public void setStoreReport(boolean storeReport) { this.storeReport = storeReport; }
        
        public boolean isIncludeEmptyReport() { return includeEmptyReport; }
        public void setIncludeEmptyReport(boolean includeEmptyReport) { this.includeEmptyReport = includeEmptyReport; }
    }
    
    /**
     * Report generation result
     */
    public static class ReportResult {
        private final String reportId;
        private final String filePath;
        private final ReportFormat format;
        private final String content;
        private final int issueCount;
        private final long generationTime;
        
        public ReportResult(String reportId, String filePath, ReportFormat format, 
                          String content, int issueCount, long generationTime) {
            this.reportId = reportId;
            this.filePath = filePath;
            this.format = format;
            this.content = content;
            this.issueCount = issueCount;
            this.generationTime = generationTime;
        }
        
        public String getReportId() { return reportId; }
        public String getFilePath() { return filePath; }
        public ReportFormat getFormat() { return format; }
        public String getContent() { return content; }
        public int getIssueCount() { return issueCount; }
        public long getGenerationTime() { return generationTime; }
    }
    
    /**
     * Report summary for listing
     */
    public static class ReportSummary {
        private String fileName;
        private String filePath;
        private ReportFormat format;
        private long size;
        private long lastModified;
        
        // Getters and setters
        public String getFileName() { return fileName; }
        public void setFileName(String fileName) { this.fileName = fileName; }
        
        public String getFilePath() { return filePath; }
        public void setFilePath(String filePath) { this.filePath = filePath; }
        
        public ReportFormat getFormat() { return format; }
        public void setFormat(ReportFormat format) { this.format = format; }
        
        public long getSize() { return size; }
        public void setSize(long size) { this.size = size; }
        
        public long getLastModified() { return lastModified; }
        public void setLastModified(long lastModified) { this.lastModified = lastModified; }
    }
}