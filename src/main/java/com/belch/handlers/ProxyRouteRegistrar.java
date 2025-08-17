package com.belch.handlers;

import burp.api.montoya.MontoyaApi;
import com.belch.database.DatabaseService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.Javalin;
import java.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Responsible for registering proxy-related API routes.
 * Extracted from RouteHandler for modularity and maintainability.
 */
public class ProxyRouteRegistrar {
    private static final Logger logger = LoggerFactory.getLogger(ProxyRouteRegistrar.class);
    private final MontoyaApi api;
    private final DatabaseService databaseService;
    private final ObjectMapper objectMapper;

    public ProxyRouteRegistrar(MontoyaApi api, DatabaseService databaseService, ObjectMapper objectMapper) {
        this.api = api;
        this.databaseService = databaseService;
        this.objectMapper = objectMapper;
    }


    public void registerRoutes(Javalin app) {
        // Enhanced search proxy traffic with advanced filtering and regex support (Phase 3 Task 12)
        app.get("/proxy/search", ctx -> {
            if (!checkDatabaseAvailable(ctx)) return;
            Map<String, String> searchParams = extractSearchParams(ctx);
            
            // Use regex search if regex parameters are provided
            List<Map<String, Object>> results;
            long totalCount;
            
            boolean hasRegexParams = searchParams.containsKey("url_regex") || 
                                   searchParams.containsKey("method_regex") ||
                                   searchParams.containsKey("host_regex") ||
                                   searchParams.containsKey("headers_regex") ||
                                   searchParams.containsKey("body_regex") ||
                                   searchParams.containsKey("response_headers_regex") ||
                                   searchParams.containsKey("response_body_regex") ||
                                   searchParams.containsKey("session_tag_regex") ||
                                   Boolean.parseBoolean(searchParams.getOrDefault("use_regex", "false"));
            
            if (hasRegexParams) {
                results = databaseService.searchTrafficWithRegex(searchParams);
                totalCount = databaseService.getRegexSearchCount(searchParams);
            } else {
                results = databaseService.searchTraffic(searchParams);
                totalCount = databaseService.getSearchCount(searchParams);
            }
            Map<String, Object> response = new HashMap<>();
            response.put("results", results);
            response.put("count", results.size());
            response.put("total_count", totalCount);
            response.put("filters", searchParams);
            if (searchParams.containsKey("limit") || searchParams.containsKey("offset")) {
                Map<String, Object> pagination = new HashMap<>();
                int limit = searchParams.containsKey("limit") ? Integer.parseInt(searchParams.get("limit")) : 1000;
                int offset = searchParams.containsKey("offset") ? Integer.parseInt(searchParams.get("offset")) : 0;
                pagination.put("limit", limit);
                pagination.put("offset", offset);
                pagination.put("total_pages", (totalCount + limit - 1) / limit);
                pagination.put("current_page", (offset / limit) + 1);
                pagination.put("has_next", offset + limit < totalCount);
                pagination.put("has_previous", offset > 0);
                response.put("pagination", pagination);
            }
            ctx.json(response);
        });

        // Download endpoint for exporting search results
        app.get("/proxy/search/download", ctx -> {
            String format = ctx.queryParam("format");
            if (format == null) {
                format = "json";
            }
            format = format.toLowerCase();
            if (!format.equals("json") && !format.equals("csv") && !format.equals("xml") && !format.equals("custom")) {
                ctx.status(400).json(Map.of(
                    "error", "Invalid format",
                    "message", "Format must be 'json', 'csv', 'xml', or 'custom'",
                    "supported_formats", List.of("json", "csv", "xml", "custom")
                ));
                return;
            }
            Map<String, String> searchParams = extractSearchParams(ctx);
            searchParams.remove("limit");
            searchParams.remove("offset");
            
            // Use regex search if regex parameters are provided (Phase 3 Task 12)
            List<Map<String, Object>> results;
            boolean hasRegexParams = searchParams.containsKey("url_regex") || 
                                   searchParams.containsKey("method_regex") ||
                                   searchParams.containsKey("host_regex") ||
                                   searchParams.containsKey("headers_regex") ||
                                   searchParams.containsKey("body_regex") ||
                                   searchParams.containsKey("response_headers_regex") ||
                                   searchParams.containsKey("response_body_regex") ||
                                   searchParams.containsKey("session_tag_regex") ||
                                   Boolean.parseBoolean(searchParams.getOrDefault("use_regex", "false"));
            
            if (hasRegexParams) {
                results = databaseService.searchTrafficWithRegex(searchParams);
            } else {
                results = databaseService.searchTraffic(searchParams);
            }
            String filename = "proxy_traffic_" + System.currentTimeMillis() + "." + format;
            ctx.header("Content-Disposition", "attachment; filename=\"" + filename + "\"");
            if (format.equals("json")) {
                ctx.contentType("application/json")
                   .result(objectMapper.writeValueAsString(Map.of(
                       "export_metadata", Map.of(
                           "timestamp", System.currentTimeMillis(),
                           "total_records", results.size(),
                           "filters", searchParams
                       ),
                       "data", results
                   )));
            } else if (format.equals("csv")) {
                ctx.contentType("text/csv")
                   .result(convertToCsv(results));
            } else if (format.equals("xml")) {
                ctx.contentType("application/xml")
                   .result(convertToXml(results, searchParams));
            } else if (format.equals("custom")) {
                // Phase 3 Task 12: Custom export templates
                String template = ctx.queryParam("template");
                if (template == null || template.trim().isEmpty()) {
                    ctx.status(400).json(Map.of(
                        "error", "Missing template parameter",
                        "message", "Custom format requires 'template' query parameter",
                        "available_templates", List.of("detailed", "summary", "burp_xml", "nmap_xml", "custom_json")
                    ));
                    return;
                }
                
                String customContent = convertWithCustomTemplate(results, searchParams, template);
                String contentType = getContentTypeForTemplate(template);
                ctx.contentType(contentType).result(customContent);
            }
        });
        
        // Phase 3 Task 12: Bulk tagging/commenting endpoints
        
        // Bulk add tags
        app.post("/proxy/bulk/tags", ctx -> {
            if (!checkDatabaseAvailable(ctx)) return;
            
            try {
                Map<String, Object> requestBody = objectMapper.readValue(ctx.body(), Map.class);
                
                @SuppressWarnings("unchecked")
                List<Object> requestIdObjects = (List<Object>) requestBody.get("request_ids");
                if (requestIdObjects == null || requestIdObjects.isEmpty()) {
                    ctx.status(400).json(Map.of(
                        "error", "Missing required field",
                        "message", "request_ids array is required"
                    ));
                    return;
                }
                
                List<Long> requestIds = requestIdObjects.stream()
                    .map(obj -> {
                        if (obj instanceof Number) {
                            return ((Number) obj).longValue();
                        } else {
                            return Long.parseLong(obj.toString());
                        }
                    })
                    .collect(java.util.stream.Collectors.toList());
                
                String tags = (String) requestBody.get("tags");
                if (tags == null || tags.trim().isEmpty()) {
                    ctx.status(400).json(Map.of(
                        "error", "Missing required field",
                        "message", "tags field is required"
                    ));
                    return;
                }
                
                int updated = databaseService.bulkAddTags(requestIds, tags.trim());
                
                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("updated_count", updated);
                response.put("request_ids", requestIds);
                response.put("tags_added", tags.trim());
                response.put("operation", "bulk_tag_add");
                
                ctx.json(response);
                
            } catch (Exception e) {
                logger.error("Failed to bulk add tags", e);
                ctx.status(500).json(Map.of(
                    "error", "Internal server error",
                    "message", "Failed to add tags: " + e.getMessage()
                ));
            }
        });
        
        // Bulk remove tags
        app.delete("/proxy/bulk/tags", ctx -> {
            if (!checkDatabaseAvailable(ctx)) return;
            
            try {
                Map<String, Object> requestBody = objectMapper.readValue(ctx.body(), Map.class);
                
                @SuppressWarnings("unchecked")
                List<Object> requestIdObjects = (List<Object>) requestBody.get("request_ids");
                if (requestIdObjects == null || requestIdObjects.isEmpty()) {
                    ctx.status(400).json(Map.of(
                        "error", "Missing required field",
                        "message", "request_ids array is required"
                    ));
                    return;
                }
                
                List<Long> requestIds = requestIdObjects.stream()
                    .map(obj -> {
                        if (obj instanceof Number) {
                            return ((Number) obj).longValue();
                        } else {
                            return Long.parseLong(obj.toString());
                        }
                    })
                    .collect(java.util.stream.Collectors.toList());
                
                String tags = (String) requestBody.get("tags");
                if (tags == null || tags.trim().isEmpty()) {
                    ctx.status(400).json(Map.of(
                        "error", "Missing required field",
                        "message", "tags field is required"
                    ));
                    return;
                }
                
                int updated = databaseService.bulkRemoveTags(requestIds, tags.trim());
                
                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("updated_count", updated);
                response.put("request_ids", requestIds);
                response.put("tags_removed", tags.trim());
                response.put("operation", "bulk_tag_remove");
                
                ctx.json(response);
                
            } catch (Exception e) {
                logger.error("Failed to bulk remove tags", e);
                ctx.status(500).json(Map.of(
                    "error", "Internal server error",
                    "message", "Failed to remove tags: " + e.getMessage()
                ));
            }
        });
        
        // Bulk add comments
        app.post("/proxy/bulk/comments", ctx -> {
            if (!checkDatabaseAvailable(ctx)) return;
            
            try {
                Map<String, Object> requestBody = objectMapper.readValue(ctx.body(), Map.class);
                
                @SuppressWarnings("unchecked")
                List<Object> requestIdObjects = (List<Object>) requestBody.get("request_ids");
                if (requestIdObjects == null || requestIdObjects.isEmpty()) {
                    ctx.status(400).json(Map.of(
                        "error", "Missing required field",
                        "message", "request_ids array is required"
                    ));
                    return;
                }
                
                List<Long> requestIds = requestIdObjects.stream()
                    .map(obj -> {
                        if (obj instanceof Number) {
                            return ((Number) obj).longValue();
                        } else {
                            return Long.parseLong(obj.toString());
                        }
                    })
                    .collect(java.util.stream.Collectors.toList());
                
                String comment = (String) requestBody.get("comment");
                if (comment == null || comment.trim().isEmpty()) {
                    ctx.status(400).json(Map.of(
                        "error", "Missing required field",
                        "message", "comment field is required"
                    ));
                    return;
                }
                
                int updated = databaseService.bulkAddComments(requestIds, comment.trim());
                
                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("updated_count", updated);
                response.put("request_ids", requestIds);
                response.put("comment_added", comment.trim());
                response.put("operation", "bulk_comment_add");
                
                ctx.json(response);
                
            } catch (Exception e) {
                logger.error("Failed to bulk add comments", e);
                ctx.status(500).json(Map.of(
                    "error", "Internal server error",
                    "message", "Failed to add comments: " + e.getMessage()
                ));
            }
        });
        
        // Bulk clear comments
        app.delete("/proxy/bulk/comments", ctx -> {
            if (!checkDatabaseAvailable(ctx)) return;
            
            try {
                Map<String, Object> requestBody = objectMapper.readValue(ctx.body(), Map.class);
                
                @SuppressWarnings("unchecked")
                List<Object> requestIdObjects = (List<Object>) requestBody.get("request_ids");
                if (requestIdObjects == null || requestIdObjects.isEmpty()) {
                    ctx.status(400).json(Map.of(
                        "error", "Missing required field",
                        "message", "request_ids array is required"
                    ));
                    return;
                }
                
                List<Long> requestIds = requestIdObjects.stream()
                    .map(obj -> {
                        if (obj instanceof Number) {
                            return ((Number) obj).longValue();
                        } else {
                            return Long.parseLong(obj.toString());
                        }
                    })
                    .collect(java.util.stream.Collectors.toList());
                
                int updated = databaseService.bulkClearComments(requestIds);
                
                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("updated_count", updated);
                response.put("request_ids", requestIds);
                response.put("operation", "bulk_comment_clear");
                
                ctx.json(response);
                
            } catch (Exception e) {
                logger.error("Failed to bulk clear comments", e);
                ctx.status(500).json(Map.of(
                    "error", "Internal server error",
                    "message", "Failed to clear comments: " + e.getMessage()
                ));
            }
        });
    }

    private boolean checkDatabaseAvailable(io.javalin.http.Context ctx) {
        if (databaseService == null || !databaseService.isInitialized()) {
            ctx.status(503).json(Map.of(
                "error", "Database not available",
                "message", "Database service is not initialized. Please configure the extension in the 'REST API Config' tab.",
                "status", "service_unavailable"
            ));
            return false;
        }
        
        // Check for project changes and reinitialize if needed
        try {
            databaseService.checkForProjectChangeAndReinitialize();
        } catch (Exception e) {
            logger.warn("Failed to check for project changes: {}", e.getMessage());
            // Don't fail the request, but log the issue
        }
        
        return true;
    }

    private Map<String, String> extractSearchParams(io.javalin.http.Context ctx) {
        Map<String, String> searchParams = new HashMap<>();
        if (ctx.queryParam("url") != null) searchParams.put("url", ctx.queryParam("url"));
        if (ctx.queryParam("url_pattern") != null) searchParams.put("url_pattern", ctx.queryParam("url_pattern"));
        if (ctx.queryParam("method") != null) searchParams.put("method", ctx.queryParam("method"));
        if (ctx.queryParam("host") != null) searchParams.put("host", ctx.queryParam("host"));
        if (ctx.queryParam("status_code") != null) searchParams.put("status_code", ctx.queryParam("status_code"));
        if (ctx.queryParam("session_tag") != null) searchParams.put("session_tag", ctx.queryParam("session_tag"));
        if (ctx.queryParam("case_insensitive") != null) searchParams.put("case_insensitive", ctx.queryParam("case_insensitive"));
        if (ctx.queryParam("start_time") != null) searchParams.put("start_time", ctx.queryParam("start_time"));
        if (ctx.queryParam("end_time") != null) searchParams.put("end_time", ctx.queryParam("end_time"));
        if (ctx.queryParam("limit") != null) searchParams.put("limit", ctx.queryParam("limit"));
        if (ctx.queryParam("offset") != null) searchParams.put("offset", ctx.queryParam("offset"));
        
        // Phase 3 Task 12: Add regex support for all filter parameters
        if (ctx.queryParam("url_regex") != null) searchParams.put("url_regex", ctx.queryParam("url_regex"));
        if (ctx.queryParam("method_regex") != null) searchParams.put("method_regex", ctx.queryParam("method_regex"));
        if (ctx.queryParam("host_regex") != null) searchParams.put("host_regex", ctx.queryParam("host_regex"));
        if (ctx.queryParam("headers_regex") != null) searchParams.put("headers_regex", ctx.queryParam("headers_regex"));
        if (ctx.queryParam("body_regex") != null) searchParams.put("body_regex", ctx.queryParam("body_regex"));
        if (ctx.queryParam("response_headers_regex") != null) searchParams.put("response_headers_regex", ctx.queryParam("response_headers_regex"));
        if (ctx.queryParam("response_body_regex") != null) searchParams.put("response_body_regex", ctx.queryParam("response_body_regex"));
        if (ctx.queryParam("session_tag_regex") != null) searchParams.put("session_tag_regex", ctx.queryParam("session_tag_regex"));
        if (ctx.queryParam("use_regex") != null) searchParams.put("use_regex", ctx.queryParam("use_regex"));
        
        return searchParams;
    }

    private String convertToCsv(List<Map<String, Object>> results) {
        StringBuilder csv = new StringBuilder();
        csv.append("id,timestamp,method,url,host,status_code,session_tag\n");
        for (Map<String, Object> record : results) {
            csv.append(escapeCsvValue(record.get("id")))
               .append(",")
               .append(escapeCsvValue(record.get("timestamp")))
               .append(",")
               .append(escapeCsvValue(record.get("method")))
               .append(",")
               .append(escapeCsvValue(record.get("url")))
               .append(",")
               .append(escapeCsvValue(record.get("host")))
               .append(",")
               .append(escapeCsvValue(record.get("status_code")))
               .append(",")
               .append(escapeCsvValue(record.get("session_tag")))
               .append("\n");
        }
        return csv.toString();
    }

    private String escapeCsvValue(Object value) {
        if (value == null) {
            return "";
        }
        String str = value.toString();
        if (str.contains(",") || str.contains("\"") || str.contains("\n") || str.contains("\r")) {
            str = "\"" + str.replace("\"", "\"\"") + "\"";
        }
        return str;
    }
    
    /**
     * Convert results to XML format for Phase 3 Task 12.
     */
    private String convertToXml(List<Map<String, Object>> results, Map<String, String> searchParams) {
        StringBuilder xml = new StringBuilder();
        xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.append("<proxy_traffic_export>\n");
        
        // Add metadata
        xml.append("  <metadata>\n");
        xml.append("    <timestamp>").append(System.currentTimeMillis()).append("</timestamp>\n");
        xml.append("    <total_records>").append(results.size()).append("</total_records>\n");
        xml.append("    <export_format>xml</export_format>\n");
        
        // Add filters
        if (!searchParams.isEmpty()) {
            xml.append("    <filters>\n");
            for (Map.Entry<String, String> filter : searchParams.entrySet()) {
                xml.append("      <filter name=\"").append(escapeXml(filter.getKey())).append("\">")
                   .append(escapeXml(filter.getValue())).append("</filter>\n");
            }
            xml.append("    </filters>\n");
        }
        xml.append("  </metadata>\n");
        
        // Add data
        xml.append("  <data>\n");
        for (Map<String, Object> record : results) {
            xml.append("    <record>\n");
            
            // Add each field
            xml.append("      <id>").append(escapeXml(record.get("id"))).append("</id>\n");
            xml.append("      <timestamp>").append(escapeXml(record.get("timestamp"))).append("</timestamp>\n");
            xml.append("      <method>").append(escapeXml(record.get("method"))).append("</method>\n");
            xml.append("      <url>").append(escapeXml(record.get("url"))).append("</url>\n");
            xml.append("      <host>").append(escapeXml(record.get("host"))).append("</host>\n");
            xml.append("      <status_code>").append(escapeXml(record.get("status_code"))).append("</status_code>\n");
            xml.append("      <session_tag>").append(escapeXml(record.get("session_tag"))).append("</session_tag>\n");
            
            // Add optional fields
            if (record.get("tags") != null) {
                xml.append("      <tags>").append(escapeXml(record.get("tags"))).append("</tags>\n");
            }
            if (record.get("comment") != null) {
                xml.append("      <comment>").append(escapeXml(record.get("comment"))).append("</comment>\n");
            }
            
            // Add request data
            if (record.get("headers") != null || record.get("body") != null) {
                xml.append("      <request>\n");
                if (record.get("headers") != null) {
                    xml.append("        <headers><![CDATA[").append(record.get("headers")).append("]]></headers>\n");
                }
                if (record.get("body") != null) {
                    xml.append("        <body><![CDATA[").append(record.get("body")).append("]]></body>\n");
                }
                xml.append("      </request>\n");
            }
            
            // Add response data
            if (record.get("response_headers") != null || record.get("response_body") != null) {
                xml.append("      <response>\n");
                if (record.get("response_headers") != null) {
                    xml.append("        <headers><![CDATA[").append(record.get("response_headers")).append("]]></headers>\n");
                }
                if (record.get("response_body") != null) {
                    xml.append("        <body><![CDATA[").append(record.get("response_body")).append("]]></body>\n");
                }
                xml.append("      </response>\n");
            }
            
            xml.append("    </record>\n");
        }
        xml.append("  </data>\n");
        xml.append("</proxy_traffic_export>\n");
        
        return xml.toString();
    }
    
    /**
     * Escape XML special characters.
     */
    private String escapeXml(Object value) {
        if (value == null) {
            return "";
        }
        return value.toString()
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&apos;");
    }
    
    /**
     * Convert results using custom templates for Phase 3 Task 12.
     */
    private String convertWithCustomTemplate(List<Map<String, Object>> results, Map<String, String> searchParams, String template) {
        switch (template.toLowerCase()) {
            case "detailed":
                return generateDetailedTemplate(results, searchParams);
            case "summary":
                return generateSummaryTemplate(results, searchParams);
            case "burp_xml":
                return generateBurpXmlTemplate(results, searchParams);
            case "nmap_xml":
                return generateNmapXmlTemplate(results, searchParams);
            case "custom_json":
                return generateCustomJsonTemplate(results, searchParams);
            default:
                throw new IllegalArgumentException("Unknown template: " + template);
        }
    }
    
    /**
     * Get content type for template.
     */
    private String getContentTypeForTemplate(String template) {
        switch (template.toLowerCase()) {
            case "detailed":
            case "summary":
                return "text/plain";
            case "burp_xml":
            case "nmap_xml":
                return "application/xml";
            case "custom_json":
                return "application/json";
            default:
                return "text/plain";
        }
    }
    
    /**
     * Generate detailed text template.
     */
    private String generateDetailedTemplate(List<Map<String, Object>> results, Map<String, String> searchParams) {
        StringBuilder output = new StringBuilder();
        output.append("=== BELCH API DETAILED TRAFFIC EXPORT ===\n");
        output.append("Export Time: ").append(new java.util.Date()).append("\n");
        output.append("Total Records: ").append(results.size()).append("\n");
        
        if (!searchParams.isEmpty()) {
            output.append("Applied Filters:\n");
            for (Map.Entry<String, String> filter : searchParams.entrySet()) {
                output.append("  ").append(filter.getKey()).append(": ").append(filter.getValue()).append("\n");
            }
        }
        output.append("\n");
        
        for (int i = 0; i < results.size(); i++) {
            Map<String, Object> record = results.get(i);
            output.append("--- Record ").append(i + 1).append(" ---\n");
            output.append("ID: ").append(record.get("id")).append("\n");
            output.append("Timestamp: ").append(record.get("timestamp")).append("\n");
            output.append("Method: ").append(record.get("method")).append("\n");
            output.append("URL: ").append(record.get("url")).append("\n");
            output.append("Host: ").append(record.get("host")).append("\n");
            output.append("Status Code: ").append(record.get("status_code")).append("\n");
            output.append("Session Tag: ").append(record.get("session_tag")).append("\n");
            
            if (record.get("tags") != null) {
                output.append("Tags: ").append(record.get("tags")).append("\n");
            }
            if (record.get("comment") != null) {
                output.append("Comment: ").append(record.get("comment")).append("\n");
            }
            
            if (record.get("headers") != null) {
                output.append("Request Headers:\n").append(record.get("headers")).append("\n");
            }
            if (record.get("body") != null) {
                output.append("Request Body:\n").append(record.get("body")).append("\n");
            }
            if (record.get("response_headers") != null) {
                output.append("Response Headers:\n").append(record.get("response_headers")).append("\n");
            }
            if (record.get("response_body") != null) {
                output.append("Response Body:\n").append(record.get("response_body")).append("\n");
            }
            
            output.append("\n");
        }
        
        return output.toString();
    }
    
    /**
     * Generate summary text template.
     */
    private String generateSummaryTemplate(List<Map<String, Object>> results, Map<String, String> searchParams) {
        StringBuilder output = new StringBuilder();
        output.append("=== BELCH API TRAFFIC SUMMARY ===\n");
        output.append("Export Time: ").append(new java.util.Date()).append("\n");
        output.append("Total Records: ").append(results.size()).append("\n\n");
        
        output.append(String.format("%-6s %-8s %-20s %-12s %-50s\n", "ID", "METHOD", "HOST", "STATUS", "URL"));
        output.append("=".repeat(100)).append("\n");
        
        for (Map<String, Object> record : results) {
            output.append(String.format("%-6s %-8s %-20s %-12s %-50s\n",
                String.valueOf(record.get("id")),
                String.valueOf(record.get("method")),
                truncate(String.valueOf(record.get("host")), 20),
                String.valueOf(record.get("status_code")),
                truncate(String.valueOf(record.get("url")), 50)
            ));
        }
        
        return output.toString();
    }
    
    /**
     * Generate Burp Suite compatible XML template.
     */
    private String generateBurpXmlTemplate(List<Map<String, Object>> results, Map<String, String> searchParams) {
        StringBuilder xml = new StringBuilder();
        xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.append("<items burpVersion=\"Belch API Export\" exportTime=\"").append(System.currentTimeMillis()).append("\">\n");
        
        for (Map<String, Object> record : results) {
            xml.append("  <item>\n");
            xml.append("    <time>").append(escapeXml(record.get("timestamp"))).append("</time>\n");
            xml.append("    <url>").append(escapeXml(record.get("url"))).append("</url>\n");
            xml.append("    <host ip=\"\">").append(escapeXml(record.get("host"))).append("</host>\n");
            xml.append("    <port>443</port>\n"); // Default HTTPS port
            xml.append("    <protocol>https</protocol>\n");
            xml.append("    <method>").append(escapeXml(record.get("method"))).append("</method>\n");
            xml.append("    <path>").append(escapeXml(extractPath(String.valueOf(record.get("url"))))).append("</path>\n");
            xml.append("    <extension></extension>\n");
            
            if (record.get("headers") != null) {
                xml.append("    <request base64=\"false\"><![CDATA[")
                   .append(record.get("method")).append(" ").append(extractPath(String.valueOf(record.get("url")))).append(" HTTP/1.1\n")
                   .append(record.get("headers"));
                if (record.get("body") != null) {
                    xml.append("\n\n").append(record.get("body"));
                }
                xml.append("]]></request>\n");
            }
            
            if (record.get("status_code") != null) {
                xml.append("    <status>").append(escapeXml(record.get("status_code"))).append("</status>\n");
                
                if (record.get("response_headers") != null) {
                    xml.append("    <response base64=\"false\"><![CDATA[")
                       .append("HTTP/1.1 ").append(record.get("status_code")).append(" OK\n")
                       .append(record.get("response_headers"));
                    if (record.get("response_body") != null) {
                        xml.append("\n\n").append(record.get("response_body"));
                    }
                    xml.append("]]></response>\n");
                }
            }
            
            xml.append("    <comment>").append(escapeXml(record.get("comment"))).append("</comment>\n");
            xml.append("  </item>\n");
        }
        
        xml.append("</items>\n");
        return xml.toString();
    }
    
    /**
     * Generate Nmap XML compatible template.
     */
    private String generateNmapXmlTemplate(List<Map<String, Object>> results, Map<String, String> searchParams) {
        StringBuilder xml = new StringBuilder();
        xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.append("<!DOCTYPE nmaprun>\n");
        xml.append("<nmaprun scanner=\"belch-api\" start=\"").append(System.currentTimeMillis() / 1000).append("\" version=\"export\">\n");
        xml.append("  <scaninfo type=\"http\" protocol=\"tcp\" numservices=\"").append(results.size()).append("\"/>\n");
        
        // Group by host
        Map<String, java.util.List<Map<String, Object>>> hostGroups = new HashMap<>();
        for (Map<String, Object> record : results) {
            String host = String.valueOf(record.get("host"));
            hostGroups.computeIfAbsent(host, k -> new ArrayList<>()).add(record);
        }
        
        for (Map.Entry<String, java.util.List<Map<String, Object>>> hostGroup : hostGroups.entrySet()) {
            xml.append("  <host>\n");
            xml.append("    <address addr=\"").append(escapeXml(hostGroup.getKey())).append("\" addrtype=\"ipv4\"/>\n");
            xml.append("    <hostnames>\n");
            xml.append("      <hostname name=\"").append(escapeXml(hostGroup.getKey())).append("\" type=\"PTR\"/>\n");
            xml.append("    </hostnames>\n");
            xml.append("    <ports>\n");
            
            for (Map<String, Object> record : hostGroup.getValue()) {
                xml.append("      <port protocol=\"tcp\" portid=\"443\">\n");
                xml.append("        <state state=\"open\" reason=\"syn-ack\"/>\n");
                xml.append("        <service name=\"https\" method=\"").append(escapeXml(record.get("method"))).append("\"");
                xml.append(" extrainfo=\"").append(escapeXml(record.get("url"))).append("\"/>\n");
                xml.append("      </port>\n");
            }
            
            xml.append("    </ports>\n");
            xml.append("  </host>\n");
        }
        
        xml.append("</nmaprun>\n");
        return xml.toString();
    }
    
    /**
     * Generate custom JSON template with enhanced metadata.
     */
    private String generateCustomJsonTemplate(List<Map<String, Object>> results, Map<String, String> searchParams) {
        try {
            Map<String, Object> export = new HashMap<>();
            
            // Enhanced metadata
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("export_version", "1.0");
            metadata.put("export_time", System.currentTimeMillis());
            metadata.put("export_time_human", new java.util.Date().toString());
            metadata.put("tool", "Belch API");
            metadata.put("total_records", results.size());
            metadata.put("applied_filters", searchParams);
            
            // Statistics
            Map<String, Object> stats = new HashMap<>();
            Map<String, Integer> methodCounts = new HashMap<>();
            Map<String, Integer> statusCounts = new HashMap<>();
            Map<String, Integer> hostCounts = new HashMap<>();
            
            for (Map<String, Object> record : results) {
                String method = String.valueOf(record.get("method"));
                String status = String.valueOf(record.get("status_code"));
                String host = String.valueOf(record.get("host"));
                
                methodCounts.put(method, methodCounts.getOrDefault(method, 0) + 1);
                statusCounts.put(status, statusCounts.getOrDefault(status, 0) + 1);
                hostCounts.put(host, hostCounts.getOrDefault(host, 0) + 1);
            }
            
            stats.put("methods", methodCounts);
            stats.put("status_codes", statusCounts);
            stats.put("hosts", hostCounts);
            metadata.put("statistics", stats);
            
            export.put("metadata", metadata);
            export.put("traffic_records", results);
            
            return objectMapper.writeValueAsString(export);
            
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate custom JSON template", e);
        }
    }
    
    /**
     * Helper method to extract path from URL.
     */
    private String extractPath(String url) {
        try {
            java.net.URI uri = new java.net.URI(url);
            String path = uri.getPath();
            if (uri.getQuery() != null) {
                path += "?" + uri.getQuery();
            }
            return path.isEmpty() ? "/" : path;
        } catch (Exception e) {
            return "/";
        }
    }
    
    /**
     * Helper method to truncate strings.
     */
    private String truncate(String str, int maxLength) {
        if (str == null) return "";
        return str.length() <= maxLength ? str : str.substring(0, maxLength - 3) + "...";
    }
} 