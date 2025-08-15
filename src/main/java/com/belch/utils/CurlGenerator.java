package com.belch.utils;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Utility class for generating curl commands from HTTP request data.
 * Supports various shell environments, header redaction, and pretty formatting.
 * 
 * @author Charlie Campbell
 * @version 1.0.0
 */
public class CurlGenerator {
    
    // Sensitive headers that should be redacted when requested
    private static final Set<String> SENSITIVE_HEADERS = new HashSet<>(Arrays.asList(
        "authorization", "cookie", "x-api-key", "x-auth-token", "x-access-token",
        "api-key", "auth-token", "access-token", "bearer", "jwt", "session",
        "x-session-id", "x-csrf-token", "x-xsrf-token", "x-forwarded-for"
    ));
    
    // Binary content types that should be truncated
    private static final Set<String> BINARY_CONTENT_TYPES = new HashSet<>(Arrays.asList(
        "application/octet-stream", "image/", "video/", "audio/", "application/pdf",
        "application/zip", "application/gzip", "application/x-compressed"
    ));
    
    // Maximum body size before truncation (in characters)
    private static final int MAX_BODY_SIZE = 10000;
    
    public enum ShellType {
        SH("sh"),
        BASH("bash"), 
        ZSH("zsh"),
        POWERSHELL("powershell");
        
        private final String name;
        
        ShellType(String name) {
            this.name = name;
        }
        
        public String getName() {
            return name;
        }
        
        public static ShellType fromString(String shell) {
            if (shell == null) return SH;
            
            switch (shell.toLowerCase()) {
                case "bash": return BASH;
                case "zsh": return ZSH;
                case "powershell": case "pwsh": return POWERSHELL;
                default: return SH;
            }
        }
    }
    
    /**
     * Request data container for curl generation
     */
    public static class RequestData {
        private final String method;
        private final String url;
        private final String headers;
        private final String body;
        private final String contentType;
        
        public RequestData(String method, String url, String headers, String body, String contentType) {
            this.method = method != null ? method.toUpperCase() : "GET";
            this.url = url;
            this.headers = headers;
            this.body = body;
            this.contentType = contentType;
        }
        
        // Getters
        public String getMethod() { return method; }
        public String getUrl() { return url; }
        public String getHeaders() { return headers; }
        public String getBody() { return body; }
        public String getContentType() { return contentType; }
    }
    
    /**
     * Generate a curl command from request data
     * 
     * @param requestData The HTTP request data
     * @param pretty Whether to format for readability (multi-line)
     * @param redact Whether to redact sensitive headers
     * @param shellType The target shell environment
     * @return Generated curl command
     */
    public static String buildCurlCommand(RequestData requestData, boolean pretty, boolean redact, ShellType shellType) {
        if (requestData == null || requestData.getUrl() == null) {
            return "# Error: Invalid request data";
        }
        
        StringBuilder curl = new StringBuilder();
        String indent = pretty ? "  " : "";
        String lineEnd = pretty ? " \\\n" : " ";
        
        // Start with curl command
        curl.append("curl");
        
        // Add method if not GET
        if (!"GET".equals(requestData.getMethod())) {
            curl.append(lineEnd).append(indent).append("-X ").append(requestData.getMethod());
        }
        
        // Add headers
        if (requestData.getHeaders() != null && !requestData.getHeaders().trim().isEmpty()) {
            String[] headerLines = requestData.getHeaders().split("\\r?\\n");
            for (String headerLine : headerLines) {
                headerLine = headerLine.trim();
                if (headerLine.isEmpty() || headerLine.toLowerCase().startsWith("host:")) {
                    continue; // Skip empty lines and Host header (curl adds automatically)
                }
                
                String processedHeader = processHeader(headerLine, redact, shellType);
                if (processedHeader != null) {
                    curl.append(lineEnd).append(indent).append("-H ").append(processedHeader);
                }
            }
        }
        
        // Add body if present
        if (requestData.getBody() != null && !requestData.getBody().trim().isEmpty()) {
            String processedBody = processBody(requestData.getBody(), requestData.getContentType(), shellType);
            if (processedBody != null) {
                curl.append(lineEnd).append(indent).append("-d ").append(processedBody);
            }
        }
        
        // Add URL (always last)
        curl.append(lineEnd).append(indent).append(escapeForShell(requestData.getUrl(), shellType));
        
        return curl.toString();
    }
    
    /**
     * Process and escape a header line
     */
    private static String processHeader(String headerLine, boolean redact, ShellType shellType) {
        if (headerLine == null || headerLine.trim().isEmpty()) {
            return null;
        }
        
        int colonIndex = headerLine.indexOf(':');
        if (colonIndex == -1) {
            return null; // Invalid header format
        }
        
        String headerName = headerLine.substring(0, colonIndex).trim().toLowerCase();
        String headerValue = headerLine.substring(colonIndex + 1).trim();
        
        // Redact sensitive headers if requested
        if (redact && isSensitiveHeader(headerName)) {
            headerValue = "[REDACTED]";
        }
        
        String fullHeader = headerName + ": " + headerValue;
        return escapeForShell(fullHeader, shellType);
    }
    
    /**
     * Process and escape request body
     */
    private static String processBody(String body, String contentType, ShellType shellType) {
        if (body == null) {
            return null;
        }
        
        // Check if content type suggests binary data
        if (isBinaryContent(contentType)) {
            return escapeForShell("# Binary content truncated (type: " + contentType + ")", shellType);
        }
        
        // Truncate large bodies
        String processedBody = body;
        if (body.length() > MAX_BODY_SIZE) {
            processedBody = body.substring(0, MAX_BODY_SIZE) + "\n# ... (truncated " + (body.length() - MAX_BODY_SIZE) + " characters)";
        }
        
        return escapeForShell(processedBody, shellType);
    }
    
    /**
     * Check if a header is considered sensitive
     */
    private static boolean isSensitiveHeader(String headerName) {
        return SENSITIVE_HEADERS.contains(headerName.toLowerCase()) ||
               headerName.toLowerCase().contains("auth") ||
               headerName.toLowerCase().contains("token") ||
               headerName.toLowerCase().contains("key");
    }
    
    /**
     * Check if content type suggests binary data
     */
    private static boolean isBinaryContent(String contentType) {
        if (contentType == null) {
            return false;
        }
        
        String lowerContentType = contentType.toLowerCase();
        return BINARY_CONTENT_TYPES.stream().anyMatch(lowerContentType::startsWith);
    }
    
    /**
     * Escape a string for the target shell environment
     */
    private static String escapeForShell(String input, ShellType shellType) {
        if (input == null) {
            return "''";
        }
        
        switch (shellType) {
            case POWERSHELL:
                return escapePowerShell(input);
            default:
                return escapeUnixShell(input);
        }
    }
    
    /**
     * Escape string for Unix-like shells (sh, bash, zsh)
     */
    private static String escapeUnixShell(String input) {
        // Use single quotes for most content, but handle single quotes specially
        if (!input.contains("'")) {
            return "'" + input + "'";
        }
        
        // For strings containing single quotes, use double quotes and escape special chars
        StringBuilder escaped = new StringBuilder("\"");
        for (char c : input.toCharArray()) {
            switch (c) {
                case '"':
                    escaped.append("\\\"");
                    break;
                case '\\':
                    escaped.append("\\\\");
                    break;
                case '$':
                    escaped.append("\\$");
                    break;
                case '`':
                    escaped.append("\\`");
                    break;
                case '\n':
                    escaped.append("\\n");
                    break;
                case '\r':
                    escaped.append("\\r");
                    break;
                case '\t':
                    escaped.append("\\t");
                    break;
                default:
                    escaped.append(c);
                    break;
            }
        }
        escaped.append("\"");
        return escaped.toString();
    }
    
    /**
     * Escape string for PowerShell
     */
    private static String escapePowerShell(String input) {
        StringBuilder escaped = new StringBuilder("'");
        for (char c : input.toCharArray()) {
            if (c == '\'') {
                escaped.append("''"); // Double single quote to escape in PowerShell
            } else {
                escaped.append(c);
            }
        }
        escaped.append("'");
        return escaped.toString();
    }
    
    /**
     * Generate curl command with default options (pretty=false, redact=false, shell=sh)
     */
    public static String buildCurlCommand(RequestData requestData) {
        return buildCurlCommand(requestData, false, false, ShellType.SH);
    }
    
    /**
     * Create a commented curl command with metadata
     */
    public static String buildCurlCommandWithMetadata(RequestData requestData, boolean pretty, boolean redact, 
                                                     ShellType shellType, Long requestId, String timestamp) {
        StringBuilder result = new StringBuilder();
        
        // Add metadata comments
        result.append("# Generated curl command for request");
        if (requestId != null) {
            result.append(" ID: ").append(requestId);
        }
        if (timestamp != null) {
            result.append(" (").append(timestamp).append(")");
        }
        result.append("\n");
        
        if (redact) {
            result.append("# Note: Sensitive headers have been redacted\n");
        }
        
        result.append("# Method: ").append(requestData.getMethod()).append("\n");
        result.append("# URL: ").append(requestData.getUrl()).append("\n");
        
        if (requestData.getContentType() != null) {
            result.append("# Content-Type: ").append(requestData.getContentType()).append("\n");
        }
        
        result.append("\n");
        result.append(buildCurlCommand(requestData, pretty, redact, shellType));
        
        return result.toString();
    }
} 