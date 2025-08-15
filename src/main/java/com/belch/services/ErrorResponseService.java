package com.belch.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Service for creating enhanced error responses with error codes, suggestions, and fixes.
 * Provides standardized error formatting across the API.
 */
public class ErrorResponseService {
    
    private static final Logger logger = LoggerFactory.getLogger(ErrorResponseService.class);
    
    /**
     * Error severity levels
     */
    public enum Severity {
        LOW, MEDIUM, HIGH, CRITICAL
    }
    
    /**
     * Standard error codes
     */
    public static class ErrorCodes {
        public static final String DATABASE_UNAVAILABLE = "DB_001";
        public static final String DATABASE_CONNECTION_FAILED = "DB_002";
        public static final String DATABASE_QUERY_FAILED = "DB_003";
        public static final String DATABASE_TIMEOUT = "DB_004";
        
        public static final String SCANNER_NOT_AVAILABLE = "SC_001";
        public static final String SCANNER_TASK_NOT_FOUND = "SC_002";
        public static final String SCANNER_INVALID_CONFIG = "SC_003";
        public static final String SCANNER_EXECUTION_FAILED = "SC_004";
        
        public static final String VALIDATION_FAILED = "VAL_001";
        public static final String INVALID_PARAMETER = "VAL_002";
        public static final String MISSING_PARAMETER = "VAL_003";
        public static final String INVALID_FORMAT = "VAL_004";
        
        public static final String CIRCUIT_BREAKER_OPEN = "CB_001";
        public static final String RETRY_EXHAUSTED = "RT_001";
        public static final String TIMEOUT_ERROR = "TO_001";
        
        public static final String WEBSOCKET_CONNECTION_FAILED = "WS_001";
        public static final String WEBSOCKET_SEND_FAILED = "WS_002";
        
        public static final String INTERNAL_ERROR = "INT_001";
        public static final String SERVICE_UNAVAILABLE = "SVC_001";
        public static final String RATE_LIMIT_EXCEEDED = "RL_001";
    }
    
    /**
     * Create a standardized error response
     */
    public Map<String, Object> createErrorResponse(
            String errorCode, 
            String message, 
            Severity severity,
            Exception exception) {
        
        String requestId = UUID.randomUUID().toString();
        
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", true);
        errorResponse.put("error_code", errorCode);
        errorResponse.put("message", message);
        errorResponse.put("severity", severity.toString().toLowerCase());
        errorResponse.put("timestamp", Instant.now().toEpochMilli());
        errorResponse.put("request_id", requestId);
        
        // Add suggested fixes based on error code
        String suggestion = getSuggestion(errorCode);
        if (suggestion != null) {
            errorResponse.put("suggestion", suggestion);
        }
        
        // Add documentation link
        String docLink = getDocumentationLink(errorCode);
        if (docLink != null) {
            errorResponse.put("documentation", docLink);
        }
        
        // Add exception details in debug mode
        if (exception != null) {
            Map<String, Object> exceptionDetails = new HashMap<>();
            exceptionDetails.put("exception_type", exception.getClass().getSimpleName());
            exceptionDetails.put("exception_message", exception.getMessage());
            errorResponse.put("debug", exceptionDetails);
        }
        
        // Log the error
        logger.error("Error [{}] ({}): {} - Request ID: {}", 
            errorCode, severity, message, requestId, exception);
        
        return errorResponse;
    }
    
    /**
     * Create database error response
     */
    public Map<String, Object> createDatabaseError(String operation, Exception exception) {
        String errorCode;
        String message;
        
        if (exception.getMessage().contains("timeout")) {
            errorCode = ErrorCodes.DATABASE_TIMEOUT;
            message = "Database operation timed out during " + operation;
        } else if (exception.getMessage().contains("connection")) {
            errorCode = ErrorCodes.DATABASE_CONNECTION_FAILED;
            message = "Failed to connect to database for " + operation;
        } else {
            errorCode = ErrorCodes.DATABASE_QUERY_FAILED;
            message = "Database query failed during " + operation;
        }
        
        return createErrorResponse(errorCode, message, Severity.HIGH, exception);
    }
    
    /**
     * Create scanner error response
     */
    public Map<String, Object> createScannerError(String operation, Exception exception) {
        String errorCode = ErrorCodes.SCANNER_EXECUTION_FAILED;
        String message = "Scanner operation failed: " + operation;
        
        if (exception.getMessage().contains("not found")) {
            errorCode = ErrorCodes.SCANNER_TASK_NOT_FOUND;
            message = "Scanner task not found: " + operation;
        } else if (exception.getMessage().contains("configuration")) {
            errorCode = ErrorCodes.SCANNER_INVALID_CONFIG;
            message = "Invalid scanner configuration for: " + operation;
        }
        
        return createErrorResponse(errorCode, message, Severity.MEDIUM, exception);
    }
    
    /**
     * Create validation error response
     */
    public Map<String, Object> createValidationError(String parameter, String issue) {
        String errorCode = ErrorCodes.VALIDATION_FAILED;
        String message = "Validation failed for parameter '" + parameter + "': " + issue;
        
        if (issue.contains("missing") || issue.contains("required")) {
            errorCode = ErrorCodes.MISSING_PARAMETER;
        } else if (issue.contains("format") || issue.contains("invalid")) {
            errorCode = ErrorCodes.INVALID_FORMAT;
        }
        
        return createErrorResponse(errorCode, message, Severity.LOW, null);
    }
    
    /**
     * Create circuit breaker error response
     */
    public Map<String, Object> createCircuitBreakerError(String service) {
        String message = "Service '" + service + "' is temporarily unavailable due to circuit breaker";
        return createErrorResponse(ErrorCodes.CIRCUIT_BREAKER_OPEN, message, Severity.MEDIUM, null);
    }
    
    /**
     * Create retry exhausted error response
     */
    public Map<String, Object> createRetryExhaustedError(String operation, int attempts) {
        String message = "Operation '" + operation + "' failed after " + attempts + " retry attempts";
        return createErrorResponse(ErrorCodes.RETRY_EXHAUSTED, message, Severity.HIGH, null);
    }
    
    /**
     * Get suggested fix for error code
     */
    private String getSuggestion(String errorCode) {
        switch (errorCode) {
            case ErrorCodes.DATABASE_UNAVAILABLE:
                return "Check database connection settings and ensure database service is running";
            case ErrorCodes.DATABASE_CONNECTION_FAILED:
                return "Verify database URL, credentials, and network connectivity";
            case ErrorCodes.DATABASE_TIMEOUT:
                return "Consider increasing connection timeout or optimizing query performance";
            case ErrorCodes.SCANNER_NOT_AVAILABLE:
                return "Ensure Burp Suite scanner is properly initialized and available";
            case ErrorCodes.SCANNER_TASK_NOT_FOUND:
                return "Verify the task ID exists and hasn't been cancelled or completed";
            case ErrorCodes.SCANNER_INVALID_CONFIG:
                return "Check scanner configuration parameters and ensure they are valid";
            case ErrorCodes.VALIDATION_FAILED:
                return "Review request parameters and ensure they meet the required format";
            case ErrorCodes.CIRCUIT_BREAKER_OPEN:
                return "Wait for the service to recover or check service health status";
            case ErrorCodes.RETRY_EXHAUSTED:
                return "Check underlying service availability and consider manual retry";
            case ErrorCodes.WEBSOCKET_CONNECTION_FAILED:
                return "Verify WebSocket endpoint URL and check network connectivity";
            case ErrorCodes.RATE_LIMIT_EXCEEDED:
                return "Reduce request frequency or wait before retrying";
            default:
                return "Please check the logs for more details or contact support";
        }
    }
    
    /**
     * Get documentation link for error code
     */
    private String getDocumentationLink(String errorCode) {
        String baseUrl = "/docs/errors/";
        
        if (errorCode.startsWith("DB_")) {
            return baseUrl + "database-errors";
        } else if (errorCode.startsWith("SC_")) {
            return baseUrl + "scanner-errors";
        } else if (errorCode.startsWith("VAL_")) {
            return baseUrl + "validation-errors";
        } else if (errorCode.startsWith("CB_") || errorCode.startsWith("RT_")) {
            return baseUrl + "resilience-errors";
        } else if (errorCode.startsWith("WS_")) {
            return baseUrl + "websocket-errors";
        }
        
        return baseUrl + "general-errors";
    }
    
    /**
     * Create a simple error response for quick use
     */
    public Map<String, Object> createSimpleError(int httpStatus, String message) {
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", true);
        errorResponse.put("status", httpStatus);
        errorResponse.put("message", message);
        errorResponse.put("timestamp", Instant.now().toEpochMilli());
        return errorResponse;
    }
}