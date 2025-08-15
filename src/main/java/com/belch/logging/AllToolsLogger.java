package com.belch.logging;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import com.belch.database.DatabaseService;
import com.belch.database.TrafficQueue;
import com.belch.config.ApiConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

/**
 * Captures traffic from ALL Burp tools and logs them to the database with proper source attribution.
 * This logger registers as an HTTP handler to intercept all traffic regardless of the originating tool.
 * 
 * @author Charlie Campbell
 * @version 1.0.0
 */
public class AllToolsLogger implements HttpHandler {
    
    private static final Logger logger = LoggerFactory.getLogger(AllToolsLogger.class);
    
    private final MontoyaApi api;
    private final DatabaseService databaseService;
    private final TrafficQueue trafficQueue;
    private final ApiConfig config;
    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private final AtomicBoolean shutdown = new AtomicBoolean(false);
    
    // Track pending requests to match with responses
    private final Map<String, PendingRequest> pendingRequests = new ConcurrentHashMap<>();
    
    /**
     * Represents a pending request waiting for its response.
     */
    private static class PendingRequest {
        final HttpRequestToBeSent request;
        final String toolSource;
        final long timestamp;
        
        PendingRequest(HttpRequestToBeSent request, String toolSource) {
            this.request = request;
            this.toolSource = toolSource;
            this.timestamp = System.currentTimeMillis();
        }
    }
    
    /**
     * Constructor for AllToolsLogger.
     * 
     * @param api The MontoyaApi instance
     * @param databaseService The database service for storing traffic
     * @param trafficQueue The traffic queue for WebSocket broadcasting
     * @param config The API configuration
     */
    public AllToolsLogger(MontoyaApi api, DatabaseService databaseService, TrafficQueue trafficQueue, ApiConfig config) {
        this.api = api;
        this.databaseService = databaseService;
        this.trafficQueue = trafficQueue;
        this.config = config;
    }
    
    /**
     * Initializes the all-tools logger by registering with Burp's HTTP handler.
     */
    public void initialize() {
        if (initialized.getAndSet(true)) {
            logger.warn("AllToolsLogger already initialized");
            return;
        }
        
        if (databaseService == null || !databaseService.isInitialized()) {
            logger.error("Cannot initialize AllToolsLogger - database service not available");
            throw new IllegalStateException("DatabaseService is required for AllToolsLogger");
        }
        
        try {
            // Register as HTTP handler to capture ALL traffic from ALL tools
            api.http().registerHttpHandler(this);
            
            logger.info("AllToolsLogger HTTP handler registered successfully");
            
        } catch (Exception e) {
            logger.error("Failed to initialize AllToolsLogger", e);
            api.logging().logToError("AllToolsLogger initialization failed: " + e.getMessage());
            api.logging().logToError("AllToolsLogger initialization failed: " + e.getMessage());
            initialized.set(false);
            throw new RuntimeException("Failed to initialize AllToolsLogger", e);
        }
    }
    
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        if (shutdown.get() || databaseService == null) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }
        
        try {
            // Determine the source tool
            String toolSource = getToolSource(requestToBeSent);
            
            // Generate a key for matching request with response
            String requestKey = generateRequestKey(requestToBeSent);
            
            // Store the request for matching with response
            pendingRequests.put(requestKey, new PendingRequest(requestToBeSent, toolSource));
            
            // Clean up old pending requests (older than 5 minutes)
            cleanupOldPendingRequests();
            
            logger.debug("Request captured from {}: {} {}", toolSource, 
                        requestToBeSent.method(), requestToBeSent.url());
            
        } catch (Exception e) {
            logger.error("Error handling request from " + getToolSource(requestToBeSent), e);
        }
        
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }
    
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (shutdown.get() || databaseService == null) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }
        
        try {
            // Try to match this response with a pending request
            String responseKey = generateRequestKey(responseReceived.initiatingRequest());
            PendingRequest matchingRequest = pendingRequests.remove(responseKey);
            
            String toolSource;
            HttpRequestToBeSent request;
            
            if (matchingRequest != null) {
                // Found matching request
                toolSource = matchingRequest.toolSource;
                request = matchingRequest.request;
            } else {
                // No matching request found - determine source from response
                toolSource = getToolSource(responseReceived);
                request = null;
            }
            
            // Store the complete transaction in database
            storeTrafficWithSource(request, responseReceived, toolSource);
            
            logger.debug("Response captured from {}: {} {} -> {}", 
                        toolSource,
                        responseReceived.initiatingRequest().method(),
                        responseReceived.initiatingRequest().url(),
                        responseReceived.statusCode());
            
        } catch (Exception e) {
            logger.error("Error handling response from " + getToolSource(responseReceived), e);
        }
        
        return ResponseReceivedAction.continueWith(responseReceived);
    }
    
    /**
     * Determines the source tool from the request.
     */
    private String getToolSource(HttpRequestToBeSent request) {
        try {
            ToolType toolType = request.toolSource().toolType();
            return mapToolTypeToSource(toolType);
        } catch (Exception e) {
            logger.debug("Could not determine tool source for request", e);
            return "UNKNOWN";
        }
    }
    
    /**
     * Determines the source tool from the response.
     */
    private String getToolSource(HttpResponseReceived response) {
        try {
            ToolType toolType = response.toolSource().toolType();
            return mapToolTypeToSource(toolType);
        } catch (Exception e) {
            logger.debug("Could not determine tool source for response", e);
            return "UNKNOWN";
        }
    }
    
    /**
     * Maps Burp's ToolType to our traffic source strings.
     */
    private String mapToolTypeToSource(ToolType toolType) {
        switch (toolType) {
            case PROXY:
                return "PROXY";
            case REPEATER:
                return "REPEATER";
            case INTRUDER:
                return "INTRUDER";
            case SCANNER:
                return "SCANNER";
            case SEQUENCER:
                return "SEQUENCER";
            case COMPARER:
                return "COMPARER";
            case DECODER:
                return "DECODER";
            case EXTENSIONS:
                return "EXTENSION";
            default:
                return "UNKNOWN";
        }
    }
    
    /**
     * Stores traffic in the database with source attribution.
     */
    private void storeTrafficWithSource(HttpRequestToBeSent request, HttpResponseReceived response, String toolSource) {
        try {
            // Use the request from the response if we don't have the original
            var actualRequest = request != null ? request : response.initiatingRequest();
            
            // Extract request details
            String method = actualRequest.method();
            String url = actualRequest.url();
            String host = actualRequest.httpService().host();
            String requestHeaders = actualRequest.headers().toString();
            String requestBody = actualRequest.bodyToString();
            
            // Extract response details
            String responseHeaders = response.headers().toString();
            String responseBody = response.bodyToString();
            int statusCode = response.statusCode();
            
            // Create session tag with tool source
            String sessionTag = config.getSessionTag() + "_" + toolSource.toLowerCase();
            
            // Store using the enhanced method with source tracking
            long recordId = databaseService.storeRawTrafficWithSource(
                method, url, host,
                requestHeaders, requestBody,
                responseHeaders, responseBody,
                statusCode, sessionTag,
                TrafficSource.valueOf(toolSource)
            );
            
            if (recordId > 0) {
                logger.debug("Stored traffic from {}: {} {} -> {} (ID: {})", 
                           toolSource, method, url, statusCode, recordId);
                
                // Queue traffic for WebSocket broadcasting
                if (trafficQueue != null) {
                    trafficQueue.queueRawTraffic(
                        method, url, host, 
                        requestHeaders, requestBody, 
                        responseHeaders, responseBody, 
                        statusCode, sessionTag, 
                        TrafficSource.valueOf(toolSource)
                    );
                    logger.debug("Queued {} traffic for WebSocket broadcasting", toolSource);
                } else {
                    logger.warn("TrafficQueue is null - cannot broadcast WebSocket events");
                }
            }
            
        } catch (Exception e) {
            logger.error("Error storing traffic from " + toolSource, e);
        }
    }
    
    /**
     * Generates a unique key for request/response matching.
     */
    private String generateRequestKey(burp.api.montoya.http.message.requests.HttpRequest request) {
        // Create a key based on method, URL, and timestamp (rounded to second)
        return request.method() + "|" + request.url() + "|" + (System.currentTimeMillis() / 1000);
    }
    
    /**
     * Cleans up old pending requests to prevent memory leaks.
     */
    private void cleanupOldPendingRequests() {
        if (pendingRequests.size() > 1000) { // Only clean up when we have many pending
            long cutoffTime = System.currentTimeMillis() - (5 * 60 * 1000); // 5 minutes ago
            
            pendingRequests.entrySet().removeIf(entry -> 
                entry.getValue().timestamp < cutoffTime
            );
        }
    }
    
    /**
     * Shuts down the all-tools logger.
     */
    public void shutdown() {
        if (shutdown.getAndSet(true)) {
            return;
        }
        
        logger.info("AllToolsLogger shutting down");
        
        // Clear pending requests
        pendingRequests.clear();
        
        logger.info("AllToolsLogger shutdown completed");
    }
    
    /**
     * Checks if the logger is initialized and ready.
     */
    public boolean isReady() {
        return initialized.get() && !shutdown.get() && databaseService != null;
    }
    
    /**
     * Gets the number of pending requests (for debugging).
     */
    public int getPendingRequestCount() {
        return pendingRequests.size();
    }
} 