package com.belch.logging;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import com.belch.database.DatabaseService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

/**
 * Logger for capturing and storing Repeater traffic directly to the database.
 * This class implements HttpHandler to monitor all HTTP traffic and filters for 
 * requests/responses that originated from the Repeater tool.
 * 
 * @author Charlie Campbell
 * @version 2.0.0
 */
public class RepeaterLogger implements HttpHandler {
    
    private static final Logger logger = LoggerFactory.getLogger(RepeaterLogger.class);
    
    private final MontoyaApi api;
    private final DatabaseService databaseService;
    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private final AtomicBoolean shutdown = new AtomicBoolean(false);
    
    // PHASE 12 FIX: Add TrafficQueue for WebSocket broadcasting
    private com.belch.database.TrafficQueue trafficQueue;
    
    // Track pending Repeater requests to match with responses
    private final Map<String, HttpRequestToBeSent> pendingRepeaterRequests = new ConcurrentHashMap<>();
    
    /**
     * Constructor for RepeaterLogger.
     * 
     * @param api The MontoyaApi instance
     * @param trafficQueue The traffic queue for WebSocket events
     * @param databaseService The database service for direct storage
     */
    public RepeaterLogger(MontoyaApi api, com.belch.database.TrafficQueue trafficQueue, DatabaseService databaseService) {
        this.api = api;
        this.trafficQueue = trafficQueue;
        this.databaseService = databaseService;
        logger.info("RepeaterLogger initialized with TrafficQueue for proven async processing");
    }
    
    /**
     * PHASE 12 FIX: Set TrafficQueue for WebSocket broadcasting.
     * 
     * @param trafficQueue The traffic queue for WebSocket events
     */
    public void setTrafficQueue(com.belch.database.TrafficQueue trafficQueue) {
        this.trafficQueue = trafficQueue;
        logger.info("RepeaterLogger: TrafficQueue connected for WebSocket broadcasting");
    }
    
    /**
     * Initializes the Repeater logger and registers with Burp's HTTP handler.
     */
    public void initialize() {
        if (initialized.getAndSet(true)) {
            logger.warn("RepeaterLogger already initialized");
            return;
        }
        
        if (databaseService == null || !databaseService.isInitialized()) {
            logger.error("Cannot initialize RepeaterLogger - database service not available");
            throw new IllegalStateException("DatabaseService is required for RepeaterLogger");
        }
        
        try {
            // Register as HTTP handler to capture all HTTP traffic
            api.http().registerHttpHandler(this);
            
            logger.info("RepeaterLogger: Successfully registered HTTP handler for direct database storage");
            
        } catch (Exception e) {
            logger.error("Failed to initialize RepeaterLogger", e);
            api.logging().logToError("RepeaterLogger initialization failed: " + e.getMessage());
            initialized.set(false);
            throw new RuntimeException("Failed to initialize RepeaterLogger", e);
        }
    }
    
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        if (shutdown.get() || databaseService == null) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }
        
        try {
            // Check if this is a repeater request
            if (isRepeaterRequest(requestToBeSent)) {
                // Store this request to match with the upcoming response
                String requestKey = generateRequestKey(requestToBeSent);
                pendingRepeaterRequests.put(requestKey, requestToBeSent);
                
                logger.debug("Repeater request detected: {} {}", 
                           requestToBeSent.method(), requestToBeSent.url());
            }
            
        } catch (Exception e) {
            logger.error("Error handling Repeater request", e);
        }
        
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }
    
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (shutdown.get() || databaseService == null) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }
        
        try {
            // Check if this response is from Repeater tool
            if (responseReceived.toolSource().toolType() == ToolType.REPEATER) {
                // Try to match this response with a pending Repeater request
                String responseKey = generateRequestKey(responseReceived.initiatingRequest());
                HttpRequestToBeSent matchingRequest = pendingRepeaterRequests.remove(responseKey);
                
                if (matchingRequest != null) {
                    // Store directly in database with REPEATER source
                    storeRepeaterTraffic(matchingRequest, responseReceived);
                    
                    logger.info("Repeater traffic captured: {} {} -> {} (Source: REPEATER)", 
                               matchingRequest.method(), matchingRequest.url(), responseReceived.statusCode());
                    
                    // Log to Burp's output for immediate visibility
                    api.logging().logToOutput(String.format("REPEATER CAPTURED: %s %s -> %s (Source: REPEATER)", 
                        matchingRequest.method(), matchingRequest.url(), responseReceived.statusCode()));
                } else {
                    // Response without matching request (shouldn't happen normally)
                    logger.debug("Received Repeater response without matching request: {} {}", 
                               responseReceived.statusCode(), responseReceived.initiatingRequest().url());
                }
            }
            
        } catch (Exception e) {
            logger.error("Error handling Repeater response", e);
        }
        
        return ResponseReceivedAction.continueWith(responseReceived);
    }
    
    /**
     * Stores Repeater traffic directly in the database with source attribution.
     */
    private void storeRepeaterTraffic(HttpRequestToBeSent request, HttpResponseReceived response) {
        try {
            // Extract request details
            String method = request.method();
            String url = request.url();
            String host = request.httpService().host();
            String requestHeaders = request.headers().toString();
            String requestBody = request.bodyToString();
            
            // Extract response details
            String responseHeaders = response.headers().toString();
            String responseBody = response.bodyToString();
            int statusCode = response.statusCode();
            
            // Get current session tag from API
            String sessionTag = api.persistence().preferences().getString("session_tag");
            if (sessionTag == null || sessionTag.trim().isEmpty()) {
                sessionTag = "session_" + System.currentTimeMillis() + "_repeater";
            }
            
            // Store using the enhanced method with source tracking
            long recordId = databaseService.storeRawTrafficWithSource(
                method, url, host,
                requestHeaders, requestBody,
                responseHeaders, responseBody,
                statusCode, sessionTag,
                TrafficSource.REPEATER
            );
            
            if (recordId > 0) {
                logger.debug("Stored Repeater traffic: {} {} -> {} (ID: {})", 
                           method, url, statusCode, recordId);
                
                // PHASE 12 FIX: Also queue for WebSocket broadcasting
                if (trafficQueue != null) {
                    trafficQueue.queueRawTraffic(method, url, host, 
                                               requestHeaders, requestBody,
                                               responseHeaders, responseBody, 
                                               statusCode, sessionTag,
                                               TrafficSource.REPEATER);
                    logger.debug("Queued Repeater traffic for WebSocket broadcast");
                }
            }
            
        } catch (Exception e) {
            logger.error("Error storing Repeater traffic", e);
        }
    }
    
    /**
     * Checks if the request is from the Repeater tool.
     */
    private boolean isRepeaterRequest(HttpRequestToBeSent request) {
        try {
            return request.toolSource().toolType() == ToolType.REPEATER;
        } catch (Exception e) {
            logger.debug("Could not determine tool source for request", e);
            return false;
        }
    }
    
    /**
     * Generates a unique key for request/response matching.
     */
    private String generateRequestKey(burp.api.montoya.http.message.requests.HttpRequest request) {
        // Create a key based on method, URL, and current time (approximate)
        return request.method() + "|" + request.url() + "|" + (System.currentTimeMillis() / 1000);
    }
    
    /**
     * Shuts down the Repeater logger.
     */
    public void shutdown() {
        if (shutdown.getAndSet(true)) {
            return;
        }
        
        logger.info("Shutting down RepeaterLogger");
        
        // Clear pending requests
        pendingRepeaterRequests.clear();
        
        logger.info("RepeaterLogger shutdown completed");
    }
    
    /**
     * Checks if the Repeater logger is initialized.
     * 
     * @return true if initialized, false otherwise
     */
    public boolean isInitialized() {
        return initialized.get() && !shutdown.get();
    }
} 