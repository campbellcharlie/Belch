package com.belch.logging;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import com.belch.database.TrafficQueue;
import com.belch.database.DatabaseService;
import com.belch.utils.TrafficUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.Map;
import java.nio.charset.StandardCharsets;

/**
 * Handles logging of proxy traffic using the proven TrafficQueue approach.
 * This logger uses asynchronous processing to handle high-volume traffic
 * without impacting Burp's performance.
 * 
 * @author Charlie Campbell
 * @version 2.0.0
 */
public class ProxyLogger implements ProxyRequestHandler, ProxyResponseHandler {
    
    private static final Logger logger = LoggerFactory.getLogger(ProxyLogger.class);
    
    private final MontoyaApi api;
    private final TrafficQueue trafficQueue;
    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private final AtomicBoolean shutdown;
    private final DatabaseService databaseService;
    
    /**
     * Constructor for ProxyLogger with TrafficQueue (proven approach).
     * 
     * @param api The MontoyaApi instance
     * @param trafficQueue The traffic queue for asynchronous traffic processing
     * @param databaseService The database service for storing traffic
     */
    public ProxyLogger(MontoyaApi api, TrafficQueue trafficQueue, DatabaseService databaseService) {
        this.api = api;
        this.trafficQueue = trafficQueue;
        this.databaseService = databaseService;
        this.shutdown = new AtomicBoolean(false);
        logger.info("ProxyLogger initialized with TrafficQueue for proven async processing");
    }
    
    /**
     * Initializes the proxy logger by registering handlers with Burp.
     */
    public void initialize() {
        if (initialized.getAndSet(true)) {
            logger.warn("ProxyLogger already initialized");
            return;
        }
        
        if (trafficQueue == null) {
            logger.error("Cannot initialize ProxyLogger - traffic queue is null");
            throw new IllegalStateException("TrafficQueue is required for ProxyLogger");
        }
        
        try {
            // Register proxy handlers
            api.proxy().registerRequestHandler(this);
            api.proxy().registerResponseHandler(this);
            
            logger.info("ProxyLogger initialized and registered with Burp proxy");
            logger.info("ProxyLogger is now actively monitoring traffic with async processing");
            
            
        } catch (Exception e) {
            logger.error("Failed to initialize ProxyLogger", e);
            api.logging().logToError("ProxyLogger initialization failed: " + e.getMessage());
            initialized.set(false);
            throw new RuntimeException("Failed to initialize ProxyLogger", e);
        }
    }
    
    /**
     * Shuts down the proxy logger.
     */
    public void shutdown() {
        if (shutdown.getAndSet(true)) {
            return;
        }
        
        logger.info("ProxyLogger shutting down");
        
        // Note: Montoya API doesn't provide unregister methods, so handlers will be cleaned up when extension unloads
        logger.info("ProxyLogger shutdown completed");
    }
    
    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        if (shutdown.get() || trafficQueue == null) {
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }
        
        try {
            // Queue the request for asynchronous processing
            trafficQueue.queueRequest(interceptedRequest);
            
            logger.debug("Proxy request queued: {} {}", interceptedRequest.method(), interceptedRequest.url());
            
        } catch (Exception e) {
            logger.error("Error queuing proxy request", e);
        }
        
        // Continue processing the request without any delay
        return ProxyRequestReceivedAction.continueWith(interceptedRequest);
    }
    
    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        // Continue without additional processing
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
    }
    
    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        if (shutdown.get() || trafficQueue == null) {
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }
        
        try {
            // Queue the response for asynchronous processing
            trafficQueue.queueResponse(interceptedResponse);
            
            logger.debug("Proxy response queued: {} {} -> {}", 
                       interceptedResponse.initiatingRequest().method(),
                       interceptedResponse.initiatingRequest().url(), 
                       interceptedResponse.statusCode());
            
        } catch (Exception e) {
            logger.error("Error queuing proxy response", e);
        }
        
        // Continue processing the response without any delay
        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }
    
    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        // Continue without additional processing
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }
    
    /**
     * Checks if the proxy logger is initialized.
     * 
     * @return true if initialized, false otherwise
     */
    public boolean isInitialized() {
        return initialized.get();
    }
    
    /**
     * Checks if the proxy logger is shut down.
     * 
     * @return true if shut down, false otherwise
     */
    public boolean isShutdown() {
        return shutdown.get();
    }

    private void storeProxyTraffic(
            String method,
            String url,
            String host,
            Map<String, String> requestHeaders,
            byte[] requestBody,
            Map<String, String> responseHeaders,
            byte[] responseBody,
            int statusCode
    ) {
        try {
            // Get current session tag from API
            String sessionTag = api.persistence().preferences().getString("session_tag");
            if (sessionTag == null || sessionTag.trim().isEmpty()) {
                // For proxy traffic, create a unique session tag if none exists
                sessionTag = "proxy_" + System.currentTimeMillis();
            }

            // Convert headers to strings
            String reqHeaders = TrafficUtils.mapToString(requestHeaders);
            String respHeaders = TrafficUtils.mapToString(responseHeaders);

            // Store using the enhanced method with source tracking
            long recordId = databaseService.storeRawTrafficWithSource(
                method, url, host,
                reqHeaders, new String(requestBody, StandardCharsets.UTF_8),
                respHeaders, new String(responseBody, StandardCharsets.UTF_8),
                statusCode, sessionTag,
                TrafficSource.PROXY
            );

            if (recordId > 0) {
                logger.debug("Stored Proxy traffic with ID: " + recordId);
            } else {
                logger.warn("Failed to store Proxy traffic");
            }
        } catch (Exception e) {
            logger.error("Error storing Proxy traffic: " + e.getMessage());
        }
    }
} 