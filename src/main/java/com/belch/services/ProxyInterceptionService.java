package com.belch.services;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;
import java.net.URL;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;

/**
 * Service for managing real-time proxy interception rules (2025.8+)
 * Allows dynamic modification of requests and responses in transit
 */
public class ProxyInterceptionService {
    
    private static final Logger logger = LoggerFactory.getLogger(ProxyInterceptionService.class);
    
    private final MontoyaApi api;
    private final Map<String, InterceptionRule> activeRules = new ConcurrentHashMap<>();
    private final AtomicLong ruleIdCounter = new AtomicLong(1);
    private final List<Registration> registrations = new ArrayList<>();
    
    public ProxyInterceptionService(MontoyaApi api) {
        this.api = api;
        registerHandlers();
    }
    
    /**
     * Register proxy handlers for interception
     */
    private void registerHandlers() {
        // Register request handler
        Registration requestReg = api.proxy().registerRequestHandler(new ProxyRequestHandler() {
            @Override
            public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
                return ProxyRequestReceivedAction.continueWith(interceptedRequest);
            }
            
            @Override
            public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
                return processRequestRules(interceptedRequest);
            }
        });
        registrations.add(requestReg);
        
        // Register response handler
        Registration responseReg = api.proxy().registerResponseHandler(new ProxyResponseHandler() {
            @Override
            public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
                return ProxyResponseReceivedAction.continueWith(interceptedResponse);
            }
            
            @Override
            public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
                return processResponseRules(interceptedResponse);
            }
        });
        registrations.add(responseReg);
        
        logger.info("Proxy interception handlers registered successfully (2025.8+)");
    }
    
    /**
     * Process request interception rules
     */
    private ProxyRequestToBeSentAction processRequestRules(InterceptedRequest interceptedRequest) {
        HttpRequest modifiedRequest = interceptedRequest;
        
        for (InterceptionRule rule : activeRules.values()) {
            if (rule.type == RuleType.REQUEST && rule.isEnabled() && matchesCondition(rule, interceptedRequest)) {
                try {
                    modifiedRequest = applyRequestAction(rule, modifiedRequest);
                    rule.incrementHitCount();
                    logger.debug("Applied request rule '{}' to {}", rule.name, interceptedRequest.url());
                } catch (Exception e) {
                    logger.error("Failed to apply request rule '{}'", rule.name, e);
                }
            }
        }
        
        if (modifiedRequest != interceptedRequest) {
            return ProxyRequestToBeSentAction.continueWith(modifiedRequest);
        } else {
            return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
        }
    }
    
    /**
     * Process response interception rules
     */
    private ProxyResponseToBeSentAction processResponseRules(InterceptedResponse interceptedResponse) {
        HttpResponse modifiedResponse = interceptedResponse;
        
        for (InterceptionRule rule : activeRules.values()) {
            if (rule.type == RuleType.RESPONSE && rule.isEnabled() && matchesCondition(rule, interceptedResponse)) {
                try {
                    modifiedResponse = applyResponseAction(rule, modifiedResponse);
                    rule.incrementHitCount();
                    logger.debug("Applied response rule '{}' to {}", rule.name, interceptedResponse.initiatingRequest().url());
                } catch (Exception e) {
                    logger.error("Failed to apply response rule '{}'", rule.name, e);
                }
            }
        }
        
        if (modifiedResponse != interceptedResponse) {
            return ProxyResponseToBeSentAction.continueWith(modifiedResponse);
        } else {
            return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
        }
    }
    
    // ... [Rest of the methods remain the same as before]
    
    /**
     * Add new interception rule
     */
    public String addRule(String name, RuleType type, Map<String, Object> conditions, Map<String, Object> actions) {
        String ruleId = "rule_" + ruleIdCounter.getAndIncrement();
        InterceptionRule rule = new InterceptionRule(ruleId, name, type, conditions, actions);
        activeRules.put(ruleId, rule);
        logger.info("Added interception rule '{}' with ID {}", name, ruleId);
        return ruleId;
    }
    
    /**
     * Remove interception rule
     */
    public boolean removeRule(String ruleId) {
        InterceptionRule removed = activeRules.remove(ruleId);
        if (removed != null) {
            logger.info("Removed interception rule '{}' with ID {}", removed.name, ruleId);
            return true;
        }
        return false;
    }
    
    /**
     * Get all active rules
     */
    public Map<String, Map<String, Object>> getAllRules() {
        Map<String, Map<String, Object>> rules = new HashMap<>();
        for (Map.Entry<String, InterceptionRule> entry : activeRules.entrySet()) {
            InterceptionRule rule = entry.getValue();
            Map<String, Object> ruleInfo = new HashMap<>();
            ruleInfo.put("id", rule.id);
            ruleInfo.put("name", rule.name);
            ruleInfo.put("type", rule.type.toString());
            ruleInfo.put("enabled", rule.enabled);
            ruleInfo.put("hit_count", rule.hitCount);
            ruleInfo.put("conditions", rule.conditions);
            ruleInfo.put("actions", rule.actions);
            rules.put(entry.getKey(), ruleInfo);
        }
        return rules;
    }
    
    /**
     * Enable/disable rule
     */
    public boolean toggleRule(String ruleId, boolean enabled) {
        InterceptionRule rule = activeRules.get(ruleId);
        if (rule != null) {
            rule.enabled = enabled;
            logger.info("{} interception rule '{}'", enabled ? "Enabled" : "Disabled", rule.name);
            return true;
        }
        return false;
    }
    
    /**
     * Check if request matches rule conditions
     */
    private boolean matchesCondition(InterceptionRule rule, InterceptedRequest request) {
        try {
            Map<String, Object> conditions = rule.conditions;
            
            // Check condition type
            String conditionType = (String) conditions.get("type");
            if (conditionType == null) {
                return false;
            }
            
            switch (conditionType.toLowerCase()) {
                case "url_contains":
                    String urlPattern = (String) conditions.get("value");
                    return urlPattern != null && request.url().toLowerCase().contains(urlPattern.toLowerCase());
                    
                case "url_regex":
                    String urlRegex = (String) conditions.get("value");
                    if (urlRegex != null) {
                        Pattern pattern = Pattern.compile(urlRegex, Pattern.CASE_INSENSITIVE);
                        return pattern.matcher(request.url()).find();
                    }
                    break;
                    
                case "host_equals":
                    String hostPattern = (String) conditions.get("value");
                    if (hostPattern != null) {
                        try {
                            URL url = new URL(request.url());
                            return hostPattern.equalsIgnoreCase(url.getHost());
                        } catch (MalformedURLException e) {
                            logger.warn("Invalid URL for host matching: {}", request.url());
                        }
                    }
                    break;
                    
                case "method_equals":
                    String methodPattern = (String) conditions.get("value");
                    return methodPattern != null && methodPattern.equalsIgnoreCase(request.method());
                    
                case "header_contains":
                    String headerName = (String) conditions.get("header_name");
                    String headerValue = (String) conditions.get("value");
                    if (headerName != null && headerValue != null) {
                        return request.headers().stream()
                            .anyMatch(header -> headerName.equalsIgnoreCase(header.name()) && 
                                     header.value().toLowerCase().contains(headerValue.toLowerCase()));
                    }
                    break;
                    
                case "body_contains":
                    String bodyPattern = (String) conditions.get("value");
                    if (bodyPattern != null && request.body() != null) {
                        String body = request.body().toString();
                        return body.toLowerCase().contains(bodyPattern.toLowerCase());
                    }
                    break;
                    
                case "all":
                    return true;
                    
                case "none":
                    return false;
                    
                default:
                    logger.warn("Unknown condition type: {}", conditionType);
                    return false;
            }
            
        } catch (Exception e) {
            logger.error("Error matching request condition for rule '{}'", rule.name, e);
        }
        
        return false;
    }
    
    /**
     * Check if response matches rule conditions
     */
    private boolean matchesCondition(InterceptionRule rule, InterceptedResponse response) {
        try {
            Map<String, Object> conditions = rule.conditions;
            
            // Check condition type
            String conditionType = (String) conditions.get("type");
            if (conditionType == null) {
                return false;
            }
            
            switch (conditionType.toLowerCase()) {
                case "url_contains":
                    String urlPattern = (String) conditions.get("value");
                    return urlPattern != null && response.initiatingRequest().url().toLowerCase().contains(urlPattern.toLowerCase());
                    
                case "url_regex":
                    String urlRegex = (String) conditions.get("value");
                    if (urlRegex != null) {
                        Pattern pattern = Pattern.compile(urlRegex, Pattern.CASE_INSENSITIVE);
                        return pattern.matcher(response.initiatingRequest().url()).find();
                    }
                    break;
                    
                case "status_equals":
                    Integer statusCode = (Integer) conditions.get("value");
                    return statusCode != null && statusCode == response.statusCode();
                    
                case "header_contains":
                    String headerName = (String) conditions.get("header_name");
                    String headerValue = (String) conditions.get("value");
                    if (headerName != null && headerValue != null) {
                        return response.headers().stream()
                            .anyMatch(header -> headerName.equalsIgnoreCase(header.name()) && 
                                     header.value().toLowerCase().contains(headerValue.toLowerCase()));
                    }
                    break;
                    
                case "body_contains":
                    String bodyPattern = (String) conditions.get("value");
                    if (bodyPattern != null && response.body() != null) {
                        String body = response.body().toString();
                        return body.toLowerCase().contains(bodyPattern.toLowerCase());
                    }
                    break;
                    
                case "content_type_contains":
                    String contentTypePattern = (String) conditions.get("value");
                    if (contentTypePattern != null) {
                        return response.headers().stream()
                            .anyMatch(header -> "content-type".equalsIgnoreCase(header.name()) && 
                                     header.value().toLowerCase().contains(contentTypePattern.toLowerCase()));
                    }
                    break;
                    
                case "all":
                    return true;
                    
                case "none":
                    return false;
                    
                default:
                    logger.warn("Unknown condition type: {}", conditionType);
                    return false;
            }
            
        } catch (Exception e) {
            logger.error("Error matching response condition for rule '{}'", rule.name, e);
        }
        
        return false;
    }
    
    /**
     * Apply action to request
     */
    private HttpRequest applyRequestAction(InterceptionRule rule, HttpRequest request) {
        try {
            Map<String, Object> actions = rule.actions;
            String actionType = (String) actions.get("type");
            
            if (actionType == null) {
                return request;
            }
            
            switch (actionType.toLowerCase()) {
                case "add_header":
                    String headerName = (String) actions.get("header_name");
                    String headerValue = (String) actions.get("value");
                    if (headerName != null && headerValue != null) {
                        return request.withAddedHeader(headerName, headerValue);
                    }
                    break;
                    
                case "remove_header":
                    String removeHeaderName = (String) actions.get("header_name");
                    if (removeHeaderName != null) {
                        return request.withRemovedHeader(removeHeaderName);
                    }
                    break;
                    
                case "replace_header":
                    String replaceHeaderName = (String) actions.get("header_name");
                    String replaceHeaderValue = (String) actions.get("value");
                    if (replaceHeaderName != null && replaceHeaderValue != null) {
                        return request.withUpdatedHeader(replaceHeaderName, replaceHeaderValue);
                    }
                    break;
                    
                case "replace_body":
                    String newBody = (String) actions.get("value");
                    if (newBody != null) {
                        return request.withBody(newBody);
                    }
                    break;
                    
                case "replace_url":
                    String newUrl = (String) actions.get("value");
                    if (newUrl != null) {
                        // Create new request from URL
                        return HttpRequest.httpRequestFromUrl(newUrl)
                            .withAddedHeaders(request.headers())
                            .withBody(request.body());
                    }
                    break;
                    
                case "replace_method":
                    String newMethod = (String) actions.get("value");
                    if (newMethod != null) {
                        return request.withMethod(newMethod);
                    }
                    break;
                    
                case "replace_parameter":
                    String paramName = (String) actions.get("param_name");
                    String paramValue = (String) actions.get("value");
                    if (paramName != null && paramValue != null) {
                        return request.withParameter(HttpParameter.urlParameter(paramName, paramValue));
                    }
                    break;
                    
                case "drop":
                    // Return null to drop the request (but this would need special handling)
                    logger.info("Dropping request due to rule '{}'", rule.name);
                    return request; // For now, continue with request but log
                    
                case "intercept":
                    // Manual interception - would require UI integration
                    logger.info("Request intercepted by rule '{}' - URL: {}", rule.name, request.url());
                    return request;
                    
                default:
                    logger.warn("Unknown action type: {}", actionType);
                    break;
            }
            
        } catch (Exception e) {
            logger.error("Error applying request action for rule '{}'", rule.name, e);
        }
        
        return request;
    }
    
    /**
     * Apply action to response
     */
    private HttpResponse applyResponseAction(InterceptionRule rule, HttpResponse response) {
        try {
            Map<String, Object> actions = rule.actions;
            String actionType = (String) actions.get("type");
            
            if (actionType == null) {
                return response;
            }
            
            switch (actionType.toLowerCase()) {
                case "add_header":
                    String headerName = (String) actions.get("header_name");
                    String headerValue = (String) actions.get("value");
                    if (headerName != null && headerValue != null) {
                        return response.withAddedHeader(headerName, headerValue);
                    }
                    break;
                    
                case "remove_header":
                    String removeHeaderName = (String) actions.get("header_name");
                    if (removeHeaderName != null) {
                        return response.withRemovedHeader(removeHeaderName);
                    }
                    break;
                    
                case "replace_header":
                    String replaceHeaderName = (String) actions.get("header_name");
                    String replaceHeaderValue = (String) actions.get("value");
                    if (replaceHeaderName != null && replaceHeaderValue != null) {
                        return response.withUpdatedHeader(replaceHeaderName, replaceHeaderValue);
                    }
                    break;
                    
                case "replace_body":
                    String newBody = (String) actions.get("value");
                    if (newBody != null) {
                        return response.withBody(newBody);
                    }
                    break;
                    
                case "replace_status":
                    Integer newStatus = (Integer) actions.get("value");
                    String newReason = (String) actions.get("reason");
                    if (newStatus != null) {
                        if (newReason != null) {
                            return response.withStatusCode(newStatus.shortValue()).withReasonPhrase(newReason);
                        } else {
                            return response.withStatusCode(newStatus.shortValue());
                        }
                    }
                    break;
                    
                case "body_replace_text":
                    String findText = (String) actions.get("find");
                    String replaceText = (String) actions.get("replace");
                    if (findText != null && replaceText != null && response.body() != null) {
                        String currentBody = response.body().toString();
                        String modifiedBody = currentBody.replace(findText, replaceText);
                        return response.withBody(modifiedBody);
                    }
                    break;
                    
                case "body_replace_regex":
                    String findRegex = (String) actions.get("find");
                    String replaceRegex = (String) actions.get("replace");
                    if (findRegex != null && replaceRegex != null && response.body() != null) {
                        String currentBody = response.body().toString();
                        String modifiedBody = currentBody.replaceAll(findRegex, replaceRegex);
                        return response.withBody(modifiedBody);
                    }
                    break;
                    
                case "drop":
                    // Return null to drop the response (but this would need special handling)
                    logger.info("Dropping response due to rule '{}'", rule.name);
                    return response; // For now, continue with response but log
                    
                case "intercept":
                    // Manual interception - would require UI integration
                    logger.info("Response intercepted by rule '{}' - Status: {}", rule.name, response.statusCode());
                    return response;
                    
                default:
                    logger.warn("Unknown action type: {}", actionType);
                    break;
            }
            
        } catch (Exception e) {
            logger.error("Error applying response action for rule '{}'", rule.name, e);
        }
        
        return response;
    }
    
    /**
     * Shutdown service and unregister handlers
     */
    public void shutdown() {
        for (Registration registration : registrations) {
            registration.deregister();
        }
        activeRules.clear();
        logger.info("Proxy interception service shutdown completed");
    }
    
    /**
     * Rule types
     */
    public enum RuleType {
        REQUEST, RESPONSE
    }
    
    /**
     * Interception rule class
     */
    private static class InterceptionRule {
        final String id;
        final String name;
        final RuleType type;
        final Map<String, Object> conditions;
        final Map<String, Object> actions;
        boolean enabled = true;
        long hitCount = 0;
        
        InterceptionRule(String id, String name, RuleType type, Map<String, Object> conditions, Map<String, Object> actions) {
            this.id = id;
            this.name = name;
            this.type = type;
            this.conditions = conditions;
            this.actions = actions;
        }
        
        boolean isEnabled() {
            return enabled;
        }
        
        void incrementHitCount() {
            hitCount++;
        }
    }
}