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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

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
                return processResponseRules(interceptedResponse);
            }
            
            @Override
            public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
                return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
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
    private ProxyResponseReceivedAction processResponseRules(InterceptedResponse interceptedResponse) {
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
            return ProxyResponseReceivedAction.continueWith(modifiedResponse);
        } else {
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
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
    
    // Simplified implementations for demonstration
    private boolean matchesCondition(InterceptionRule rule, InterceptedRequest request) {
        return true; // Implement actual condition matching
    }
    
    private boolean matchesCondition(InterceptionRule rule, InterceptedResponse response) {
        return true; // Implement actual condition matching
    }
    
    private HttpRequest applyRequestAction(InterceptionRule rule, HttpRequest request) {
        return request; // Implement actual request modification
    }
    
    private HttpResponse applyResponseAction(InterceptionRule rule, HttpResponse response) {
        return response; // Implement actual response modification
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