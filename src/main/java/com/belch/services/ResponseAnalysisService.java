package com.belch.services;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.ResponseKeywordsAnalyzer;
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import com.belch.database.DatabaseService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Service for analyzing HTTP responses using Montoya API capabilities
 * Provides response variations analysis and keyword-based analysis
 */
public class ResponseAnalysisService {
    
    private static final Logger logger = LoggerFactory.getLogger(ResponseAnalysisService.class);
    
    private final MontoyaApi api;
    private final DatabaseService databaseService;
    
    public ResponseAnalysisService(MontoyaApi api, DatabaseService databaseService) {
        this.api = api;
        this.databaseService = databaseService;
    }
    
    /**
     * Analyze variations between multiple responses
     */
    public Map<String, Object> analyzeResponseVariations(List<Long> requestIds) {
        Map<String, Object> result = new HashMap<>();
        List<String> errors = new ArrayList<>();
        
        try {
            List<HttpResponse> responses = new ArrayList<>();
            
            // Fetch responses from database using batch method
            List<Map<String, Object>> records = databaseService.getTrafficByIds(requestIds);
            for (Map<String, Object> record : records) {
                try {
                    if (record != null) {
                        String responseBody = (String) record.get("response_body");
                        String responseHeaders = (String) record.get("response_headers");
                        Integer statusCode = (Integer) record.get("status_code");
                        
                        // Create HttpResponse from stored data (include responses with empty bodies)
                        if (responseBody == null) {
                            responseBody = "";
                        }
                        HttpResponse response = HttpResponse.httpResponse(responseBody);
                        responses.add(response);
                    }
                } catch (Exception e) {
                    errors.add("Failed to process record: " + e.getMessage());
                    logger.warn("Failed to process record for analysis", e);
                }
            }
            
            if (responses.size() < 2) {
                result.put("error", "At least 2 responses required for variation analysis");
                return result;
            }
            
            // Create variations analyzer (2025.8+)
            ResponseVariationsAnalyzer analyzer = api.http().createResponseVariationsAnalyzer();
            
            // Update analyzer with all responses
            for (HttpResponse response : responses) {
                analyzer.updateWith(response);
            }
            
            // Get variant attributes
            Set<AttributeType> variants = analyzer.variantAttributes();
            
            result.put("total_responses_analyzed", responses.size());
            result.put("variant_attributes", variants.stream()
                .map(AttributeType::toString)
                .collect(Collectors.toList()));
            result.put("has_variations", !variants.isEmpty());
            
            // Categorize variations
            Map<String, List<String>> categorizedVariations = new HashMap<>();
            for (AttributeType attr : variants) {
                String category = categorizeAttribute(attr);
                categorizedVariations.computeIfAbsent(category, k -> new ArrayList<>())
                    .add(attr.toString());
            }
            result.put("variations_by_category", categorizedVariations);
            
            // Analysis summary
            Map<String, Object> summary = new HashMap<>();
            summary.put("significant_differences", variants.size() > 0);
            summary.put("potential_authentication_bypass", variants.contains(AttributeType.STATUS_CODE) || 
                       variants.contains(AttributeType.CONTENT_LENGTH) ||
                       variants.contains(AttributeType.BODY_CONTENT));
            summary.put("response_inconsistencies", variants.contains(AttributeType.CONTENT_TYPE) ||
                       variants.contains(AttributeType.BODY_CONTENT));
            result.put("security_analysis", summary);
            
            if (!errors.isEmpty()) {
                result.put("warnings", errors);
            }
            
            logger.info("Response variation analysis completed: {} responses, {} variants found", 
                       responses.size(), variants.size());
            
        } catch (Exception e) {
            logger.error("Response variation analysis failed", e);
            result.put("error", "Analysis failed: " + e.getMessage());
        }
        
        return result;
    }
    
    /**
     * Analyze responses for specific keywords
     */
    public Map<String, Object> analyzeResponseKeywords(List<Long> requestIds, List<String> keywords, boolean caseSensitive) {
        Map<String, Object> result = new HashMap<>();
        List<String> errors = new ArrayList<>();
        
        try {
            List<HttpResponse> responses = new ArrayList<>();
            Map<Long, Map<String, Object>> requestMetadata = new HashMap<>();
            
            // Fetch responses from database using batch method
            List<Map<String, Object>> records = databaseService.getTrafficByIds(requestIds);
            for (int i = 0; i < records.size() && i < requestIds.size(); i++) {
                try {
                    Map<String, Object> record = records.get(i);
                    Long requestId = requestIds.get(i);
                    
                    if (record != null) {
                        String responseBody = (String) record.get("response_body");
                        String responseHeaders = (String) record.get("response_headers");
                        Integer statusCode = (Integer) record.get("status_code");
                        
                        // Create HttpResponse and store metadata
                        if (responseBody == null) {
                            responseBody = "";
                        }
                        HttpResponse response = HttpResponse.httpResponse(responseBody);
                        responses.add(response);
                        requestMetadata.put(requestId, record);
                    }
                } catch (Exception e) {
                    errors.add("Failed to process record: " + e.getMessage());
                    logger.warn("Failed to process record for keyword analysis", e);
                }
            }
            
            if (responses.isEmpty()) {
                result.put("error", "No valid responses found for analysis");
                return result;
            }
            
            // Create keyword analyzer (2025.8+)
            ResponseKeywordsAnalyzer analyzer = api.http().createResponseKeywordsAnalyzer(keywords);
            
            // Analyze each response
            List<Map<String, Object>> analysisResults = new ArrayList<>();
            
            // Build list of request IDs that actually have responses
            List<Long> validRequestIds = new ArrayList<>();
            for (Long requestId : requestIds) {
                if (requestMetadata.containsKey(requestId)) {
                    validRequestIds.add(requestId);
                }
            }
            
            for (int i = 0; i < responses.size() && i < validRequestIds.size(); i++) {
                HttpResponse response = responses.get(i);
                Long requestId = validRequestIds.get(i);
                Map<String, Object> metadata = requestMetadata.get(requestId);
                
                Map<String, Object> responseAnalysis = new HashMap<>();
                
                // Update analyzer with response
                analyzer.updateWith(response);
                
                // Get keyword matches using manual search
                List<String> foundKeywords = findKeywordsInResponse(response, keywords, caseSensitive);
                
                responseAnalysis.put("request_id", requestId);
                responseAnalysis.put("url", metadata != null ? metadata.get("url") : "unknown");
                responseAnalysis.put("status_code", metadata != null ? metadata.get("status_code") : 0);
                responseAnalysis.put("matched_keywords", foundKeywords);
                responseAnalysis.put("match_count", foundKeywords.size());
                responseAnalysis.put("has_sensitive_data", !foundKeywords.isEmpty());
                
                analysisResults.add(responseAnalysis);
            }
            
            // Summary statistics
            int totalMatches = analysisResults.stream()
                .mapToInt(r -> ((List<String>) r.get("matched_keywords")).size())
                .sum();
            
            int responsesWithMatches = (int) analysisResults.stream()
                .filter(r -> ((List<String>) r.get("matched_keywords")).size() > 0)
                .count();
            
            Map<String, Object> summary = new HashMap<>();
            summary.put("total_responses_analyzed", responses.size());
            summary.put("responses_with_matches", responsesWithMatches);
            summary.put("total_keyword_matches", totalMatches);
            summary.put("match_percentage", responses.size() > 0 ? 
                (responsesWithMatches * 100.0) / responses.size() : 0);
            
            // Keyword frequency
            Map<String, Integer> keywordFrequency = new HashMap<>();
            for (Map<String, Object> analysis : analysisResults) {
                List<String> matches = (List<String>) analysis.get("matched_keywords");
                for (String keyword : matches) {
                    keywordFrequency.merge(keyword, 1, Integer::sum);
                }
            }
            
            result.put("summary", summary);
            result.put("keyword_frequency", keywordFrequency);
            result.put("detailed_results", analysisResults);
            result.put("searched_keywords", keywords);
            result.put("case_sensitive", caseSensitive);
            
            if (!errors.isEmpty()) {
                result.put("warnings", errors);
            }
            
            logger.info("Keyword analysis completed: {} responses analyzed, {} matches found", 
                       responses.size(), totalMatches);
            
        } catch (Exception e) {
            logger.error("Keyword analysis failed", e);
            result.put("error", "Analysis failed: " + e.getMessage());
        }
        
        return result;
    }
    
    /**
     * Helper method to find keywords in response
     */
    private List<String> findKeywordsInResponse(HttpResponse response, List<String> keywords, boolean caseSensitive) {
        List<String> foundKeywords = new ArrayList<>();
        String content = response.bodyToString();
        String headers = response.headers().toString();
        
        // Combine body and headers for searching
        String searchText = content + " " + headers;
        
        if (!caseSensitive) {
            searchText = searchText.toLowerCase();
        }
        
        for (String keyword : keywords) {
            String searchKeyword = caseSensitive ? keyword : keyword.toLowerCase();
            if (searchText.contains(searchKeyword)) {
                foundKeywords.add(keyword);
            }
        }
        
        return foundKeywords;
    }
    
    /**
     * Parse headers string into list format expected by HttpResponse
     */
    private List<String> parseHeaders(String headersString) {
        if (headersString == null || headersString.trim().isEmpty()) {
            return new ArrayList<>();
        }
        
        return Arrays.asList(headersString.split("\\r?\\n"));
    }
    
    /**
     * Categorize attribute types for better reporting
     */
    private String categorizeAttribute(AttributeType attributeType) {
        switch (attributeType) {
            case STATUS_CODE:
                return "HTTP_STATUS";
            case CONTENT_TYPE:
                return "HTTP_HEADERS";
            case BODY_CONTENT:
                return "RESPONSE_BODY";
            case CONTENT_LENGTH:
                return "CONTENT_PROPERTIES";
            default:
                return "OTHER";
        }
    }
}