package com.belch.services;

import burp.api.montoya.MontoyaApi;
import com.belch.database.DatabaseService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Optimized service layer that intelligently chooses between database queries
 * and Montoya API calls based on performance characteristics and data freshness.
 * 
 * Key optimizations:
 * - Uses database for historical data queries (faster than API enumeration)
 * - Uses API for live/current state queries (more accurate than cache)
 * - Implements intelligent caching to reduce API overhead
 * - Batches operations when possible for better performance
 * 
 * @author Charlie Campbell
 * @version 1.0.0
 */
public class OptimizedApiService {
    
    private static final Logger logger = LoggerFactory.getLogger(OptimizedApiService.class);
    
    private final MontoyaApi api;
    private final DatabaseService databaseService;
    
    // Performance metrics
    private final AtomicLong dbQueryCount = new AtomicLong(0);
    private final AtomicLong apiCallCount = new AtomicLong(0);
    private final AtomicLong cacheHitCount = new AtomicLong(0);
    
    // In-memory caches for frequently accessed data
    private final Map<String, Object> projectConfigCache = new ConcurrentHashMap<>();
    private volatile long projectConfigCacheTime = 0;
    private static final long PROJECT_CONFIG_CACHE_TTL = 60000; // 1 minute
    
    public OptimizedApiService(MontoyaApi api, DatabaseService databaseService) {
        this.api = api;
        this.databaseService = databaseService;
    }
    
    /**
     * Gets proxy history with optimal data source selection.
     * Uses database for historical queries, API for current state verification.
     */
    public List<Map<String, Object>> getProxyHistory(Map<String, String> searchParams) {
        dbQueryCount.incrementAndGet();
        
        // Always use database for historical traffic - it's much faster than API enumeration
        List<Map<String, Object>> results = databaseService.searchTraffic(searchParams);
        
        logger.debug("Retrieved {} proxy history records from database", results.size());
        return results;
    }
    
    /**
     * Performs optimized scope checking with multi-level caching.
     * 1. Check database scope cache first (fastest)
     * 2. Check in-memory cache for project config
     * 3. Fall back to API calls when necessary
     */
    public Map<String, Boolean> optimizedScopeCheck(List<String> urls) {
        if (urls.isEmpty()) {
            return new HashMap<>();
        }
        
        Map<String, Boolean> results = new HashMap<>();
        List<String> uncachedUrls = new ArrayList<>();
        
        // Step 1: Check database scope cache
        for (String url : urls) {
            Map<String, Object> cached = databaseService.getCachedScopeResult(url);
            if (cached != null) {
                results.put(url, (Boolean) cached.get("inScope"));
                cacheHitCount.incrementAndGet();
            } else {
                uncachedUrls.add(url);
            }
        }
        
        // Step 2: For uncached URLs, use API and cache results
        if (!uncachedUrls.isEmpty()) {
            for (String url : uncachedUrls) {
                try {
                    apiCallCount.incrementAndGet();
                    boolean inScope = api.scope().isInScope(url);
                    results.put(url, inScope);
                    databaseService.cacheScopeResult(url, inScope);
                } catch (Exception e) {
                    logger.warn("Failed to check scope for URL {}: {}", url, e.getMessage());
                    results.put(url, false); // Conservative default
                }
            }
        }
        
        logger.debug("Scope check: {} URLs, {} cache hits, {} API calls", 
                    urls.size(), cacheHitCount.get(), uncachedUrls.size());
        
        return results;
    }
    
    /**
     * Gets current project scope configuration with intelligent caching.
     * Uses cache for repeated requests, API for updates.
     */
    public Map<String, Object> getCurrentScopeConfiguration(boolean forceRefresh) {
        long currentTime = System.currentTimeMillis();
        
        // Check cache first unless force refresh requested
        if (!forceRefresh && 
            !projectConfigCache.isEmpty() && 
            (currentTime - projectConfigCacheTime) < PROJECT_CONFIG_CACHE_TTL) {
            
            cacheHitCount.incrementAndGet();
            logger.debug("Returning cached project scope configuration");
            return new HashMap<>(projectConfigCache);
        }
        
        // Fetch fresh data from API
        try {
            apiCallCount.incrementAndGet();
            String projectConfigJson = api.burpSuite().exportProjectOptionsAsJson();
            
            // Parse and cache the result
            Map<String, Object> config = parseProjectConfig(projectConfigJson);
            projectConfigCache.clear();
            projectConfigCache.putAll(config);
            projectConfigCacheTime = currentTime;
            
            logger.debug("Refreshed project scope configuration cache");
            return new HashMap<>(config);
            
        } catch (Exception e) {
            logger.error("Failed to get project configuration", e);
            
            // Return cached data if available, even if stale
            if (!projectConfigCache.isEmpty()) {
                logger.warn("Returning stale cached project configuration due to API error");
                return new HashMap<>(projectConfigCache);
            }
            
            throw new RuntimeException("Failed to get project configuration", e);
        }
    }
    
    /**
     * Gets traffic statistics optimized for database queries.
     * Database is always faster than API for aggregate statistics.
     */
    public Map<String, Object> getTrafficStatistics(Map<String, String> searchParams) {
        dbQueryCount.incrementAndGet();
        
        // Use database for all statistical queries - much faster than API enumeration
        Map<String, Object> stats = databaseService.getTrafficStats(searchParams);
        
        // Add some live API data for current session context
        try {
            apiCallCount.incrementAndGet();
            stats.put("burp_suite_version", api.burpSuite().version());
            stats.put("current_session_active", true);
        } catch (Exception e) {
            logger.debug("Failed to add live API context to statistics", e);
        }
        
        return stats;
    }
    
    /**
     * Optimized proxy history import that handles large datasets efficiently.
     */
    public int importProxyHistoryOptimized(String sessionTag) {
        apiCallCount.incrementAndGet();
        
        // Use database service which is optimized for bulk inserts
        return databaseService.importExistingProxyHistory(api, sessionTag);
    }
    
    /**
     * Gets performance metrics for monitoring and optimization.
     */
    public Map<String, Object> getPerformanceMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        
        long totalOperations = dbQueryCount.get() + apiCallCount.get();
        double cacheHitRate = totalOperations > 0 ? 
            (cacheHitCount.get() * 100.0 / totalOperations) : 0.0;
        
        metrics.put("database_queries", dbQueryCount.get());
        metrics.put("api_calls", apiCallCount.get());
        metrics.put("cache_hits", cacheHitCount.get());
        metrics.put("total_operations", totalOperations);
        metrics.put("cache_hit_rate_percent", String.format("%.1f", cacheHitRate));
        metrics.put("db_vs_api_ratio", String.format("%.1f", 
            apiCallCount.get() > 0 ? (dbQueryCount.get() * 1.0 / apiCallCount.get()) : 0.0));
        
        // Add database status
        metrics.put("database_initialized", databaseService.isInitialized());
        
        // Add cache status
        metrics.put("project_config_cache_size", projectConfigCache.size());
        metrics.put("project_config_cache_age_ms", System.currentTimeMillis() - projectConfigCacheTime);
        
        return metrics;
    }
    
    /**
     * Clears all caches to force fresh data retrieval.
     */
    public void clearCaches() {
        projectConfigCache.clear();
        projectConfigCacheTime = 0;
        logger.info("All caches cleared");
    }
    
    /**
     * Provides recommendations for optimal API usage based on metrics.
     */
    public List<String> getOptimizationRecommendations() {
        List<String> recommendations = new ArrayList<>();
        
        long totalOps = dbQueryCount.get() + apiCallCount.get();
        if (totalOps < 10) {
            recommendations.add("Not enough operations yet for meaningful recommendations");
            return recommendations;
        }
        
        double cacheHitRate = (cacheHitCount.get() * 100.0 / totalOps);
        if (cacheHitRate < 50) {
            recommendations.add("Low cache hit rate (" + String.format("%.1f", cacheHitRate) + "%) - consider increasing cache TTL");
        }
        
        double dbRatio = (dbQueryCount.get() * 100.0 / totalOps);
        if (dbRatio < 70) {
            recommendations.add("High API usage (" + String.format("%.1f", 100 - dbRatio) + "%) - consider using database for historical queries");
        }
        
        if (apiCallCount.get() > 100) {
            recommendations.add("High API call count - consider batching operations and improving caching");
        }
        
        if (recommendations.isEmpty()) {
            recommendations.add("Performance is optimal - good balance of database and API usage");
        }
        
        return recommendations;
    }
    
    /**
     * Parses project configuration JSON and extracts relevant scope information.
     */
    private Map<String, Object> parseProjectConfig(String configJson) {
        // This would typically use Jackson ObjectMapper, but keeping it simple for now
        Map<String, Object> result = new HashMap<>();
        result.put("raw_config", configJson);
        result.put("parsed_at", System.currentTimeMillis());
        
        // Add basic parsing logic here if needed
        // For now, just store the raw config for the caller to parse
        
        return result;
    }
} 