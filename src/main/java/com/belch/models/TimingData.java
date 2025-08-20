package com.belch.models;

/**
 * Timing data captured from Montoya API responses
 */
public class TimingData {
    private final Long dnsResolutionTime;
    private final Long connectionTime;
    private final Long tlsNegotiationTime;
    private final Long requestTime;
    private final Long responseTime;
    private final Long totalTime;
    
    public TimingData(Long dnsResolutionTime, Long connectionTime, Long tlsNegotiationTime,
                     Long requestTime, Long responseTime, Long totalTime) {
        this.dnsResolutionTime = dnsResolutionTime;
        this.connectionTime = connectionTime;
        this.tlsNegotiationTime = tlsNegotiationTime;
        this.requestTime = requestTime;
        this.responseTime = responseTime;
        this.totalTime = totalTime;
    }
    
    // Factory method for creating from Montoya API TimingData (2025.8+)
    public static TimingData fromMontoyaTimingData(burp.api.montoya.http.handler.TimingData montoyaTimingData) {
        if (montoyaTimingData == null) {
            return null;
        }
        
        return new TimingData(
            null, // DNS resolution not available in this TimingData interface
            null, // Connection time not available
            null, // TLS negotiation not available
            null, // Request time not available
            montoyaTimingData.timeBetweenRequestSentAndStartOfResponse() != null ? 
                montoyaTimingData.timeBetweenRequestSentAndStartOfResponse().toMillis() : null,
            montoyaTimingData.timeBetweenRequestSentAndEndOfResponse() != null ? 
                montoyaTimingData.timeBetweenRequestSentAndEndOfResponse().toMillis() : null
        );
    }
    
    // Factory method for creating basic timing data
    public static TimingData createBasicTiming(long totalTime) {
        return new TimingData(null, null, null, null, null, totalTime);
    }
    
    // Factory method for creating empty timing data
    public static TimingData createEmpty() {
        return new TimingData(null, null, null, null, null, null);
    }
    
    // Getters
    public Long getDnsResolutionTime() { return dnsResolutionTime; }
    public Long getConnectionTime() { return connectionTime; }
    public Long getTlsNegotiationTime() { return tlsNegotiationTime; }
    public Long getRequestTime() { return requestTime; }
    public Long getResponseTime() { return responseTime; }
    public Long getTotalTime() { return totalTime; }
    
    // Utility methods
    public boolean hasAnyTiming() {
        return dnsResolutionTime != null || connectionTime != null || tlsNegotiationTime != null ||
               requestTime != null || responseTime != null || totalTime != null;
    }
    
    @Override
    public String toString() {
        return String.format("TimingData{dns=%dms, conn=%dms, tls=%dms, req=%dms, resp=%dms, total=%dms}",
                dnsResolutionTime, connectionTime, tlsNegotiationTime, 
                requestTime, responseTime, totalTime);
    }
}