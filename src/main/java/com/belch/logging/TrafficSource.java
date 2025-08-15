package com.belch.logging;

/**
 * Enum defining all possible traffic sources for tracking and analytics.
 * Used to identify where traffic originated from within Burp Suite.
 * 
 * @author Charlie Campbell
 * @version 1.0.0
 */
public enum TrafficSource {
    PROXY("PROXY"),           // Traffic captured from Burp's proxy
    REPEATER("REPEATER"),     // Traffic from Burp's repeater tool
    INTRUDER("INTRUDER"),     // Traffic from Burp's intruder tool
    SCANNER("SCANNER"),       // Traffic from Burp's scanner
    SEQUENCER("SEQUENCER"),   // Traffic from Burp's sequencer
    COMPARER("COMPARER"),     // Traffic from Burp's comparer
    DECODER("DECODER"),       // Traffic from Burp's decoder
    IMPORTED("IMPORTED"),     // Traffic imported from existing saves/history
    MANUAL("MANUAL"),         // Manually created/injected traffic
    API("API"),               // Traffic generated via REST API calls
    EXTENSION("EXTENSION"),   // Traffic from other Burp extensions
    UNKNOWN("UNKNOWN");       // Fallback for unidentified sources
    
    private final String value;
    
    TrafficSource(String value) {
        this.value = value;
    }
    
    public String getValue() {
        return value;
    }
    
    @Override
    public String toString() {
        return value;
    }
    
    /**
     * Parse traffic source from string value.
     * 
     * @param value The string representation of the traffic source
     * @return The corresponding TrafficSource enum, or UNKNOWN if not found
     */
    public static TrafficSource fromString(String value) {
        if (value == null) return UNKNOWN;
        
        for (TrafficSource source : values()) {
            if (source.value.equalsIgnoreCase(value)) {
                return source;
            }
        }
        return UNKNOWN;
    }
} 