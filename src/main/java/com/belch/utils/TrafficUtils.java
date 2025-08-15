package com.belch.utils;

import java.util.Map;
import java.util.stream.Collectors;

public class TrafficUtils {
    public static String mapToString(Map<String, String> map) {
        if (map == null || map.isEmpty()) {
            return "";
        }
        return map.entrySet().stream()
                .map(entry -> entry.getKey() + ": " + entry.getValue())
                .collect(Collectors.joining("\n"));
    }
} 