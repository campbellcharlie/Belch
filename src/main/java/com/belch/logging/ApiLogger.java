package com.belch.logging;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.core.ConsoleAppender;
import org.slf4j.LoggerFactory;

/**
 * Utility class for configuring and managing logging for the Belch - Burp Suite REST API Extension.
 * This class sets up the logging framework with appropriate patterns and levels.
 * 
 * @author Charlie Campbell
 * @version 1.0.0
 */
public class ApiLogger {
    
    private static final String LOG_PATTERN = "%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n";
    private static boolean initialized = false;
    
    /**
     * Private constructor to prevent instantiation.
     */
    private ApiLogger() {
        // Utility class
    }
    
    /**
     * Initializes the logging configuration for the extension.
     * This method sets up console logging with a standardized format.
     */
    public static synchronized void initialize() {
        if (initialized) {
            return;
        }
        
        LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
        
        // Create console appender
        ConsoleAppender consoleAppender = new ConsoleAppender<>();
        consoleAppender.setContext(context);
        consoleAppender.setName("console");
        
        // Create and configure pattern layout encoder
        PatternLayoutEncoder encoder = new PatternLayoutEncoder();
        encoder.setContext(context);
        encoder.setPattern(LOG_PATTERN);
        encoder.start();
        
        consoleAppender.setEncoder(encoder);
        consoleAppender.start();
        
        // Get root logger and configure
        Logger rootLogger = context.getLogger(Logger.ROOT_LOGGER_NAME);
        rootLogger.addAppender(consoleAppender);
        rootLogger.setLevel(Level.INFO);
        
        // Set specific logger levels
        context.getLogger("com.belch").setLevel(Level.DEBUG);
        context.getLogger("io.javalin").setLevel(Level.INFO);
        context.getLogger("org.eclipse.jetty").setLevel(Level.WARN);
        
        initialized = true;
        
        org.slf4j.Logger logger = LoggerFactory.getLogger(ApiLogger.class);
        logger.info("API Logger initialized successfully");
    }
    
    /**
     * Sets the verbose logging mode.
     * 
     * @param verbose true to enable verbose logging, false otherwise
     */
    public static void setVerbose(boolean verbose) {
        LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
        Logger rootLogger = context.getLogger("com.belch");
        
        if (verbose) {
            rootLogger.setLevel(Level.DEBUG);
            LoggerFactory.getLogger(ApiLogger.class).info("Verbose logging enabled");
        } else {
            rootLogger.setLevel(Level.INFO);
            LoggerFactory.getLogger(ApiLogger.class).info("Verbose logging disabled");
        }
    }
    
    /**
     * Gets a logger instance for the specified class.
     * 
     * @param clazz The class to get the logger for
     * @return Logger instance
     */
    public static org.slf4j.Logger getLogger(Class<?> clazz) {
        return LoggerFactory.getLogger(clazz);
    }
    
    /**
     * Gets a logger instance for the specified name.
     * 
     * @param name The logger name
     * @return Logger instance
     */
    public static org.slf4j.Logger getLogger(String name) {
        return LoggerFactory.getLogger(name);
    }
} 