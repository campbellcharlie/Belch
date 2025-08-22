package com.belch.handlers;

import com.belch.services.BCheckService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.Javalin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * BChecks API Routes
 * 
 * Provides REST API endpoints for BChecks management:
 * - Import BCheck scripts
 * - List and manage BChecks
 * - Security validation
 * - BCheck statistics
 */
public class BCheckRouteRegistrar {
    
    private static final Logger logger = LoggerFactory.getLogger(BCheckRouteRegistrar.class);
    
    private final BCheckService bCheckService;
    private final ObjectMapper objectMapper;
    
    public BCheckRouteRegistrar(BCheckService bCheckService) {
        this.bCheckService = bCheckService;
        this.objectMapper = new ObjectMapper();
    }
    
    /**
     * Register BCheck-related routes.
     */
    public void registerRoutes(Javalin app) {
        
        // GET /bchecks - List all BChecks
        app.get("/bchecks", ctx -> {
            Map<String, Object> bchecks = bCheckService.getBChecks();
            ctx.json(bchecks);
        });
        
        // POST /bchecks - Import a new BCheck
        app.post("/bchecks", ctx -> {
            try {
                Map<String, Object> requestBody = objectMapper.readValue(ctx.body(), Map.class);
                
                String script = (String) requestBody.get("script");
                if (script == null || script.trim().isEmpty()) {
                    ctx.status(400).json(Map.of(
                        "error", "Missing required field",
                        "message", "script field is required"
                    ));
                    return;
                }
                
                String name = (String) requestBody.getOrDefault("name", "Unnamed BCheck");
                String description = (String) requestBody.getOrDefault("description", "");
                Boolean enabled = (Boolean) requestBody.getOrDefault("enabled", true);
                
                Map<String, Object> result = bCheckService.importBCheck(script, name, description, enabled);
                
                if ((Boolean) result.get("success")) {
                    ctx.status(201).json(result);
                } else {
                    ctx.status(400).json(result);
                }
                
            } catch (Exception e) {
                logger.error("Failed to import BCheck", e);
                ctx.status(500).json(Map.of(
                    "error", "Internal server error",
                    "message", "Failed to import BCheck: " + e.getMessage()
                ));
            }
        });
        
        // POST /bchecks/import-file - Import BCheck from file
        app.post("/bchecks/import-file", ctx -> {
            try {
                Map<String, Object> requestBody = objectMapper.readValue(ctx.body(), Map.class);
                
                String filePath = (String) requestBody.get("file_path");
                if (filePath == null || filePath.trim().isEmpty()) {
                    ctx.status(400).json(Map.of(
                        "error", "Missing required field",
                        "message", "file_path field is required"
                    ));
                    return;
                }
                
                String name = (String) requestBody.get("name");
                String description = (String) requestBody.getOrDefault("description", "");
                Boolean enabled = (Boolean) requestBody.getOrDefault("enabled", true);
                
                Map<String, Object> result = bCheckService.importBCheckFromFile(filePath, name, description, enabled);
                
                if ((Boolean) result.get("success")) {
                    ctx.status(201).json(result);
                } else {
                    ctx.status(400).json(result);
                }
                
            } catch (Exception e) {
                logger.error("Failed to import BCheck from file", e);
                ctx.status(500).json(Map.of(
                    "error", "Internal server error",
                    "message", "Failed to import BCheck from file: " + e.getMessage()
                ));
            }
        });
        
        // GET /bchecks/{bcheckId} - Get specific BCheck details
        app.get("/bchecks/{bcheckId}", ctx -> {
            String bcheckId = ctx.pathParam("bcheckId");
            Map<String, Object> result = bCheckService.getBCheck(bcheckId);
            
            if ((Boolean) result.get("success")) {
                ctx.json(result);
            } else {
                ctx.status(404).json(result);
            }
        });
        
        // DELETE /bchecks/{bcheckId} - Delete a BCheck
        app.delete("/bchecks/{bcheckId}", ctx -> {
            String bcheckId = ctx.pathParam("bcheckId");
            Map<String, Object> result = bCheckService.deleteBCheck(bcheckId);
            
            if ((Boolean) result.get("success")) {
                ctx.json(result);
            } else {
                ctx.status(404).json(result);
            }
        });
        
        // POST /bchecks/validate - Validate BCheck script security
        app.post("/bchecks/validate", ctx -> {
            try {
                Map<String, Object> requestBody = objectMapper.readValue(ctx.body(), Map.class);
                
                String script = (String) requestBody.get("script");
                if (script == null || script.trim().isEmpty()) {
                    ctx.status(400).json(Map.of(
                        "error", "Missing required field",
                        "message", "script field is required"
                    ));
                    return;
                }
                
                Map<String, Object> validation = bCheckService.validateBCheckSecurity(script);
                ctx.json(validation);
                
            } catch (Exception e) {
                logger.error("Failed to validate BCheck script", e);
                ctx.status(500).json(Map.of(
                    "error", "Internal server error",
                    "message", "Failed to validate script: " + e.getMessage()
                ));
            }
        });
        
        // GET /bchecks/stats - Get BCheck statistics
        app.get("/bchecks/stats", ctx -> {
            Map<String, Object> stats = bCheckService.getBCheckStats();
            ctx.json(stats);
        });
        
        // GET /bchecks/templates - Get BCheck script templates
        app.get("/bchecks/templates", ctx -> {
            Map<String, Object> templates = getBCheckTemplates();
            ctx.json(templates);
        });
        
        // GET /bchecks/security-rules - Get security validation rules
        app.get("/bchecks/security-rules", ctx -> {
            Map<String, Object> rules = getSecurityRules();
            ctx.json(rules);
        });
        
        logger.info("BCheck routes registered successfully");
    }
    
    /**
     * Get BCheck script templates.
     */
    private Map<String, Object> getBCheckTemplates() {
        Map<String, Object> templates = new HashMap<>();
        
        Map<String, Object> basicTemplate = new HashMap<>();
        basicTemplate.put("name", "Basic BCheck Template");
        basicTemplate.put("description", "Simple template for creating a basic BCheck");
        basicTemplate.put("script", getBCheckBasicTemplate());
        
        Map<String, Object> httpTemplate = new HashMap<>();
        httpTemplate.put("name", "HTTP Request BCheck Template");
        httpTemplate.put("description", "Template for BChecks that analyze HTTP requests");
        httpTemplate.put("script", getBCheckHttpTemplate());
        
        Map<String, Object> responseTemplate = new HashMap<>();
        responseTemplate.put("name", "HTTP Response BCheck Template");
        responseTemplate.put("description", "Template for BChecks that analyze HTTP responses");
        responseTemplate.put("script", getBCheckResponseTemplate());
        
        templates.put("basic", basicTemplate);
        templates.put("http_request", httpTemplate);
        templates.put("http_response", responseTemplate);
        templates.put("available_templates", 3);
        
        return templates;
    }
    
    /**
     * Get security validation rules.
     */
    private Map<String, Object> getSecurityRules() {
        Map<String, Object> rules = new HashMap<>();
        
        rules.put("prohibited_patterns", Map.of(
            "System.exit", "Prevents script termination",
            "Runtime.getRuntime", "Blocks runtime access",
            "ProcessBuilder", "Prevents process execution",
            "java.lang.reflect", "Blocks reflection access",
            "java.io.File", "Prevents file system access",
            "java.nio.file", "Blocks file operations",
            "javax.script", "Prevents script engine access"
        ));
        
        rules.put("prohibited_imports", Map.of(
            "java.lang.reflect", "Reflection can bypass security",
            "java.io", "Direct file I/O not allowed", 
            "java.nio.file", "File operations restricted"
        ));
        
        rules.put("prohibited_operations", Map.of(
            "new File()", "File creation blocked",
            "Files.", "File operations restricted",
            "Socket", "Network access limited",
            "URLConnection", "Direct connections blocked"
        ));
        
        rules.put("size_limits", Map.of(
            "max_script_size", 1024 * 1024,
            "max_script_size_human", "1MB"
        ));
        
        rules.put("validation_info", Map.of(
            "purpose", "Prevent malicious script execution",
            "scope", "Protects host system and Burp Suite",
            "bypass_warning", "Do not attempt to bypass these restrictions"
        ));
        
        return rules;
    }
    
    private String getBCheckBasicTemplate() {
        return "/**\n" +
            " * Basic BCheck Template\n" +
            " * \n" +
            " * This template provides a starting point for creating custom BChecks.\n" +
            " * Modify the logic below to implement your specific security check.\n" +
            " */\n" +
            "\n" +
            "function initialize() {\n" +
            "    // BCheck initialization logic\n" +
            "    return {\n" +
            "        name: \"Custom Security Check\",\n" +
            "        author: \"Your Name\",\n" +
            "        version: \"1.0\"\n" +
            "    };\n" +
            "}\n" +
            "\n" +
            "function check(requestResponse) {\n" +
            "    // Implement your security check logic here\n" +
            "    var request = requestResponse.request();\n" +
            "    var response = requestResponse.response();\n" +
            "    \n" +
            "    // Example: Check for a simple pattern\n" +
            "    var responseBody = response.bodyToString();\n" +
            "    if (responseBody.includes(\"example_vulnerability_pattern\")) {\n" +
            "        return {\n" +
            "            confidence: \"HIGH\",\n" +
            "            severity: \"MEDIUM\",\n" +
            "            detail: \"Custom vulnerability detected\"\n" +
            "        };\n" +
            "    }\n" +
            "    \n" +
            "    return null; // No issue found\n" +
            "}";
    }
    
    private String getBCheckHttpTemplate() {
        return "/**\n" +
            " * HTTP Request Analysis BCheck Template\n" +
            " * \n" +
            " * Template for analyzing HTTP requests for security issues.\n" +
            " */\n" +
            "\n" +
            "function initialize() {\n" +
            "    return {\n" +
            "        name: \"HTTP Request Security Check\",\n" +
            "        author: \"Your Name\",\n" +
            "        version: \"1.0\"\n" +
            "    };\n" +
            "}\n" +
            "\n" +
            "function check(requestResponse) {\n" +
            "    var request = requestResponse.request();\n" +
            "    \n" +
            "    // Analyze request headers\n" +
            "    var headers = request.headers();\n" +
            "    for (var i = 0; i < headers.size(); i++) {\n" +
            "        var header = headers.get(i);\n" +
            "        // Check for suspicious header values\n" +
            "        if (header.value().includes(\"suspicious_pattern\")) {\n" +
            "            return {\n" +
            "                confidence: \"HIGH\",\n" +
            "                severity: \"HIGH\",\n" +
            "                detail: \"Suspicious header detected: \" + header.name()\n" +
            "            };\n" +
            "        }\n" +
            "    }\n" +
            "    \n" +
            "    // Analyze request parameters\n" +
            "    var parameters = request.parameters();\n" +
            "    for (var i = 0; i < parameters.size(); i++) {\n" +
            "        var param = parameters.get(i);\n" +
            "        // Check for injection patterns\n" +
            "        if (param.value().includes(\"'\") || param.value().includes('\"')) {\n" +
            "            return {\n" +
            "                confidence: \"MEDIUM\",\n" +
            "                severity: \"MEDIUM\",\n" +
            "                detail: \"Potential injection in parameter: \" + param.name()\n" +
            "            };\n" +
            "        }\n" +
            "    }\n" +
            "    \n" +
            "    return null;\n" +
            "}";
    }
    
    private String getBCheckResponseTemplate() {
        return "/**\n" +
            " * HTTP Response Analysis BCheck Template\n" +
            " * \n" +
            " * Template for analyzing HTTP responses for security issues.\n" +
            " */\n" +
            "\n" +
            "function initialize() {\n" +
            "    return {\n" +
            "        name: \"HTTP Response Security Check\",\n" +
            "        author: \"Your Name\",\n" +
            "        version: \"1.0\"\n" +
            "    };\n" +
            "}\n" +
            "\n" +
            "function check(requestResponse) {\n" +
            "    var response = requestResponse.response();\n" +
            "    \n" +
            "    if (!response) {\n" +
            "        return null; // No response to analyze\n" +
            "    }\n" +
            "    \n" +
            "    // Check response headers for security issues\n" +
            "    var headers = response.headers();\n" +
            "    var hasXFrameOptions = false;\n" +
            "    var hasCSP = false;\n" +
            "    \n" +
            "    for (var i = 0; i < headers.size(); i++) {\n" +
            "        var header = headers.get(i);\n" +
            "        var headerName = header.name().toLowerCase();\n" +
            "        \n" +
            "        if (headerName === \"x-frame-options\") {\n" +
            "            hasXFrameOptions = true;\n" +
            "        }\n" +
            "        if (headerName === \"content-security-policy\") {\n" +
            "            hasCSP = true;\n" +
            "        }\n" +
            "    }\n" +
            "    \n" +
            "    // Check for missing security headers\n" +
            "    if (!hasXFrameOptions && !hasCSP) {\n" +
            "        return {\n" +
            "            confidence: \"MEDIUM\",\n" +
            "            severity: \"LOW\",\n" +
            "            detail: \"Missing security headers (X-Frame-Options, CSP)\"\n" +
            "        };\n" +
            "    }\n" +
            "    \n" +
            "    // Analyze response body\n" +
            "    var responseBody = response.bodyToString();\n" +
            "    if (responseBody.includes(\"error\") && responseBody.includes(\"stack trace\")) {\n" +
            "        return {\n" +
            "            confidence: \"HIGH\",\n" +
            "            severity: \"MEDIUM\",\n" +
            "            detail: \"Stack trace disclosure detected\"\n" +
            "        };\n" +
            "    }\n" +
            "    \n" +
            "    return null;\n" +
            "}";
    }
}