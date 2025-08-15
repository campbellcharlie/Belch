package com.belch.services;

import com.belch.config.ApiConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Phase 3 Task 13: Interactive Documentation Service
 * 
 * Provides dynamic API documentation with interactive examples,
 * code generation, and real-time testing capabilities.
 */
public class DocumentationService {
    
    private static final Logger logger = LoggerFactory.getLogger(DocumentationService.class);
    
    private final ApiConfig config;
    private final ObjectMapper objectMapper;
    private final Map<String, EndpointDocumentation> endpoints;
    
    public DocumentationService(ApiConfig config) {
        this.config = config;
        this.objectMapper = new ObjectMapper();
        this.endpoints = new HashMap<>();
        initializeEndpointDocumentation();
        logger.info("[*] Documentation Service initialized with {} endpoints", endpoints.size());
    }
    
    /**
     * Get interactive documentation for all endpoints.
     */
    public Map<String, Object> getInteractiveDocumentation() {
        Map<String, Object> documentation = new HashMap<>();
        documentation.put("title", "Belch API Interactive Documentation");
        documentation.put("version", "1.0.0");
        documentation.put("base_url", getBaseUrl());
        documentation.put("generated_at", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        documentation.put("total_endpoints", endpoints.size());
        
        Map<String, Object> categorizedEndpoints = new HashMap<>();
        
        // Group endpoints by category
        for (Map.Entry<String, EndpointDocumentation> entry : endpoints.entrySet()) {
            EndpointDocumentation endpoint = entry.getValue();
            String category = endpoint.getCategory();
            
            categorizedEndpoints.computeIfAbsent(category, k -> new ArrayList<>());
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> categoryList = (List<Map<String, Object>>) categorizedEndpoints.get(category);
            categoryList.add(endpoint.toInteractiveMap());
        }
        
        documentation.put("endpoints_by_category", categorizedEndpoints);
        documentation.put("features", getDocumentationFeatures());
        
        return documentation;
    }
    
    /**
     * Get documentation for a specific endpoint with interactive examples.
     */
    public Map<String, Object> getEndpointDocumentation(String method, String path) {
        String key = method.toUpperCase() + " " + path;
        EndpointDocumentation endpoint = endpoints.get(key);
        
        if (endpoint == null) {
            return Map.of(
                "error", "Endpoint not found",
                "available_endpoints", endpoints.keySet()
            );
        }
        
        Map<String, Object> doc = endpoint.toInteractiveMap();
        doc.put("interactive_examples", generateInteractiveExamples(endpoint));
        doc.put("test_data", generateTestData(endpoint));
        doc.put("code_samples", generateCodeSamples(endpoint));
        
        return doc;
    }
    
    /**
     * Generate curl command for an endpoint with sample data.
     */
    public String generateCurlCommand(String method, String path, Map<String, Object> parameters) {
        StringBuilder curl = new StringBuilder();
        curl.append("curl -X ").append(method.toUpperCase()).append(" ");
        
        String fullUrl = getBaseUrl() + path;
        
        if ("GET".equalsIgnoreCase(method) && parameters != null && !parameters.isEmpty()) {
            // Add query parameters for GET requests
            List<String> queryParams = new ArrayList<>();
            for (Map.Entry<String, Object> param : parameters.entrySet()) {
                queryParams.add(param.getKey() + "=" + param.getValue());
            }
            fullUrl += "?" + String.join("&", queryParams);
        }
        
        curl.append("\"").append(fullUrl).append("\" ");
        
        // Add headers
        curl.append("-H \"Content-Type: application/json\" ");
        curl.append("-H \"Accept: application/json\" ");
        
        // Add body for POST/PUT/DELETE requests
        if (!"GET".equalsIgnoreCase(method) && parameters != null && !parameters.isEmpty()) {
            try {
                String jsonBody = objectMapper.writeValueAsString(parameters);
                curl.append("-d '").append(jsonBody).append("' ");
            } catch (Exception e) {
                logger.warn("Failed to serialize parameters to JSON", e);
            }
        }
        
        return curl.toString().trim();
    }
    
    /**
     * Generate JavaScript fetch example.
     */
    public String generateJavaScriptExample(String method, String path, Map<String, Object> parameters) {
        StringBuilder js = new StringBuilder();
        js.append("// JavaScript Fetch Example\n");
        js.append("const response = await fetch('").append(getBaseUrl()).append(path);
        
        if ("GET".equalsIgnoreCase(method) && parameters != null && !parameters.isEmpty()) {
            List<String> queryParams = new ArrayList<>();
            for (Map.Entry<String, Object> param : parameters.entrySet()) {
                queryParams.add(param.getKey() + "=${encodeURIComponent('" + param.getValue() + "')}");
            }
            js.append("?").append(String.join("&", queryParams));
        }
        
        js.append("', {\n");
        js.append("  method: '").append(method.toUpperCase()).append("',\n");
        js.append("  headers: {\n");
        js.append("    'Content-Type': 'application/json',\n");
        js.append("    'Accept': 'application/json'\n");
        js.append("  }");
        
        if (!"GET".equalsIgnoreCase(method) && parameters != null && !parameters.isEmpty()) {
            try {
                String jsonBody = objectMapper.writeValueAsString(parameters);
                js.append(",\n  body: JSON.stringify(").append(jsonBody).append(")");
            } catch (Exception e) {
                logger.warn("Failed to serialize parameters to JSON", e);
            }
        }
        
        js.append("\n});\n\n");
        js.append("const data = await response.json();\n");
        js.append("console.log(data);");
        
        return js.toString();
    }
    
    /**
     * Generate Python requests example.
     */
    public String generatePythonExample(String method, String path, Map<String, Object> parameters) {
        StringBuilder python = new StringBuilder();
        python.append("# Python Requests Example\n");
        python.append("import requests\nimport json\n\n");
        
        python.append("url = '").append(getBaseUrl()).append(path).append("'\n");
        python.append("headers = {\n");
        python.append("    'Content-Type': 'application/json',\n");
        python.append("    'Accept': 'application/json'\n");
        python.append("}\n\n");
        
        if (parameters != null && !parameters.isEmpty()) {
            if ("GET".equalsIgnoreCase(method)) {
                python.append("params = ").append(formatPythonDict(parameters)).append("\n");
                python.append("response = requests.").append(method.toLowerCase()).append("(url, headers=headers, params=params)\n");
            } else {
                python.append("data = ").append(formatPythonDict(parameters)).append("\n");
                python.append("response = requests.").append(method.toLowerCase()).append("(url, headers=headers, json=data)\n");
            }
        } else {
            python.append("response = requests.").append(method.toLowerCase()).append("(url, headers=headers)\n");
        }
        
        python.append("\nif response.status_code == 200:\n");
        python.append("    result = response.json()\n");
        python.append("    print(json.dumps(result, indent=2))\n");
        python.append("else:\n");
        python.append("    print(f'Error: {response.status_code} - {response.text}')");
        
        return python.toString();
    }
    
    /**
     * Get OpenAPI specification for the API.
     */
    public Map<String, Object> getOpenApiSpec() {
        Map<String, Object> spec = new HashMap<>();
        spec.put("openapi", "3.0.3");
        
        // Info section
        Map<String, Object> info = new HashMap<>();
        info.put("title", "Belch API");
        info.put("description", "Interactive API for Burp Suite Extension");
        info.put("version", "1.0.0");
        info.put("contact", Map.of("name", "Belch API Support"));
        spec.put("info", info);
        
        // Servers
        spec.put("servers", List.of(
            Map.of("url", getBaseUrl(), "description", "Local Development Server")
        ));
        
        // Paths
        Map<String, Object> paths = new HashMap<>();
        for (Map.Entry<String, EndpointDocumentation> entry : endpoints.entrySet()) {
            EndpointDocumentation endpoint = entry.getValue();
            String pathKey = endpoint.getPath();
            String methodKey = endpoint.getMethod().toLowerCase();
            
            paths.computeIfAbsent(pathKey, k -> new HashMap<>());
            @SuppressWarnings("unchecked")
            Map<String, Object> pathObj = (Map<String, Object>) paths.get(pathKey);
            pathObj.put(methodKey, endpoint.toOpenApiOperation());
        }
        spec.put("paths", paths);
        
        // Components
        spec.put("components", Map.of(
            "schemas", generateOpenApiSchemas()
        ));
        
        return spec;
    }
    
    private void initializeEndpointDocumentation() {
        // Phase 3 Task 13: Add comprehensive endpoint documentation
        
        // Proxy Traffic Management
        Map<String, Object> searchParams = new HashMap<>();
        searchParams.put("url", "Filter by URL (supports wildcards with * and ?)");
        searchParams.put("url_pattern", "Wildcard pattern for URL matching (* = any chars, ? = single char)");
        searchParams.put("method", "HTTP method (GET, POST, etc.)");
        searchParams.put("host", "Filter by host");
        searchParams.put("status_code", "HTTP status code");
        searchParams.put("session_tag", "Filter by session tag (empty = search all sessions)");
        searchParams.put("case_insensitive", "Case insensitive matching (true/false)");
        searchParams.put("url_regex", "Regex pattern for URL matching");
        searchParams.put("method_regex", "Regex pattern for method matching");
        searchParams.put("use_regex", "Enable regex mode (true/false)");
        searchParams.put("start_time", "Filter by start timestamp");
        searchParams.put("end_time", "Filter by end timestamp");
        searchParams.put("limit", "Maximum results to return");
        searchParams.put("offset", "Results offset for pagination");
        
        addEndpoint("GET", "/proxy/search", "Proxy Traffic",
            "Search proxy traffic with advanced filtering, wildcard patterns, and regex support",
            searchParams,
            generateSampleSearchResponse()
        );
        
        addEndpoint("GET", "/proxy/search/download", "Proxy Traffic",
            "Export proxy traffic in multiple formats",
            Map.of(
                "format", "Export format: json, csv, xml, custom",
                "template", "For custom format: detailed, summary, burp_xml, nmap_xml, custom_json",
                "url", "Filter by URL",
                "method", "HTTP method filter"
            ),
            "File download with Content-Disposition header"
        );
        
        addEndpoint("POST", "/proxy/bulk/tags", "Proxy Traffic",
            "Add tags to multiple traffic records",
            Map.of(
                "request_ids", List.of(1, 2, 3),
                "tags", "vulnerable,tested,reviewed"
            ),
            Map.of(
                "success", true,
                "updated_count", 3,
                "operation", "bulk_tag_add"
            )
        );
        
        addEndpoint("DELETE", "/proxy/bulk/tags", "Proxy Traffic",
            "Remove tags from multiple traffic records",
            Map.of(
                "request_ids", List.of(1, 2, 3),
                "tags", "old_tag,deprecated"
            ),
            Map.of(
                "success", true,
                "updated_count", 3,
                "operation", "bulk_tag_remove"
            )
        );
        
        addEndpoint("POST", "/proxy/bulk/comments", "Proxy Traffic",
            "Add comments to multiple traffic records",
            Map.of(
                "request_ids", List.of(1, 2, 3),
                "comment", "Security review completed"
            ),
            Map.of(
                "success", true,
                "updated_count", 3,
                "operation", "bulk_comment_add"
            )
        );
        
        // Scanner Integration
        addEndpoint("POST", "/scanner/audit", "Scanner",
            "Start security audit scan on specific URLs",
            Map.of(
                "urls", List.of("https://example.com/api/users", "https://example.com/login"),
                "audit_config", "LEGACY_ACTIVE_AUDIT_CHECKS",
                "optimization_strategy", "BALANCED"
            ),
            Map.of(
                "task_id", "scan_12345",
                "status", "started",
                "urls_count", 2
            )
        );
        
        addEndpoint("POST", "/scanner/crawl", "Scanner",
            "Start crawl scan on seed URLs",
            Map.of(
                "seed_urls", List.of("https://example.com"),
                "max_depth", 3,
                "session_tag", "crawl_session_001"
            ),
            Map.of(
                "task_id", "crawl_67890",
                "status", "started",
                "seed_urls_count", 1
            )
        );
        
        // Collaborator Integration  
        addEndpoint("GET", "/collaborator/interactions/enhanced", "Collaborator",
            "Get collaborator interactions with database storage and pattern matching",
            Map.of(
                "client_secret", "your_client_secret_here",
                "store_in_db", "true",
                "session_tag", "test_session"
            ),
            Map.of(
                "interactions", List.of(),
                "count", 0,
                "stored_in_database", true,
                "pattern_matches", List.of()
            )
        );
        
        addEndpoint("POST", "/collaborator/payloads/bulk", "Collaborator",
            "Generate multiple collaborator payloads with tracking",
            Map.of(
                "count", 5,
                "session_tag", "bulk_test",
                "type", "integration_test",
                "custom_data_list", List.of("data1", "data2", "data3", "data4", "data5")
            ),
            Map.of(
                "payloads", List.of("payload1.collaborator.com", "payload2.collaborator.com"),
                "count", 5,
                "client_secret", "generated_secret",
                "tracking_enabled", true
            )
        );
        
        // Configuration Management
        addEndpoint("GET", "/config", "Configuration",
            "Get current API configuration",
            Map.of(),
            Map.of(
                "session_tag", "default",
                "database_path", "/path/to/database.db",
                "websocket_enabled", true
            )
        );
        
        addEndpoint("PUT", "/config", "Configuration",
            "Update API configuration with hot reload",
            Map.of(
                "session_tag", "new_session",
                "enable_logging", true,
                "max_database_size", "100MB"
            ),
            Map.of(
                "success", true,
                "updated_fields", List.of("session_tag", "enable_logging"),
                "reload_required", false
            )
        );
        
        logger.info("Initialized {} endpoint documentations", endpoints.size());
    }
    
    private void addEndpoint(String method, String path, String category, String description, 
                           Map<String, Object> parameters, Object sampleResponse) {
        EndpointDocumentation endpoint = new EndpointDocumentation(
            method, path, category, description, parameters, sampleResponse
        );
        endpoints.put(method + " " + path, endpoint);
    }
    
    private Map<String, Object> generateInteractiveExamples(EndpointDocumentation endpoint) {
        Map<String, Object> examples = new HashMap<>();
        
        Map<String, Object> sampleParams = endpoint.getParameters();
        
        examples.put("curl", generateCurlCommand(endpoint.getMethod(), endpoint.getPath(), sampleParams));
        examples.put("javascript", generateJavaScriptExample(endpoint.getMethod(), endpoint.getPath(), sampleParams));
        examples.put("python", generatePythonExample(endpoint.getMethod(), endpoint.getPath(), sampleParams));
        
        return examples;
    }
    
    private Map<String, Object> generateTestData(EndpointDocumentation endpoint) {
        Map<String, Object> testData = new HashMap<>();
        testData.put("sample_request", endpoint.getParameters());
        testData.put("sample_response", endpoint.getSampleResponse());
        testData.put("test_scenarios", generateTestScenarios(endpoint));
        return testData;
    }
    
    private List<Map<String, Object>> generateTestScenarios(EndpointDocumentation endpoint) {
        List<Map<String, Object>> scenarios = new ArrayList<>();
        
        // Success scenario
        scenarios.add(Map.of(
            "name", "Successful Request",
            "description", "Standard successful request with valid parameters",
            "parameters", endpoint.getParameters(),
            "expected_status", 200,
            "expected_response_type", "application/json"
        ));
        
        // Error scenarios based on endpoint type
        if (endpoint.getParameters().containsKey("request_ids")) {
            scenarios.add(Map.of(
                "name", "Missing Required Field",
                "description", "Request without required request_ids field",
                "parameters", Map.of(),
                "expected_status", 400,
                "expected_error", "Missing required field"
            ));
        }
        
        if (endpoint.getPath().contains("search")) {
            scenarios.add(Map.of(
                "name", "Large Result Set",
                "description", "Request that returns many results to test pagination",
                "parameters", Map.of("limit", 1000, "offset", 0),
                "expected_status", 200,
                "performance_note", "Should complete within 5 seconds"
            ));
        }
        
        return scenarios;
    }
    
    private Map<String, Object> generateCodeSamples(EndpointDocumentation endpoint) {
        Map<String, Object> samples = new HashMap<>();
        
        // Generate additional language examples
        samples.put("java", generateJavaExample(endpoint));
        samples.put("go", generateGoExample(endpoint));
        samples.put("php", generatePhpExample(endpoint));
        
        return samples;
    }
    
    private String generateJavaExample(EndpointDocumentation endpoint) {
        StringBuilder java = new StringBuilder();
        java.append("// Java Example using OkHttp\n");
        java.append("import okhttp3.*;\nimport java.io.IOException;\n\n");
        java.append("OkHttpClient client = new OkHttpClient();\n\n");
        
        String url = getBaseUrl() + endpoint.getPath();
        
        if ("GET".equalsIgnoreCase(endpoint.getMethod()) && !endpoint.getParameters().isEmpty()) {
            java.append("HttpUrl.Builder urlBuilder = HttpUrl.parse(\"").append(url).append("\").newBuilder();\n");
            for (Map.Entry<String, Object> param : endpoint.getParameters().entrySet()) {
                java.append("urlBuilder.addQueryParameter(\"").append(param.getKey())
                    .append("\", \"").append(param.getValue()).append("\");\n");
            }
            java.append("String url = urlBuilder.build().toString();\n\n");
        } else {
            java.append("String url = \"").append(url).append("\";\n");
        }
        
        java.append("Request.Builder requestBuilder = new Request.Builder()\n");
        java.append("    .url(url)\n");
        java.append("    .addHeader(\"Content-Type\", \"application/json\")\n");
        java.append("    .addHeader(\"Accept\", \"application/json\");\n\n");
        
        if (!"GET".equalsIgnoreCase(endpoint.getMethod()) && !endpoint.getParameters().isEmpty()) {
            java.append("String json = \"{\\\"example\\\": \\\"data\\\"}\";\n");
            java.append("RequestBody body = RequestBody.create(json, MediaType.get(\"application/json\"));\n");
            java.append("requestBuilder.").append(endpoint.getMethod().toLowerCase()).append("(body);\n\n");
        }
        
        java.append("Request request = requestBuilder.build();\n");
        java.append("try (Response response = client.newCall(request).execute()) {\n");
        java.append("    if (response.isSuccessful()) {\n");
        java.append("        System.out.println(response.body().string());\n");
        java.append("    }\n");
        java.append("}");
        
        return java.toString();
    }
    
    private String generateGoExample(EndpointDocumentation endpoint) {
        StringBuilder go = new StringBuilder();
        go.append("// Go Example\n");
        go.append("package main\n\n");
        go.append("import (\n    \"fmt\"\n    \"net/http\"\n    \"io/ioutil\"\n");
        if (!"GET".equalsIgnoreCase(endpoint.getMethod())) {
            go.append("    \"strings\"\n");
        }
        go.append(")\n\n");
        go.append("func main() {\n");
        go.append("    url := \"").append(getBaseUrl()).append(endpoint.getPath()).append("\"\n\n");
        
        if (!"GET".equalsIgnoreCase(endpoint.getMethod()) && !endpoint.getParameters().isEmpty()) {
            go.append("    payload := `{\"example\": \"data\"}`\n");
            go.append("    req, _ := http.NewRequest(\"").append(endpoint.getMethod().toUpperCase())
              .append("\", url, strings.NewReader(payload))\n");
        } else {
            go.append("    req, _ := http.NewRequest(\"").append(endpoint.getMethod().toUpperCase())
              .append("\", url, nil)\n");
        }
        
        go.append("    req.Header.Set(\"Content-Type\", \"application/json\")\n");
        go.append("    req.Header.Set(\"Accept\", \"application/json\")\n\n");
        go.append("    client := &http.Client{}\n");
        go.append("    resp, err := client.Do(req)\n");
        go.append("    if err != nil {\n        panic(err)\n    }\n");
        go.append("    defer resp.Body.Close()\n\n");
        go.append("    body, _ := ioutil.ReadAll(resp.Body)\n");
        go.append("    fmt.Println(string(body))\n");
        go.append("}");
        
        return go.toString();
    }
    
    private String generatePhpExample(EndpointDocumentation endpoint) {
        StringBuilder php = new StringBuilder();
        php.append("<?php\n");
        php.append("// PHP Example using cURL\n\n");
        php.append("$url = '").append(getBaseUrl()).append(endpoint.getPath()).append("';\n");
        php.append("$headers = [\n");
        php.append("    'Content-Type: application/json',\n");
        php.append("    'Accept: application/json'\n");
        php.append("];\n\n");
        
        php.append("$ch = curl_init();\n");
        php.append("curl_setopt($ch, CURLOPT_URL, $url);\n");
        php.append("curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);\n");
        php.append("curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);\n");
        
        if (!"GET".equalsIgnoreCase(endpoint.getMethod())) {
            php.append("curl_setopt($ch, CURLOPT_CUSTOMREQUEST, '").append(endpoint.getMethod().toUpperCase()).append("');\n");
            if (!endpoint.getParameters().isEmpty()) {
                php.append("curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(['example' => 'data']));\n");
            }
        }
        
        php.append("\n$response = curl_exec($ch);\n");
        php.append("$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);\n");
        php.append("curl_close($ch);\n\n");
        php.append("if ($httpCode === 200) {\n");
        php.append("    $data = json_decode($response, true);\n");
        php.append("    print_r($data);\n");
        php.append("} else {\n");
        php.append("    echo \"Error: $httpCode - $response\";\n");
        php.append("}\n");
        php.append("?>");
        
        return php.toString();
    }
    
    private String getBaseUrl() {
        return "http://localhost:7850";
    }
    
    private List<String> getDocumentationFeatures() {
        return List.of(
            "Interactive code examples in 6+ languages",
            "Real-time API testing",
            "OpenAPI 3.0 specification",
            "Comprehensive parameter documentation",
            "Error scenario examples",
            "Performance testing guidance",
            "Export functionality demos",
            "Regex pattern examples"
        );
    }
    
    private Map<String, Object> generateSampleSearchResponse() {
        return Map.of(
            "results", List.of(
                Map.of(
                    "id", 1,
                    "timestamp", "2024-01-15T10:30:00Z",
                    "method", "GET",
                    "url", "https://example.com/api/users",
                    "host", "example.com",
                    "status_code", 200,
                    "session_tag", "test_session"
                )
            ),
            "count", 1,
            "total_count", 1,
            "filters", Map.of("url_pattern", "*api/users*"),
            "examples", Map.of(
                "wildcard_patterns", List.of(
                    "*/api/* - URLs containing /api/",
                    "*login* - URLs containing 'login'",
                    "*.js - URLs ending with .js",
                    "https://*.com/* - HTTPS URLs on .com domains"
                ),
                "session_filtering", List.of(
                    "session_tag=my_session - Filter by specific session",
                    "session_tag= - Search across all sessions"
                )
            )
        );
    }
    
    private String formatPythonDict(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if (!first) sb.append(", ");
            first = false;
            sb.append("'").append(entry.getKey()).append("': ");
            if (entry.getValue() instanceof String) {
                sb.append("'").append(entry.getValue()).append("'");
            } else if (entry.getValue() instanceof List) {
                sb.append(entry.getValue().toString());
            } else {
                sb.append(entry.getValue());
            }
        }
        sb.append("}");
        return sb.toString();
    }
    
    private Map<String, Object> generateOpenApiSchemas() {
        Map<String, Object> schemas = new HashMap<>();
        
        // Common response schema
        schemas.put("ApiResponse", Map.of(
            "type", "object",
            "properties", Map.of(
                "success", Map.of("type", "boolean"),
                "message", Map.of("type", "string"),
                "data", Map.of("type", "object")
            )
        ));
        
        // Search response schema
        schemas.put("SearchResponse", Map.of(
            "type", "object",
            "properties", Map.of(
                "results", Map.of("type", "array", "items", Map.of("$ref", "#/components/schemas/TrafficRecord")),
                "count", Map.of("type", "integer"),
                "total_count", Map.of("type", "integer"),
                "filters", Map.of("type", "object")
            )
        ));
        
        // Traffic record schema
        schemas.put("TrafficRecord", Map.of(
            "type", "object",
            "properties", Map.of(
                "id", Map.of("type", "integer"),
                "timestamp", Map.of("type", "string", "format", "date-time"),
                "method", Map.of("type", "string"),
                "url", Map.of("type", "string"),
                "host", Map.of("type", "string"),
                "status_code", Map.of("type", "integer")
            )
        ));
        
        return schemas;
    }
    
    /**
     * Inner class to represent endpoint documentation.
     */
    private static class EndpointDocumentation {
        private final String method;
        private final String path;
        private final String category;
        private final String description;
        private final Map<String, Object> parameters;
        private final Object sampleResponse;
        
        public EndpointDocumentation(String method, String path, String category, String description,
                                   Map<String, Object> parameters, Object sampleResponse) {
            this.method = method;
            this.path = path;
            this.category = category;
            this.description = description;
            this.parameters = parameters != null ? new HashMap<>(parameters) : new HashMap<>();
            this.sampleResponse = sampleResponse;
        }
        
        public Map<String, Object> toInteractiveMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("method", method);
            map.put("path", path);
            map.put("category", category);
            map.put("description", description);
            map.put("parameters", parameters);
            map.put("sample_response", sampleResponse);
            return map;
        }
        
        public Map<String, Object> toOpenApiOperation() {
            Map<String, Object> operation = new HashMap<>();
            operation.put("summary", description);
            operation.put("tags", List.of(category));
            
            if (!parameters.isEmpty()) {
                List<Map<String, Object>> params = new ArrayList<>();
                for (Map.Entry<String, Object> param : parameters.entrySet()) {
                    params.add(Map.of(
                        "name", param.getKey(),
                        "in", "GET".equalsIgnoreCase(method) ? "query" : "body",
                        "description", "Parameter: " + param.getKey(),
                        "schema", Map.of("type", getTypeFromValue(param.getValue()))
                    ));
                }
                operation.put("parameters", params);
            }
            
            operation.put("responses", Map.of(
                "200", Map.of(
                    "description", "Successful response",
                    "content", Map.of(
                        "application/json", Map.of(
                            "schema", Map.of("$ref", "#/components/schemas/ApiResponse")
                        )
                    )
                )
            ));
            
            return operation;
        }
        
        private String getTypeFromValue(Object value) {
            if (value instanceof String) return "string";
            if (value instanceof Integer || value instanceof Long) return "integer";
            if (value instanceof Boolean) return "boolean";
            if (value instanceof List) return "array";
            if (value instanceof Map) return "object";
            return "string";
        }
        
        // Getters
        public String getMethod() { return method; }
        public String getPath() { return path; }
        public String getCategory() { return category; }
        public String getDescription() { return description; }
        public Map<String, Object> getParameters() { return parameters; }
        public Object getSampleResponse() { return sampleResponse; }
    }
}