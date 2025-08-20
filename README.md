# Belch - Burp Suite REST API Extension

![Java](https://img.shields.io/badge/Java-11+-blue.svg)
![Burp Suite Pro](https://img.shields.io/badge/Burp%20Suite%20Pro-Required-orange.svg)

REST API extension for Burp Suite Professional providing programmatic access to proxy traffic, active scanner, scope management, and collaborative testing workflows. Designed for security teams implementing scripted testing workflows and custom tooling integrations.

**⚠️ Requires Burp Suite Professional - This is an extension, not a standalone tool.**

## Table of Contents

- [Why Use Belch?](#why-use-belch)
- [Installation & Setup](#installation--setup)
- [Quick Start Examples](#quick-start-examples)
- [API Documentation](#api-documentation)
- [Use Cases](#use-cases)
- [Requirements](#requirements)
- [Building from Source](#building-from-source)
- [Support](#support)

## Features

**API Coverage**
- Proxy traffic management: search, filter, export HTTP requests/responses with HTTP version tracking
- Advanced filtering: batch host filtering, incremental updates with timestamp-based queries
- Scanner operations: trigger scans, retrieve vulnerability findings
- Scope configuration: programmatic include/exclude URL management
- Burp Collaborator integration for out-of-band testing
- Session tracking and traffic organization

**Integration Options**
- REST API with OpenAPI 3.0 specification
- WebSocket endpoints for real-time traffic streaming
- HAR and CSV export formats
- cURL command generation for request replay

**Operational Features**
- SQLite-based traffic storage with full-text search
- Request/response body handling up to 50MB
- Concurrent scan management and task tracking
- Session-based traffic filtering and organization

## Installation & Setup

### Step 1: Download the Extension
```bash
# Clone the repository
git clone https://github.com/campbellcharlie/belch.git
cd belch

# Build the extension
mvn clean package

# The JAR file will be in target/belch-1.0.0.jar
```

### Step 2: Load in Burp Suite Professional
1. **Open Burp Suite Professional** (must be running for the API to work)
2. Go to **Extensions** → **Installed** → **Add**
3. Select **Java** extension type
4. Choose the `belch-1.0.0.jar` file
5. Click **Next** and **Close**

### Step 3: Verify Installation

The API runs on port 7850 when Burp Suite Professional is active with the extension loaded.

**Endpoints:**
- API Base: `http://localhost:7850`
- Documentation: `http://localhost:7850/docs` 
- OpenAPI Specification: `http://localhost:7850/openapi`
- Health Check: `http://localhost:7850/health`
- WebSocket Stream: `ws://localhost:7850/ws/stream`

## API Usage

### Basic Operations

**Health Check**
```bash
curl http://localhost:7850/health
```

**Proxy Traffic Search**
```bash
curl "http://localhost:7850/proxy/search?host=example.com&method=POST&limit=10"
```

**Export Traffic Data** 
```bash
curl "http://localhost:7850/proxy/search/download?format=csv&session_tag=test_session"
```

### Scanner Integration

**Submit URL for Scanning**
```bash
curl -X POST http://localhost:7850/scanner/scan-url-list \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://example.com/api"]}'
```

**Retrieve Scan Results**
```bash
curl http://localhost:7850/scanner/issues
```

### Real-time Monitoring
```javascript
const ws = new WebSocket('ws://localhost:7850/ws/stream');
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Traffic event:', data.event_type, data.data.url);
};
```

## API Documentation

- **Interactive API Docs**: [`http://localhost:7850/docs`](http://localhost:7850/docs) - Complete endpoint reference with testing interface
- **OpenAPI Spec**: [`http://localhost:7850/openapi`](http://localhost:7850/openapi) - Machine-readable specification for tooling integration
- **Postman Collection**: [`http://localhost:7850/postman`](http://localhost:7850/postman) - Import directly into Postman for testing


## Implementation Examples

### Automated Security Testing
```python
import requests
import sys

def security_scan_workflow():
    # Verify API availability
    health = requests.get('http://localhost:7850/health')
    if health.status_code != 200:
        print("Belch API not available")
        sys.exit(1)
    
    # Submit URLs for scanning
    scan_request = {
        "urls": ["https://api.example.com"],
        "session_tag": "security_assessment_2024"
    }
    
    response = requests.post('http://localhost:7850/scanner/scan-url-list', 
                           json=scan_request)
    
    # Retrieve scan results
    issues = requests.get('http://localhost:7850/scanner/issues').json()
    
    # Process findings
    high_severity = [i for i in issues['issues'] if i['severity'] == 'HIGH']
    if high_severity:
        print(f"Found {len(high_severity)} high severity issues")
        for issue in high_severity:
            print(f"- {issue['name']} at {issue['base_url']}")
```

### Traffic Analysis and Reporting
```bash
#!/bin/bash
# Export traffic data for analysis
SESSION_TAG="pentest_$(date +%Y%m%d)"

# Set session for current testing
curl -X POST http://localhost:7850/session/tag \
  -H "Content-Type: application/json" \
  -d "{\"session_tag\": \"$SESSION_TAG\"}"

# Perform testing activities...

# Export results
curl "http://localhost:7850/proxy/search/download?format=csv&session_tag=$SESSION_TAG" \
  -o "traffic_analysis_$SESSION_TAG.csv"
```

## Requirements

**Runtime Dependencies**
- Burp Suite Professional 2023.1 or later
- Java 11+ (typically bundled with Burp Suite)
- Minimum 2GB available RAM for traffic storage
- Port 7850 available (configurable via application.properties)

**Build Dependencies** 
- Maven 3.6+
- Java Development Kit 11+

## Building from Source

```bash
git clone https://github.com/campbellcharlie/belch.git
cd belch
mvn clean package
```

The compiled extension will be located at `target/belch-1.0.0.jar`.

## Limitations

- WebSocket connections limited to 50 concurrent clients
- Request/response body storage capped at 50MB per request  
- SQLite database performance may degrade with >1M stored requests
- Scanner integration depends on Burp Suite Professional license limitations
- API rate limiting: 1000 requests per minute per client

## Troubleshooting

**Extension fails to load**
- Verify Java 11+ compatibility with your Burp Suite installation
- Check Burp Suite extension error logs for specific failure details

**API connection refused**
- Confirm Burp Suite Professional is running with extension loaded
- Verify port 7850 is available and not blocked by firewall
- Check `http://localhost:7850/health` for service status

**High memory usage**
- Large traffic history increases memory requirements
- Consider periodic database cleanup for long-running sessions
- Monitor SQLite database size in user data directory

## License Compliance

Belch requires Burp Suite Professional and must be used in compliance with PortSwigger's license terms.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Disclaimer

**Burp Suite is a trademark of PortSwigger Ltd.**  
This project is an independent, third-party extension and is not affiliated with, endorsed by, or sponsored by PortSwigger Ltd.  

This extension makes no claims of being secure and is intended for use only in controlled, local environments.  
It must not be exposed to the public internet or used in a manner that violates PortSwigger's license terms.

## Acknowledgments

Special thanks to [Phil Thomas](https://github.com/fz42net) for the fantastic name "Belch" - it perfectly captures the essence of this Burp extension!

## Support

- Documentation: `http://localhost:7850/docs`
- Issues: [GitHub Issues](https://github.com/campbellcharlie/Belch/issues) 