# CLAUDE.md - Project Context for AI Assistant

## CRITICAL INFORMATION - NEVER FORGET
- **DEFAULT API PORT: 7850**
- The Belch API runs on http://localhost:7850
- This is NOT port 8080 (that's Burp's proxy port)
- This is NOT port 8081

## Project Overview
Belch is a Burp Suite extension that provides a REST API for accessing Burp Suite's functionality programmatically.

## Key Commands
- Build: `mvn clean package`
- The JAR is built to: `/Users/charlie/src/BURP_API/target/belch-1.0.0.jar`

## Testing the API
Always use port 7850 for API calls:
```bash
curl http://localhost:7850/proxy/history
curl http://localhost:7850/proxy/search?host=example.com
curl http://localhost:7850/stats
```

## Recent Issues Fixed
- Database disconnection issues - Added connection validation with SELECT 1 test
- Added busy_timeout for SQLite to handle concurrent access
- Made getConnection() synchronized for thread safety
- if you fix the code the extension has to be reloaded in burp after you recompile the jar