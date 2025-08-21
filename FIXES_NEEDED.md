# Critical Fixes Needed for Belch Extension

## Issues to Address

### 1. Endpoint Changes Made
- **Changed PUT to POST**: The `/proxy/tag` and `/proxy/comment` endpoints were changed from PUT to POST methods
- These changes need to be documented and verified working

### 2. Import Logic Missing
- **Automatic proxy history import got commented out**: The logic that imports existing Burp proxy history on startup has been disabled or removed
- Need to re-enable this functionality so the extension automatically imports the 135+ requests that exist in Burp's proxy history
- The import should happen on extension startup without manual intervention

### 3. Database Stability Issues
- **PRAGMA problems**: Database keeps disconnecting due to PRAGMA-related issues
- Need to fix the database connection stability so it doesn't show "Disconnected" 
- Remove aggressive database checks that are causing disconnections

### 4. Current State
- Burp has 135 requests in proxy history and 138 in logger
- Extension database shows 0 requests due to import failure
- Database connection is unstable and frequently disconnects
- Tag/comment endpoints can't be tested without stable data

## Priority Order
1. Fix database stability (PRAGMA issues)
2. Re-enable automatic proxy history import
3. Verify tag/comment POST endpoints work
4. Test with actual data

## Notes
- Stop overcomplicating the solutions
- Focus on the core functionality that was working before
- Don't break existing working code while trying to add features