# Testing Guide - Verify Real SQL Injection Scanner

This document explains how to verify that the SQLi BlackBox Pro app performs **REAL** SQL injection testing, not simulated/fake functionality.

## How to Verify the Scanner is Real

### 1. Check Android Logcat Output

The scanner now includes extensive logging. To see it in action:

1. Connect your Android device/emulator to Android Studio
2. Open Logcat (View → Tool Windows → Logcat)
3. Filter by tag: `SQLScanner`
4. Run a scan and you'll see real-time output like:

```
D/SQLScanner: Starting scan for URL: http://testphp.vulnweb.com/artists.php?artist=1 with mode: STANDARD
D/SQLScanner: Testing 18 detection payloads...
D/SQLScanner: Testing payload 1: ' OR '1'='1...
D/SQLScanner: Response: Status=200, Body length=4523
D/SQLScanner: Testing payload 2: ' OR 1=1--...
I/SQLScanner: VULNERABILITY FOUND! Payload: ' OR 1=1--, DB Type: MYSQL
D/SQLScanner: Attempting data extraction with 4 payloads...
I/SQLScanner: Extracted 3 data items
```

### 2. Test with Known Vulnerable Site

Use this intentionally vulnerable test site (legal to test):
```
http://testphp.vulnweb.com/artists.php?artist=1
```

**Expected Results:**
- Scanner will make REAL HTTP requests
- Should detect SQL injection vulnerability
- Should identify MySQL database
- May extract some data depending on payload success

### 3. Test with Non-Vulnerable Site

Try a normal website like:
```
https://www.google.com
```

**Expected Results:**
- Scanner will make REAL HTTP requests
- Will show "No Vulnerability Detected"
- Results will show diagnostic info: "Tested X payloads, Encountered Y errors"
- You'll see actual error messages if network issues occur

### 4. Test Network Error Handling

Try an invalid URL:
```
http://this-domain-does-not-exist-12345.com
```

**Expected Results:**
- Will show error: "DNS Error: Cannot resolve host"
- Proves scanner is making real DNS lookups

### 5. Verify HTTP Requests with Network Monitor

Use a tool like Charles Proxy or Wireshark to monitor network traffic:

1. Set up a proxy on your computer
2. Configure Android device to use the proxy
3. Run a scan
4. You'll see actual HTTP requests with SQL payloads in the URL parameters

Example request you'll see:
```
GET /page.php?id=%27+OR+%271%27%3D%271 HTTP/1.1
Host: targetsite.com
User-Agent: okhttp/4.12.0
```

## What Makes This Scanner REAL

### Real Network Operations
- ✅ Uses OkHttp library for actual HTTP/HTTPS requests
- ✅ Runs on `Dispatchers.IO` thread (dedicated to I/O operations)
- ✅ Supports HTTP, HTTPS, and SOCKS proxy (Tor mode)
- ✅ Real DNS lookups and TCP connections

### Real SQL Injection Testing
- ✅ 34+ real SQL injection payloads
- ✅ Tests multiple database types (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- ✅ Analyzes actual server responses for SQL error patterns
- ✅ Attempts data extraction from vulnerable endpoints
- ✅ Pattern matching for 50+ different SQL error messages

### Real Error Handling
- ✅ Catches and reports DNS errors (UnknownHostException)
- ✅ Catches and reports timeout errors (SocketTimeoutException)
- ✅ Catches and reports network errors (IOException)
- ✅ Shows detailed error messages to user

### Not Simulated/Fake
- ❌ Does NOT use hardcoded/random results
- ❌ Does NOT simulate network delays
- ❌ Does NOT show fake vulnerabilities
- ❌ Does NOT work offline (requires real internet connection)

## Understanding Scan Results

### When Vulnerability is Found
Shows:
- Database type (detected from error messages)
- Successful payload used
- Response details (actual server response)
- Extracted data (if any - usernames, tables, versions, etc.)

### When No Vulnerability is Found
Shows:
- Number of payloads tested
- Number of errors encountered
- List of any network errors
- Confirms all requests completed successfully

### When Network Error Occurs
Shows specific error like:
- "Cannot connect to server. Please check the URL and your internet connection."
- "Network connection failed. Please check your internet connection."
- "Network error: timeout" (if server is slow to respond)

## Advanced Testing

### Test Tor Mode
1. Install Tor on your Android device (Orbot app)
2. Start Tor (ensure it's running on port 9050)
3. Select "Tor Mode" in the app
4. Scan will route through Tor network (slower but anonymous)
5. Check logcat - you'll see: "Using Tor SOCKS proxy at 127.0.0.1:9050"

### Test Stealth Mode
1. Select "Stealth Mode" in the app
2. Scanner will randomize User-Agent headers
3. Check logcat to see different User-Agents being used
4. Helps evade basic WAF (Web Application Firewall) detection

## Common Issues

### "Network error: Cannot connect to server"
- **Cause**: No internet connection, or URL is wrong
- **Solution**: Check internet connection, verify URL is correct

### "DNS Error: Cannot resolve host"
- **Cause**: Invalid domain name, or DNS server issues
- **Solution**: Check URL spelling, try again, or use different network

### "Timeout" errors
- **Cause**: Server is slow or overloaded
- **Solution**: This is normal for some servers, scanner continues with other payloads

### Tor mode not working
- **Cause**: Tor is not running on port 9050
- **Solution**: Install Orbot app and start Tor service

## Legal Notice

**IMPORTANT**: This tool performs REAL penetration testing. Only use it on:
- Systems you own
- Systems where you have explicit written permission to test
- Intentionally vulnerable test sites (like testphp.vulnweb.com)

Unauthorized testing is illegal and unethical.

## Code References

See these files for the actual implementation:

1. **SQLScanner.kt** - Lines 44-159: Main scanning logic with OkHttp
2. **SQLScanner.kt** - Lines 161-217: Error detection patterns
3. **SQLScanner.kt** - Lines 219-267: Data extraction logic
4. **ScanViewModel.kt** - Lines 63-79: Error handling and state management

All code uses real Android/Kotlin APIs - no simulation or mocking.
