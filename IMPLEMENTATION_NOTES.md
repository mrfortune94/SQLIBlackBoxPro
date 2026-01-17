# Implementation Notes: Mandatory Tor Routing & Database Dump

## Overview
This implementation transforms SQLi BlackBox Pro into a fail-closed, Tor-only security testing tool with comprehensive database dump capabilities.

## Key Changes Implemented

### 1. Fail-Closed Tor Architecture ✅

#### Removed Non-Tor Modes
- **Before**: App had three modes: STANDARD, TOR, STEALTH
- **After**: Only TOR mode available (fail-closed)
- **Files Modified**:
  - `SQLScanner.kt`: Removed `standardClient` and `stealthUserAgents`
  - `ModeScreen.kt`: Removed mode selection, now shows security information only
  - `ScanViewModel.kt`: Default mode set to TOR

#### Tor Verification & Enforcement
- **Added**: Pre-scan Tor verification in `SQLScanner.kt`
  - `verifyTorConnection()`: Checks Tor SOCKS proxy before each scan
  - Throws `SecurityException` if Tor is not running
  - Prevents any network activity without Tor

- **Navigation Flow Updated** in `MainActivity.kt`:
  ```
  PIN → URL → Tor Check → Secure Scan → Results
  ```
  - Added `TorCheckScreen` into navigation flow
  - Users cannot proceed to scanning unless Tor is active

- **ViewModel Integration** in `ScanViewModel.kt`:
  - Added `torState: StateFlow<TorState>` for tracking Tor status
  - Added `checkTorStatus(context: Context)` function
  - Integrated with `TorManager` (OrbotHelper.kt)

### 2. Database Dump Functionality ✅

#### New Data Models
- **`DatabaseDump`** class in `Models.kt`:
  ```kotlin
  data class DatabaseDump(
      val users: List<String>,
      val tables: List<String>,
      val schemas: List<String>,
      val allData: String
  )
  ```
- **Enhanced `ScanResult`** to include `databaseDump: DatabaseDump?`

#### Comprehensive Extraction Payloads
Added to `SQLPayloads.kt`:
- `POSTGRESQL_EXTRACTION_PAYLOADS`: PostgreSQL-specific data extraction
- `MSSQL_EXTRACTION_PAYLOADS`: MSSQL-specific data extraction
- `MYSQL_DUMP_PAYLOADS`: Comprehensive MySQL database enumeration (9 payloads)
- `POSTGRESQL_DUMP_PAYLOADS`: PostgreSQL database enumeration (6 payloads)
- `MSSQL_DUMP_PAYLOADS`: MSSQL database enumeration (6 payloads)
- `ORACLE_DUMP_PAYLOADS`: Oracle database enumeration (5 payloads)

#### Database Dump Logic
Added to `SQLScanner.kt`:
- `performDatabaseDump()`: Comprehensive database enumeration
- `extractUsers()`: Extract username:password patterns
- `extractTables()`: Extract table names
- `extractSchemas()`: Extract schema/database names
- Executes database-specific dump payloads based on detected DB type
- Builds complete dump report with timestamps

#### Download Functionality
Added to `ResultsScreen.kt`:
- **UI Component**: "DB DOWNLOAD (USERS)" button with download icon
- Shows dump statistics: user count, table count, schema count
- `downloadDatabaseDump()` function:
  - Saves to: `<External Storage>/Android/data/com.sqliblackboxpro/files/Documents/SQLIBlackBoxPro_Dumps/`
  - Filename format: `db_dump_YYYY-MM-DD_HH-mm-ss.txt`
  - Toast notifications for success/failure
  - Displays full file path to user

### 3. Permissions & Manifest Updates ✅

Added storage permissions to `AndroidManifest.xml`:
```xml
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"
    android:maxSdkVersion="32" />
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"
    android:maxSdkVersion="32" />
```

Note: On Android 13+, scoped storage is used automatically (no permissions needed for app-specific directories).

### 4. UI/UX Improvements ✅

#### TorCheckScreen Integration
- Now part of mandatory navigation flow
- Shows clear Tor status:
  - ❌ Not Installed → Install from Play Store
  - ⚠️ Installed but Not Running → Launch Orbot
  - ✅ Running → Continue to scan
- Fail-closed warnings prominently displayed

#### ModeScreen Redesign
- **Before**: Radio buttons for mode selection
- **After**: Security information display
- Shows all active security features:
  - Official Orbot (Real Tor Network)
  - Forced Tor routing via SOCKS proxy
  - App-level routing (not system-wide)
  - IP/DNS leak protection
  - Scan blocked if Tor disconnects
- Prominent "Start Secure Scan via Tor" button

#### ResultsScreen Enhancements
- Added database dump section (when available)
- Shows dump statistics
- Download button with icon
- Toast notifications for download status

## Security Architecture

### Fail-Closed Guarantees

1. **Pre-Flight Tor Check**: App checks Tor before allowing URL entry completion
2. **Pre-Scan Verification**: `verifyTorConnection()` called before each scan
3. **Mid-Scan Protection**: If Tor disconnects during scan, `SecurityException` thrown
4. **No Fallback**: No direct connections possible - Tor or nothing
5. **App-Level Routing**: Only this app uses Tor (via SOCKS proxy 127.0.0.1:9050)

### Anonymity Protection

- **IP Leak Prevention**: All HTTP requests go through Tor SOCKS proxy
- **DNS Leak Prevention**: OkHttp routes DNS through SOCKS proxy
- **No Clearnet Fallback**: SecurityException prevents silent fallback to direct connections
- **Official Tor**: Uses real Tor via Orbot (not simulated/embedded)

## Real Data vs Simulated Data

### Verification: All Features Use Real Data ✅

1. **HTTP Requests**: Uses OkHttp with real `client.newCall(request).execute()`
2. **SQL Payloads**: Real injection strings tested against live targets
3. **Database Detection**: Pattern matching on actual HTTP responses
4. **Data Extraction**: Regex parsing of real response bodies
5. **Database Dump**: Live enumeration with real payloads
6. **File Download**: Actual file I/O to device storage

**No simulated/fake functionality found in the codebase.**

## Testing Recommendations

### Before Production Use:

1. **Install Orbot** on test device
2. **Start Tor** in Orbot app
3. **Launch SQLi BlackBox Pro**
4. **Enter PIN** (any 4 digits)
5. **Enter target URL** (use a test environment you control)
6. **Verify Tor Check** screen shows "✅ Tor is Active"
7. **Start Scan** and wait for results
8. **Test DB Download**:
   - Check for download button if vulnerability found
   - Tap button and verify toast message
   - Navigate to file location and verify file contents
9. **Test Tor Disconnection**:
   - Stop Tor during scan
   - Verify scan fails with security error

### Expected File Location:
```
/storage/emulated/0/Android/data/com.sqliblackboxpro/files/Documents/SQLIBlackBoxPro_Dumps/db_dump_YYYY-MM-DD_HH-mm-ss.txt
```

### Testing Tor Enforcement:
```bash
# On device with adb access
adb shell
am force-stop org.torproject.android  # Stop Orbot
# Try to scan - should fail with Tor error
```

## Files Modified

1. **Models.kt**: Added `DatabaseDump` data class, updated `ScanResult`
2. **SQLScanner.kt**: 
   - Removed standard/stealth clients
   - Added Tor verification
   - Added database dump functionality
   - Added extraction helper methods
3. **SQLPayloads.kt**: Added comprehensive dump payloads for all database types
4. **ResultsScreen.kt**: 
   - Added database dump UI section
   - Added download button
   - Added download functionality
5. **MainActivity.kt**: 
   - Added Tor check navigation step
   - Added TorManager integration
6. **ScanViewModel.kt**: 
   - Added Tor state management
   - Added `checkTorStatus()` function
   - Enforced TOR mode only
7. **ModeScreen.kt**: Redesigned to show security information instead of mode selection
8. **AndroidManifest.xml**: Added storage permissions
9. **README.md**: Updated with new architecture and features

## Migration Guide

### For Users of Previous Versions:

**Breaking Changes:**
- STANDARD mode removed (Tor required)
- STEALTH mode removed (Tor required)
- Orbot must be installed and running
- Navigation flow includes mandatory Tor check

**New Features:**
- Database dump download
- Enhanced extraction (users, tables, schemas)
- Fail-closed security architecture
- Real-time Tor status verification

## Known Limitations

1. **Requires External Orbot**: App does not bundle Tor, requires Orbot installation
2. **Android 13+ Storage**: On newer Android versions, files saved to app-specific directory only
3. **Network Dependency**: Requires Tor network to be accessible
4. **Detection Evasion**: Some WAFs/IDS may still detect and block scans despite Tor usage

## Disclaimer

This tool is for **educational and authorized security testing only**. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing any system you do not own.

The Tor anonymity provided by this app is dependent on:
1. Orbot being correctly installed and configured
2. The Tor network being accessible
3. No user identification in other ways (e.g., login credentials, unique payloads)

This app provides network-level anonymity but does not protect against behavioral fingerprinting or application-level identification.
