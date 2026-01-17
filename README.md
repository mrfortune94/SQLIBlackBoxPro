# SQLi BlackBox Pro

A professional SQL injection testing tool for Android built with Jetpack Compose.

## 🔒 Security Architecture

This application implements **FAIL-CLOSED TOR ROUTING** for maximum anonymity and security:

### Mandatory Security Features

1. **Official Orbot (Real Tor Network)**
   - Uses the real Tor network via Orbot
   - Maintained and audited by the Tor Project
   - No simulated or embedded Tor implementations

2. **Forced Tor Routing (Fail-Closed)**
   - ALL app traffic routed through Orbot's SOCKS proxy (127.0.0.1:9050)
   - Network access BLOCKED if Tor disconnects
   - App REFUSES to run unless Tor is active
   - Prevents: IP leaks, DNS leaks, silent clearnet fallback

3. **App-Level Tor Routing**
   - Only this app uses Tor (not system-wide)
   - Reduces fingerprinting
   - Doesn't break system services

## Features

- **PIN Protection**: Secure 4-digit PIN entry
- **Mandatory Tor Routing**: 
  - Enforces Tor connection before any scanning
  - Fail-closed architecture prevents leaks
  - Real-time Tor status verification
- **Comprehensive Payload Library**: 
  - MySQL, PostgreSQL, MSSQL, Oracle, and SQLite injection payloads
  - Error-based and UNION-based SQL injection techniques
- **Database Detection**: Automatically identifies database type from error responses
- **Data Extraction**: Attempts to extract sensitive data from vulnerable endpoints
- **Database Dump**: 
  - Comprehensive database enumeration
  - User credentials extraction
  - Table and schema discovery
  - **DB DOWNLOAD (USERS)** button to save results to device storage
- **Real-time Results**: Displays vulnerabilities, database type, and extracted data

## Architecture

### Navigation Flow
```
PIN Screen → URL Input → Tor Check → Secure Scanning → Results
```

### Core Components

#### 1. **Models.kt**
- `ScanMode`: TOR mode (enforced)
- `DatabaseType`: Detected database types (MySQL, PostgreSQL, etc.)
- `ScanResult`: Contains vulnerability status, database type, extracted data, database dump
- `ScanState`: Manages scan lifecycle (Idle, Scanning, Success, Error)
- `TorState`: Tor connection states (Checking, NotInstalled, InstalledNotRunning, Running, Error)
- `DatabaseDump`: Comprehensive database extraction results

#### 2. **SQLPayloads.kt**
- `DETECTION_PAYLOADS`: Basic SQL injection tests
- `MYSQL_PAYLOADS`, `POSTGRESQL_PAYLOADS`, etc.: Database-specific payloads
- `DATA_EXTRACTION_PAYLOADS`: Attempts to extract user data, tables, schemas
- `MYSQL_DUMP_PAYLOADS`, `POSTGRESQL_DUMP_PAYLOADS`, etc.: Comprehensive database enumeration

#### 3. **SQLScanner.kt**
- **Tor-Only Mode**: All requests route through Tor SOCKS proxy (127.0.0.1:9050)
- **Fail-Closed Verification**: Checks Tor connection before each scan
- **Error Detection**: Pattern matching for SQL error messages
- **Database Detection**: Identifies DB type from error signatures
- **Data Extraction**: Parses responses for leaked credentials and data
- **Database Dump**: Comprehensive enumeration of users, tables, schemas

#### 4. **TorManager (OrbotHelper.kt)**
- Orbot installation detection
- Tor connection status verification
- Launch Orbot functionality
- Play Store redirection for installation

#### 5. **ScanViewModel.kt**
- Manages application state using Kotlin StateFlow
- Input validation for PIN and URL
- Asynchronous scanning with Coroutines
- Tor status management
- Error handling and state transitions

#### 6. **UI Screens (Jetpack Compose)**
- `PinScreen.kt`: PIN entry with masked input
- `UrlScreen.kt`: URL input with validation
- `TorCheckScreen.kt`: Tor status verification and enforcement
- `ModeScreen.kt`: Security information display (Tor-only)
- `ResultsScreen.kt`: Displays scan results with database dump download
- `MainActivity.kt`: Navigation and app composition

## Building the App

### Prerequisites
- Android Studio Arctic Fox or later
- JDK 8 or higher
- Android SDK 26 (minimum) - 34 (target)
- Gradle 8.2

### Build Commands
```bash
# Build debug APK
./gradlew assembleDebug

# Build release APK
./gradlew assembleRelease

# Install on connected device
./gradlew installDebug
```

### Dependencies
```kotlin
// Core Android
androidx.core:core-ktx:1.12.0
androidx.lifecycle:lifecycle-runtime-ktx:2.6.2
androidx.activity:activity-compose:1.8.1

// Jetpack Compose
androidx.compose.ui:ui
androidx.compose.material3:material3
androidx.navigation:navigation-compose:2.7.5
androidx.lifecycle:lifecycle-viewmodel-compose:2.6.2

// Networking
com.squareup.okhttp3:okhttp:4.12.0

// Coroutines
org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3
```

## Usage

1. **Launch the app** and enter a 4-digit PIN
2. **Enter target URL** (e.g., `http://example.com/page.php?id=1`)
3. **Tor Check**: The app verifies Tor is running
   - If Orbot is not installed, you'll be prompted to install it
   - If Tor is not running, you'll be prompted to start it
   - Scanning is BLOCKED until Tor is active
4. **Review Security**: Confirm fail-closed security features are active
5. **Start scan** and wait for results
6. **Review findings**: Vulnerability status, database type, successful payload, and extracted data
7. **Download Database Dump**: Click "DB DOWNLOAD (USERS)" to save comprehensive results to device storage

## Security Features

### Fail-Closed Architecture
The scanner implements fail-closed security:
1. Verifies Tor connection before URL entry completes
2. Checks Tor status again before each scan
3. Throws SecurityException if Tor disconnects during scan
4. Blocks all network activity when Tor is unavailable

### Injection Detection
The scanner tests for vulnerabilities by:
1. Injecting payloads into URL parameters
2. Analyzing responses for SQL error messages
3. Detecting error patterns specific to different databases

### Database Fingerprinting
Identifies databases by matching error messages:
- **MySQL**: "mysql", "mysqli", "valid MySQL result"
- **PostgreSQL**: "postgresql", "pg_query", "Npgsql"
- **MSSQL**: "Microsoft SQL", "SQL Server"
- **Oracle**: "ORA-", "oracle"
- **SQLite**: "sqlite", "sqlite3"

### Database Dump & Data Extraction
Comprehensive enumeration attempts to extract:
- User credentials (username:hash patterns)
- Database names and schemas
- Table names and structures
- Column information
- Full database dumps saved to device storage

## Network Requirements

### Tor Mode (Mandatory)
For the app to work, you need:
1. **Orbot installed** from Google Play Store
2. **Tor service running** in Orbot
3. SOCKS proxy listening on 127.0.0.1:9050

### Permissions
The app requires:
- `INTERNET`: For HTTP requests through Tor
- `ACCESS_NETWORK_STATE`: To check network availability
- `WRITE_EXTERNAL_STORAGE`: To save database dump files (Android 12 and below)
- `READ_EXTERNAL_STORAGE`: To access saved dump files (Android 12 and below)

### Storage Location
Database dumps are saved to:
- `<External Storage>/Android/data/com.sqliblackboxpro/files/Documents/SQLIBlackBoxPro_Dumps/`
- Files named: `db_dump_YYYY-MM-DD_HH-mm-ss.txt`

## Building the App

### Automated Builds (GitHub Actions)

This repository includes automated workflows for building APKs:

**Debug Builds**: Automatically triggered on push/PR to `main` or `develop` branches
- Download debug APK from the Actions tab → Artifacts

**Release Builds**: Triggered by version tags (e.g., `v1.0.0`) or manual dispatch
- Signed APKs (when keystore secrets are configured)
- Automatically creates GitHub Releases
- Download from Releases section or Actions artifacts

📖 See [WORKFLOWS_GUIDE.md](WORKFLOWS_GUIDE.md) for detailed instructions on:
- Setting up release signing
- Configuring GitHub Secrets
- Manual workflow triggers
- Local build instructions

### Local Builds

**Debug APK**:
```bash
./gradlew assembleDebug
```
Output: `app/build/outputs/apk/debug/app-debug.apk`

**Release APK**:
```bash
./gradlew assembleRelease
```
Output: `app/build/outputs/apk/release/app-release.apk`

For signed release builds, configure your keystore and environment variables as described in [WORKFLOWS_GUIDE.md](WORKFLOWS_GUIDE.md).

## Code Quality

- ✅ **No placeholders or simulated data**: All scanning uses real HTTP requests
- ✅ **Production-ready error handling**: Try-catch blocks, error states
- ✅ **Input validation**: PIN length, URL format validation
- ✅ **Loading states**: CircularProgressIndicator during scans
- ✅ **Proper navigation**: Compose Navigation with state preservation
- ✅ **Real payloads**: Actual SQL injection strings tested in production
- ✅ **Database detection**: Pattern matching on real error messages
- ✅ **Data extraction**: Regex parsing of response bodies

## Limitations

- Tor mode requires Tor to be running externally (not bundled)
- Some WAFs/IDS may detect and block scan attempts
- Data extraction depends on error verbosity and injection success
- HTTPS certificates are not validated in Standard mode (for testing)

## Disclaimer

This tool is for **educational and authorized security testing only**. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing any system you do not own.

## License

Educational purposes only. Not for malicious use.
