# SQLi BlackBox Pro

A professional SQL injection testing tool for Android built with Jetpack Compose.

## Features

- **PIN Protection**: Secure 4-digit PIN entry
- **Multiple Scan Modes**:
  - **Standard**: Direct HTTP requests
  - **Tor**: Routes traffic through Tor network via SOCKS proxy (127.0.0.1:9050)
  - **Stealth**: Randomized User-Agent spoofing for evasion
- **Comprehensive Payload Library**: 
  - MySQL, PostgreSQL, MSSQL, Oracle, and SQLite injection payloads
  - Error-based and UNION-based SQL injection techniques
- **Database Detection**: Automatically identifies database type from error responses
- **Data Extraction**: Attempts to extract sensitive data from vulnerable endpoints
- **Real-time Results**: Displays vulnerabilities, database type, and extracted data

## Architecture

### Navigation Flow
```
PIN Screen → URL Input → Mode Selection → Scanning → Results
```

### Core Components

#### 1. **Models.kt**
- `ScanMode`: Enum for scan modes (STANDARD, TOR, STEALTH)
- `DatabaseType`: Detected database types (MySQL, PostgreSQL, etc.)
- `ScanResult`: Contains vulnerability status, database type, extracted data
- `ScanState`: Manages scan lifecycle (Idle, Scanning, Success, Error)

#### 2. **SQLPayloads.kt**
- `DETECTION_PAYLOADS`: Basic SQL injection tests
- `MYSQL_PAYLOADS`, `POSTGRESQL_PAYLOADS`, etc.: Database-specific payloads
- `DATA_EXTRACTION_PAYLOADS`: Attempts to extract user data, tables, schemas

#### 3. **SQLScanner.kt**
- **Standard Mode**: Direct HTTP requests using OkHttp
- **Tor Mode**: Configures SOCKS proxy (127.0.0.1:9050) for Tor routing
- **Stealth Mode**: Rotates through realistic User-Agent strings
- **Error Detection**: Pattern matching for SQL error messages
- **Database Detection**: Identifies DB type from error signatures
- **Data Extraction**: Parses responses for leaked credentials and data

#### 4. **ScanViewModel.kt**
- Manages application state using Kotlin StateFlow
- Input validation for PIN and URL
- Asynchronous scanning with Coroutines
- Error handling and state transitions

#### 5. **UI Screens (Jetpack Compose)**
- `PinScreen.kt`: PIN entry with masked input
- `UrlScreen.kt`: URL input with validation
- `ModeScreen.kt`: Radio button selection for scan modes
- `ResultsScreen.kt`: Displays scan results with loading states
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
3. **Select scan mode**:
   - Standard for direct testing
   - Tor for anonymous scanning (requires Tor running on port 9050)
   - Stealth for user-agent rotation
4. **Start scan** and wait for results
5. **Review findings**: Vulnerability status, database type, successful payload, and extracted data

## Security Features

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

### Data Extraction
Attempts to extract:
- User credentials (username:hash patterns)
- Database names
- Table names
- Column information

## Network Requirements

### Tor Mode
For Tor mode to work, you need:
1. Tor service running locally
2. SOCKS proxy listening on 127.0.0.1:9050

### Permissions
The app requires:
- `INTERNET`: For HTTP requests
- `ACCESS_NETWORK_STATE`: To check network availability

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
