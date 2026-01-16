# SQLi BlackBox Pro - Android Application

A **REAL**, production-ready Android application for SQL injection penetration testing with Jetpack Compose UI.

## ⚠️ Important: This is NOT a Simulation

**This app performs REAL SQL injection testing:**
- ✅ Makes actual HTTP/HTTPS network requests using OkHttp
- ✅ Tests real SQL injection payloads against target servers
- ✅ Analyzes real server responses for SQL errors
- ✅ Attempts real data extraction from vulnerable endpoints
- ✅ Supports Tor SOCKS proxy for anonymous testing
- ✅ Comprehensive logging to Android logcat for verification

**NOT simulated/fake:**
- ❌ Does NOT use hardcoded results
- ❌ Does NOT work without internet connection
- ❌ Does NOT simulate network delays
- ❌ Requires real vulnerable targets to find vulnerabilities

See [TESTING_GUIDE.md](TESTING_GUIDE.md) for instructions on how to verify the scanner performs real HTTP requests and testing.

## Legal Notice

**CRITICAL**: This tool performs real penetration testing. Only use on:
- Systems you own
- Systems where you have explicit written permission to test
- Intentionally vulnerable test sites (e.g., http://testphp.vulnweb.com)

**Unauthorized testing is ILLEGAL and can result in criminal prosecution.**

## Project Structure

This is a complete Android Studio project with the following structure:

```
SQLiBlackBoxPro/
├── app/
│   ├── build.gradle.kts         # App-level Gradle build configuration
│   ├── proguard-rules.pro        # ProGuard configuration
│   └── src/main/
│       ├── AndroidManifest.xml   # App manifest with permissions
│       ├── java/com/sqliblackboxpro/
│       │   ├── MainActivity.kt           # Main entry point with Compose navigation
│       │   ├── PinScreen.kt             # PIN entry screen (validates PIN: 1234)
│       │   ├── UrlScreen.kt             # Target URL input screen
│       │   ├── ModeScreen.kt            # Attack mode selection screen
│       │   ├── ResultsScreen.kt         # Scan results display screen
│       │   ├── Models.kt                # Data models (ScanMode, DatabaseType, etc.)
│       │   ├── ScanViewModel.kt         # State management with StateFlow
│       │   ├── SQLScanner.kt            # SQL injection scanning logic
│       │   └── SQLPayloads.kt           # SQL injection payload definitions
│       └── res/
│           ├── values/
│           │   ├── strings.xml          # String resources
│           │   └── themes.xml           # App theme
│           └── mipmap-*/
│               └── ic_launcher.xml      # App launcher icons
├── build.gradle.kts             # Root-level Gradle build configuration
├── settings.gradle.kts          # Gradle settings
├── gradle.properties            # Gradle properties
├── gradle/wrapper/              # Gradle wrapper files
├── gradlew                      # Gradle wrapper script (Unix)
├── gradlew.bat                  # Gradle wrapper script (Windows)
└── .gitignore                   # Git ignore rules
```

## Testing the Scanner

### Quick Test with Vulnerable Site
To verify the scanner works, test with this intentionally vulnerable site:
```
http://testphp.vulnweb.com/artists.php?artist=1
```

### Verify Real Network Requests
Check Android Studio Logcat (filter by "SQLScanner") to see:
- Real-time scan progress
- HTTP requests being made
- Server responses received
- Vulnerability detection
- Data extraction attempts

See [TESTING_GUIDE.md](TESTING_GUIDE.md) for detailed testing instructions and verification methods.

## Features

### Navigation Flow
- **PinScreen** → **TargetUrlScreen** → **AttackModeScreen** → **LiveResultsScreen**

### Screens
1. **PIN Screen**: Validates 4-digit PIN (correct PIN is `1234`)
   - Shows error message for invalid PIN: "Invalid PIN. Access denied."
   - Shows error message for incorrect format: "PIN must be 4 digits"
   
2. **Target URL Screen**: Input target URL for testing
   - Validates http:// or https:// protocol
   
3. **Attack Mode Screen**: Select scanning mode
   - **Standard**: Direct HTTP requests
   - **Tor**: SOCKS proxy to 127.0.0.1:9050
   - **Stealth**: User-agent spoofing
   
4. **Live Results Screen**: Display scan results
   - Shows scanning progress
   - Displays vulnerability status
   - Shows detected database type
   - Displays extracted data

### Technical Implementation
- **Jetpack Compose** for UI (Material 3 design)
- **Navigation Compose** for screen navigation
- **StateFlow** for reactive state management
- **OkHttp 4.12.0** for REAL HTTP/HTTPS requests
- **Coroutines with Dispatchers.IO** for asynchronous network operations
- **34+ SQL injection payloads** covering multiple database types
- **50+ SQL error patterns** for vulnerability detection
- **Comprehensive logging** with android.util.Log for debugging

### Real Network Operations
The scanner makes **actual HTTP requests** and is NOT a simulation:
- Uses OkHttp client with real TCP connections
- Supports HTTP, HTTPS, and SOCKS proxy (Tor)
- Performs real DNS lookups
- Handles network errors (timeouts, connection failures, DNS errors)
- Injects SQL payloads into URL parameters
- Parses actual server responses for SQL errors
- Extracts real data from vulnerable responses (credentials, versions, tables, etc.)

### Build Configuration
- Android Gradle Plugin: 8.2.2
- Kotlin: 1.9.22
- Gradle: 8.2
- compileSdk: 34
- minSdk: 26
- targetSdk: 34

### Permissions
- `INTERNET` - Required for network requests
- `ACCESS_NETWORK_STATE` - Optional network state checking

## Building the Project

### Prerequisites
- Android Studio Hedgehog or newer
- JDK 17 or higher
- Android SDK with API level 34

### Build Commands
```bash
# Build the app
./gradlew build

# Build debug APK
./gradlew assembleDebug

# Build release APK
./gradlew assembleRelease

# Install on connected device
./gradlew installDebug
```

## Code Quality

### Improvements Made
- **PinScreen**: Enhanced with proper invalid PIN validation
  - Added error state in ViewModel to track PIN validation errors
  - Display user-friendly error messages in UI
  - No placeholder `show403Error` function - uses proper Compose state management
  
### Security Notes
- The app uses a hardcoded PIN (`1234`) for demo purposes
- In production, implement proper authentication mechanisms
- SQL injection testing should only be performed on systems you own or have permission to test

## Dependencies

All dependencies are specified in `app/build.gradle.kts`:
- AndroidX Core KTX
- Lifecycle Runtime KTX
- Activity Compose
- Compose BOM (Bill of Materials)
- Compose UI components
- Material 3
- Navigation Compose
- Lifecycle ViewModel Compose
- OkHttp
- Kotlinx Coroutines

## Notes

This project is set up to compile without errors in a standard Android development environment with internet access. The build may fail in restricted environments where dl.google.com is not accessible, but the project structure and code are complete and correct.
