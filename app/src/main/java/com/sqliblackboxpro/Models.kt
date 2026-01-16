package com.sqliblackboxpro

enum class ScanMode {
    STANDARD,
    TOR,
    STEALTH
}

enum class DatabaseType {
    MYSQL,
    POSTGRESQL,
    MSSQL,
    ORACLE,
    SQLITE,
    UNKNOWN
}

data class ScanResult(
    val isVulnerable: Boolean,
    val databaseType: DatabaseType,
    val extractedData: List<String>,
    val payloadUsed: String,
    val responseDetails: String
)

sealed class ScanState {
    object Idle : ScanState()
    object Scanning : ScanState()
    data class Success(val result: ScanResult) : ScanState()
    data class Error(val message: String) : ScanState()
}

sealed class TorState {
    object Checking : TorState()
    object NotInstalled : TorState()
    object InstalledNotRunning : TorState()
    object Running : TorState()
    data class Error(val message: String) : TorState()
}
