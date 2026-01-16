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

data class VulnerablePayload(
    val payload: String,
    val description: String,
    val response: String
)

data class ScanResult(
    val isVulnerable: Boolean,
    val databaseType: DatabaseType,
    val extractedData: List<String>,
    val payloadUsed: String,
    val responseDetails: String,
    val vulnerablePayloads: List<VulnerablePayload> = emptyList()
)

sealed class ScanState {
    object Idle : ScanState()
    object Scanning : ScanState()
    data class Success(val result: ScanResult) : ScanState()
    data class Error(val message: String) : ScanState()
}

sealed class InjectionState {
    object Idle : InjectionState()
    object Injecting : InjectionState()
    data class Success(val output: String) : InjectionState()
    data class Error(val message: String) : InjectionState()
}

sealed class DatabaseDumpState {
    object Idle : DatabaseDumpState()
    object Dumping : DatabaseDumpState()
    data class Success(val dumpedData: Map<String, List<String>>) : DatabaseDumpState()
    data class Error(val message: String) : DatabaseDumpState()
}
