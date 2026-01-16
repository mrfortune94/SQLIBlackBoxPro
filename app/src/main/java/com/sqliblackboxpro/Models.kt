package com.sqliblackboxpro

// Removed all non-Tor modes - app now ONLY routes through Tor for maximum anonymity
// Fail-closed architecture: if Tor is not available, app will not function
enum class ScanMode {
    TOR_ONLY // Compulsory Tor routing - all traffic through Orbot SOCKS proxy
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
    data class Success(val dumpedData: Map<String, List<String>>, val savedFilePath: String? = null) : DatabaseDumpState()
    data class Error(val message: String) : DatabaseDumpState()
}

sealed class TorState {
    object Checking : TorState()
    object NotInstalled : TorState()
    object InstalledNotRunning : TorState()
    object Running : TorState()
    data class Error(val message: String) : TorState()
}
