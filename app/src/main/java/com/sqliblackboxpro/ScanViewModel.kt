package com.sqliblackboxpro

import android.os.Environment
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class ScanViewModel : ViewModel() {
    
    private val scanner = SQLScanner()
    
    private val CORRECT_PIN = "1234" // Simple PIN for demo purposes
    private val DUMP_PIN = "9999" // PIN for database dump feature
    
    companion object {
        private const val TAG = "ScanViewModel"
        private const val REPORT_LINE_WIDTH = 60 // Width of separator lines in reports
        private const val MAX_URL_LENGTH_IN_FILENAME = 30 // Max URL chars in filename
    }
    
    private val _pin = MutableStateFlow("")
    val pin: StateFlow<String> = _pin.asStateFlow()
    
    private val _pinError = MutableStateFlow<String?>(null)
    val pinError: StateFlow<String?> = _pinError.asStateFlow()
    
    private val _targetUrl = MutableStateFlow("")
    val targetUrl: StateFlow<String> = _targetUrl.asStateFlow()
    
    private val _selectedMode = MutableStateFlow(ScanMode.STANDARD)
    val selectedMode: StateFlow<ScanMode> = _selectedMode.asStateFlow()
    
    private val _scanState = MutableStateFlow<ScanState>(ScanState.Idle)
    val scanState: StateFlow<ScanState> = _scanState.asStateFlow()
    
    private val _injectionState = MutableStateFlow<InjectionState>(InjectionState.Idle)
    val injectionState: StateFlow<InjectionState> = _injectionState.asStateFlow()
    
    private val _databaseDumpState = MutableStateFlow<DatabaseDumpState>(DatabaseDumpState.Idle)
    val databaseDumpState: StateFlow<DatabaseDumpState> = _databaseDumpState.asStateFlow()
    
    private val _showDumpPinDialog = MutableStateFlow(false)
    val showDumpPinDialog: StateFlow<Boolean> = _showDumpPinDialog.asStateFlow()
    
    private val _dumpPin = MutableStateFlow("")
    val dumpPin: StateFlow<String> = _dumpPin.asStateFlow()
    
    private val _dumpPinError = MutableStateFlow<String?>(null)
    val dumpPinError: StateFlow<String?> = _dumpPinError.asStateFlow()
    
    fun setPin(pin: String) {
        _pin.value = pin
        _pinError.value = null
    }
    
    fun validatePin(): Boolean {
        return if (pin.value.length != 4 || !pin.value.all { it.isDigit() }) {
            _pinError.value = "PIN must be 4 digits"
            false
        } else if (pin.value != CORRECT_PIN) {
            _pinError.value = "Invalid PIN. Access denied."
            false
        } else {
            _pinError.value = null
            true
        }
    }
    
    fun setTargetUrl(url: String) {
        _targetUrl.value = url
    }
    
    fun validateUrl(): Boolean {
        val url = targetUrl.value
        return url.startsWith("http://", ignoreCase = true) ||
               url.startsWith("https://", ignoreCase = true)
    }
    
    fun setMode(mode: ScanMode) {
        _selectedMode.value = mode
    }
    
    fun startScan() {
        viewModelScope.launch {
            _scanState.value = ScanState.Scanning
            try {
                // Validate URL before scanning
                if (!validateUrl()) {
                    _scanState.value = ScanState.Error("Invalid URL. Please enter a valid http:// or https:// URL")
                    return@launch
                }
                
                val result = scanner.scanURL(targetUrl.value, selectedMode.value)
                _scanState.value = ScanState.Success(result)
            } catch (e: IllegalArgumentException) {
                _scanState.value = ScanState.Error(e.message ?: "Invalid input")
            } catch (e: java.io.IOException) {
                _scanState.value = ScanState.Error("Network error: ${e.message ?: "Cannot connect to server"}")
            } catch (e: Exception) {
                _scanState.value = ScanState.Error("Scan failed: ${e.message ?: "Unknown error occurred"}")
            }
        }
    }
    
    fun injectPayload(payload: String) {
        viewModelScope.launch {
            _injectionState.value = InjectionState.Injecting
            try {
                if (!validateUrl()) {
                    _injectionState.value = InjectionState.Error("Invalid URL")
                    return@launch
                }
                
                val output = scanner.executePayload(targetUrl.value, payload, selectedMode.value)
                _injectionState.value = InjectionState.Success(output)
            } catch (e: Exception) {
                _injectionState.value = InjectionState.Error(e.message ?: "Injection failed")
            }
        }
    }
    
    fun resetInjectionState() {
        _injectionState.value = InjectionState.Idle
    }
    
    fun showDumpPinDialog() {
        _showDumpPinDialog.value = true
        _dumpPin.value = ""
        _dumpPinError.value = null
    }
    
    fun hideDumpPinDialog() {
        _showDumpPinDialog.value = false
        _dumpPin.value = ""
        _dumpPinError.value = null
    }
    
    fun setDumpPin(pin: String) {
        _dumpPin.value = pin
        _dumpPinError.value = null
    }
    
    fun validateDumpPinAndDump() {
        if (dumpPin.value.length != 4 || !dumpPin.value.all { it.isDigit() }) {
            _dumpPinError.value = "PIN must be 4 digits"
            return
        }
        
        if (dumpPin.value != DUMP_PIN) {
            _dumpPinError.value = "Invalid PIN. Access denied."
            return
        }
        
        _dumpPinError.value = null
        hideDumpPinDialog()
        startDatabaseDump()
    }
    
    private fun startDatabaseDump() {
        viewModelScope.launch {
            _databaseDumpState.value = DatabaseDumpState.Dumping
            try {
                if (!validateUrl()) {
                    _databaseDumpState.value = DatabaseDumpState.Error("Invalid URL")
                    return@launch
                }
                
                val currentState = scanState.value
                val dbType = if (currentState is ScanState.Success) {
                    currentState.result.databaseType
                } else {
                    DatabaseType.UNKNOWN
                }
                
                val dumpedData = scanner.dumpDatabase(targetUrl.value, dbType, selectedMode.value)
                
                // Save to file
                val filePath = saveDatabaseDumpToFile(dumpedData, targetUrl.value, dbType)
                
                _databaseDumpState.value = DatabaseDumpState.Success(dumpedData, filePath)
            } catch (e: Exception) {
                Log.e(TAG, "Database dump failed", e)
                _databaseDumpState.value = DatabaseDumpState.Error(e.message ?: "Database dump failed")
            }
        }
    }
    
    private fun saveDatabaseDumpToFile(data: Map<String, List<String>>, url: String, dbType: DatabaseType): String? {
        return try {
            // Create directory in Downloads folder
            val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            val sqlInjectionDir = File(downloadsDir, "SQLiBlackBoxPro")
            if (!sqlInjectionDir.exists()) {
                sqlInjectionDir.mkdirs()
            }
            
            // Create filename with timestamp
            val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
            val sanitizedUrl = url.replace(Regex("[^a-zA-Z0-9]"), "_").take(MAX_URL_LENGTH_IN_FILENAME)
            val fileName = "DB_DUMP_${sanitizedUrl}_${timestamp}.txt"
            val file = File(sqlInjectionDir, fileName)
            
            // Write data to file
            file.bufferedWriter().use { writer ->
                writer.write("=".repeat(REPORT_LINE_WIDTH))
                writer.newLine()
                writer.write("SQL INJECTION DATABASE DUMP REPORT")
                writer.newLine()
                writer.write("=".repeat(REPORT_LINE_WIDTH))
                writer.newLine()
                writer.newLine()
                writer.write("Target URL: $url")
                writer.newLine()
                writer.write("Database Type: ${dbType.name}")
                writer.newLine()
                writer.write("Timestamp: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())}")
                writer.newLine()
                writer.write("Scan Mode: ${selectedMode.value}")
                writer.newLine()
                writer.write("=".repeat(REPORT_LINE_WIDTH))
                writer.newLine()
                writer.newLine()
                
                data.forEach { (category, items) ->
                    writer.write("\n### $category ###")
                    writer.newLine()
                    writer.write("-".repeat(REPORT_LINE_WIDTH))
                    writer.newLine()
                    items.forEach { item ->
                        writer.write("  - $item")
                        writer.newLine()
                    }
                    writer.newLine()
                }
                
                writer.write("\n")
                writer.write("=".repeat(REPORT_LINE_WIDTH))
                writer.newLine()
                writer.write("END OF REPORT")
                writer.newLine()
                writer.write("=".repeat(REPORT_LINE_WIDTH))
            }
            
            Log.i(TAG, "Database dump saved to: ${file.absolutePath}")
            file.absolutePath
        } catch (e: Exception) {
            Log.e(TAG, "Failed to save database dump to file", e)
            null
        }
    }
    
    fun resetDatabaseDumpState() {
        _databaseDumpState.value = DatabaseDumpState.Idle
    }
    
    fun resetScan() {
        _scanState.value = ScanState.Idle
        _injectionState.value = InjectionState.Idle
        _databaseDumpState.value = DatabaseDumpState.Idle
    }
}
