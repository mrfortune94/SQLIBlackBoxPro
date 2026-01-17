package com.sqliblackboxpro

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class ScanViewModel : ViewModel() {
    
    private val scanner = SQLScanner()
    
    private val _pin = MutableStateFlow("")
    val pin: StateFlow<String> = _pin.asStateFlow()
    
    private val _targetUrl = MutableStateFlow("")
    val targetUrl: StateFlow<String> = _targetUrl.asStateFlow()
    
    private val _selectedMode = MutableStateFlow(ScanMode.TOR) // Default to TOR (fail-closed)
    val selectedMode: StateFlow<ScanMode> = _selectedMode.asStateFlow()
    
    private val _scanState = MutableStateFlow<ScanState>(ScanState.Idle)
    val scanState: StateFlow<ScanState> = _scanState.asStateFlow()
    
    private val _torState = MutableStateFlow<TorState>(TorState.Checking)
    val torState: StateFlow<TorState> = _torState.asStateFlow()
    
    fun setPin(pin: String) {
        _pin.value = pin
    }
    
    fun validatePin(): Boolean {
        return pin.value.length == 4 && pin.value.all { it.isDigit() }
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
    
    /**
     * Check Tor status - FAIL-CLOSED security requirement
     */
    fun checkTorStatus(context: Context) {
        viewModelScope.launch {
            _torState.value = TorState.Checking
            
            try {
                when {
                    !TorManager.isOrbotInstalled(context) -> {
                        _torState.value = TorState.NotInstalled
                    }
                    !TorManager.isTorRunning() -> {
                        _torState.value = TorState.InstalledNotRunning
                    }
                    else -> {
                        _torState.value = TorState.Running
                    }
                }
            } catch (e: Exception) {
                _torState.value = TorState.Error(e.message ?: "Unknown error checking Tor status")
            }
        }
    }
    
    fun startScan() {
        viewModelScope.launch {
            _scanState.value = ScanState.Scanning
            try {
                // FAIL-CLOSED: Always use TOR mode
                val result = scanner.scanURL(targetUrl.value, ScanMode.TOR)
                _scanState.value = ScanState.Success(result)
            } catch (e: SecurityException) {
                // Tor disconnected during scan
                _scanState.value = ScanState.Error("SECURITY ERROR: ${e.message}")
            } catch (e: Exception) {
                _scanState.value = ScanState.Error(e.message ?: "Unknown error occurred")
            }
        }
    }
    
    fun resetScan() {
        _scanState.value = ScanState.Idle
        _torState.value = TorState.Checking
    }
}
