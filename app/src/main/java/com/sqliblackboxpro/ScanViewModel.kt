package com.sqliblackboxpro

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
    
    private val _selectedMode = MutableStateFlow(ScanMode.STANDARD)
    val selectedMode: StateFlow<ScanMode> = _selectedMode.asStateFlow()
    
    private val _scanState = MutableStateFlow<ScanState>(ScanState.Idle)
    val scanState: StateFlow<ScanState> = _scanState.asStateFlow()
    
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
    
    fun startScan() {
        viewModelScope.launch {
            _scanState.value = ScanState.Scanning
            try {
                val result = scanner.scanURL(targetUrl.value, selectedMode.value)
                _scanState.value = ScanState.Success(result)
            } catch (e: Exception) {
                _scanState.value = ScanState.Error(e.message ?: "Unknown error occurred")
            }
        }
    }
    
    fun resetScan() {
        _scanState.value = ScanState.Idle
    }
}
