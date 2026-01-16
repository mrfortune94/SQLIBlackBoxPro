package com.sqliblackboxpro

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            SQLiBlackBoxProTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    SQLiBlackBoxProApp()
                }
            }
        }
    }
}

@Composable
fun SQLiBlackBoxProApp() {
    val navController = rememberNavController()
    val viewModel: ScanViewModel = viewModel()
    
    val pin by viewModel.pin.collectAsState()
    val pinError by viewModel.pinError.collectAsState()
    val targetUrl by viewModel.targetUrl.collectAsState()
    val selectedMode by viewModel.selectedMode.collectAsState()
    val scanState by viewModel.scanState.collectAsState()
    val injectionState by viewModel.injectionState.collectAsState()
    val databaseDumpState by viewModel.databaseDumpState.collectAsState()
    val showDumpPinDialog by viewModel.showDumpPinDialog.collectAsState()
    val dumpPin by viewModel.dumpPin.collectAsState()
    val dumpPinError by viewModel.dumpPinError.collectAsState()
    
    NavHost(navController = navController, startDestination = "pin") {
        composable("pin") {
            PinScreen(
                pin = pin,
                onPinChange = { viewModel.setPin(it) },
                onContinue = {
                    if (viewModel.validatePin()) {
                        navController.navigate("url")
                    }
                },
                errorMessage = pinError,
                onViewLibrary = {
                    navController.navigate("library")
                }
            )
        }
        
        composable("url") {
            UrlScreen(
                url = targetUrl,
                onUrlChange = { viewModel.setTargetUrl(it) },
                onContinue = {
                    if (viewModel.validateUrl()) {
                        navController.navigate("mode")
                    }
                }
            )
        }
        
        composable("mode") {
            ModeScreen(
                selectedMode = selectedMode,
                onModeSelected = { viewModel.setMode(it) },
                onStartScan = {
                    viewModel.startScan()
                    navController.navigate("results")
                }
            )
        }
        
        composable("results") {
            ResultsScreen(
                scanState = scanState,
                injectionState = injectionState,
                databaseDumpState = databaseDumpState,
                onNewScan = {
                    viewModel.resetScan()
                    navController.navigate("pin") {
                        popUpTo("pin") { inclusive = true }
                    }
                },
                onInjectPayload = { payload ->
                    viewModel.injectPayload(payload)
                },
                onResetInjection = {
                    viewModel.resetInjectionState()
                },
                onDatabaseDump = {
                    viewModel.showDumpPinDialog()
                },
                onResetDatabaseDump = {
                    viewModel.resetDatabaseDumpState()
                }
            )
        }
        
        composable("library") {
            PayloadLibraryScreen(
                onBack = {
                    navController.popBackStack()
                },
                onAddCustomPayload = { payload, description, category ->
                    SQLPayloads.addCustomPayload(payload, description, category)
                }
            )
        }
    }
    
    // PIN Dialog for Database Dump
    if (showDumpPinDialog) {
        DumpPinDialog(
            pin = dumpPin,
            onPinChange = { viewModel.setDumpPin(it) },
            onDismiss = { viewModel.hideDumpPinDialog() },
            onConfirm = { viewModel.validateDumpPinAndDump() },
            errorMessage = dumpPinError
        )
    }
}

@Composable
fun DumpPinDialog(
    pin: String,
    onPinChange: (String) -> Unit,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
    errorMessage: String?
) {
    Dialog(onDismissRequest = onDismiss) {
        Card {
            Column(
                modifier = Modifier.padding(16.dp)
            ) {
                Text(
                    text = "⚠️ Database Dump - PIN Required",
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.error
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "This feature dumps sensitive database information. Enter the dump PIN to proceed.",
                    style = MaterialTheme.typography.bodySmall
                )
                Spacer(modifier = Modifier.height(16.dp))
                
                OutlinedTextField(
                    value = pin,
                    onValueChange = { 
                        if (it.length <= 4 && it.all { char -> char.isDigit() }) {
                            onPinChange(it)
                        }
                    },
                    label = { Text("Dump PIN") },
                    isError = errorMessage != null,
                    supportingText = if (errorMessage != null) {
                        { Text(errorMessage, color = MaterialTheme.colorScheme.error) }
                    } else {
                        { Text("Hint: Try 9999") }
                    },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                
                Spacer(modifier = Modifier.height(16.dp))
                
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    TextButton(onClick = onDismiss) {
                        Text("Cancel")
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Button(onClick = onConfirm) {
                        Text("Confirm")
                    }
                }
            }
        }
    }
}

@Composable
fun SQLiBlackBoxProTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = MaterialTheme.colorScheme,
        typography = MaterialTheme.typography,
        content = content
    )
}
