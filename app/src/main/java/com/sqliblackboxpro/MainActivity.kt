package com.sqliblackboxpro

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch

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
    val targetUrl by viewModel.targetUrl.collectAsState()
    val selectedMode by viewModel.selectedMode.collectAsState()
    val scanState by viewModel.scanState.collectAsState()
    val torState by viewModel.torState.collectAsState()
    
    val context = androidx.compose.ui.platform.LocalContext.current
    
    NavHost(navController = navController, startDestination = "pin") {
        composable("pin") {
            PinScreen(
                pin = pin,
                onPinChange = { viewModel.setPin(it) },
                onContinue = {
                    if (viewModel.validatePin()) {
                        navController.navigate("url")
                    }
                }
            )
        }
        
        composable("url") {
            UrlScreen(
                url = targetUrl,
                onUrlChange = { viewModel.setTargetUrl(it) },
                onContinue = {
                    if (viewModel.validateUrl()) {
                        // FAIL-CLOSED: Check Tor status before proceeding
                        viewModel.checkTorStatus(context)
                        navController.navigate("torcheck")
                    }
                }
            )
        }
        
        composable("torcheck") {
            TorCheckScreen(
                torState = torState,
                onCheckAgain = { viewModel.checkTorStatus(context) },
                onLaunchOrbot = { 
                    TorManager.launchOrbot(context)
                },
                onInstallOrbot = { 
                    TorManager.openOrbotInPlayStore(context)
                },
                onContinue = {
                    // Only allow continuation if Tor is running
                    if (torState is TorState.Running) {
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
                onNewScan = {
                    viewModel.resetScan()
                    navController.navigate("pin") {
                        popUpTo("pin") { inclusive = true }
                    }
                }
            )
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
