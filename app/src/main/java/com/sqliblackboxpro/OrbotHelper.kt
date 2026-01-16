package com.sqliblackboxpro

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.util.Log
import kotlinx.coroutines.delay
import java.net.Socket

/**
 * Helper class for Orbot integration
 * Provides fail-closed Tor routing - blocks all traffic if Tor is not available
 */
object TorManager {
    private const val TAG = "TorManager"
    private const val ORBOT_PACKAGE_NAME = "org.torproject.android"
    private const val TOR_SOCKS_HOST = "127.0.0.1"
    private const val TOR_SOCKS_PORT = 9050
    private const val MAX_TOR_CHECK_ATTEMPTS = 10
    private const val TOR_CHECK_DELAY_MS = 1000L
    
    /**
     * Check if Orbot is installed on the device
     */
    fun isOrbotInstalled(context: Context): Boolean {
        return try {
            context.packageManager.getPackageInfo(ORBOT_PACKAGE_NAME, 0)
            Log.d(TAG, "Orbot is installed")
            true
        } catch (e: PackageManager.NameNotFoundException) {
            Log.w(TAG, "Orbot is NOT installed")
            false
        }
    }
    
    /**
     * Check if Tor SOCKS proxy is running and accepting connections
     */
    suspend fun isTorRunning(): Boolean {
        return try {
            Socket(TOR_SOCKS_HOST, TOR_SOCKS_PORT).use { socket ->
                val isConnected = socket.isConnected
                Log.d(TAG, "Tor SOCKS proxy check: ${if (isConnected) "RUNNING" else "NOT RUNNING"}")
                isConnected
            }
        } catch (e: Exception) {
            Log.w(TAG, "Tor SOCKS proxy is NOT running: ${e.message}")
            false
        }
    }
    
    /**
     * Launch Orbot app to start Tor
     */
    fun launchOrbot(context: Context): Boolean {
        return try {
            val intent = context.packageManager.getLaunchIntentForPackage(ORBOT_PACKAGE_NAME)
            if (intent != null) {
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(intent)
                Log.i(TAG, "Launched Orbot app")
                true
            } else {
                Log.w(TAG, "Could not create launch intent for Orbot")
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to launch Orbot: ${e.message}")
            false
        }
    }
    
    /**
     * Open Google Play Store to install Orbot
     */
    fun openOrbotInPlayStore(context: Context) {
        try {
            val intent = Intent(Intent.ACTION_VIEW).apply {
                data = Uri.parse("market://details?id=$ORBOT_PACKAGE_NAME")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(intent)
            Log.i(TAG, "Opened Orbot in Play Store")
        } catch (e: Exception) {
            // Fallback to browser if Play Store is not available
            try {
                val intent = Intent(Intent.ACTION_VIEW).apply {
                    data = Uri.parse("https://play.google.com/store/apps/details?id=$ORBOT_PACKAGE_NAME")
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                context.startActivity(intent)
                Log.i(TAG, "Opened Orbot in browser")
            } catch (e2: Exception) {
                Log.e(TAG, "Failed to open Orbot install page: ${e2.message}")
            }
        }
    }
    
    /**
     * Wait for Tor to start up (with timeout)
     * Returns true if Tor becomes available, false if timeout
     */
    suspend fun waitForTor(maxAttempts: Int = MAX_TOR_CHECK_ATTEMPTS): Boolean {
        Log.d(TAG, "Waiting for Tor to start...")
        repeat(maxAttempts) { attempt ->
            if (isTorRunning()) {
                Log.i(TAG, "Tor is now running (attempt ${attempt + 1})")
                return true
            }
            delay(TOR_CHECK_DELAY_MS)
        }
        Log.w(TAG, "Tor did not start within timeout period")
        return false
    }
    
    /**
     * Get status message for display
     */
    suspend fun getStatusMessage(context: Context): String {
        return when {
            !isOrbotInstalled(context) -> "❌ Orbot NOT installed"
            !isTorRunning() -> "⚠️ Orbot installed but Tor NOT running"
            else -> "✅ Tor is ACTIVE and routing traffic"
        }
    }
}
