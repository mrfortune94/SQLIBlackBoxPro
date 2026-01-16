package com.sqliblackboxpro

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun UrlScreen(
    url: String,
    onUrlChange: (String) -> Unit,
    onContinue: () -> Unit
) {
    var error by remember { mutableStateOf(false) }
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = "Target URL",
            style = MaterialTheme.typography.headlineMedium,
            modifier = Modifier.padding(bottom = 32.dp)
        )
        
        OutlinedTextField(
            value = url,
            onValueChange = { 
                onUrlChange(it)
                error = false
            },
            label = { Text("Enter target URL") },
            placeholder = { Text("http://example.com/page.php") },
            isError = error,
            supportingText = if (error) {
                { Text("Please enter a valid URL (http:// or https://)") }
            } else null,
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        
        Spacer(modifier = Modifier.height(24.dp))
        
        Button(
            onClick = {
                if (url.startsWith("http://", ignoreCase = true) || 
                    url.startsWith("https://", ignoreCase = true)) {
                    onContinue()
                } else {
                    error = true
                }
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Continue")
        }
    }
}
