package com.sqliblackboxpro

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp

@Composable
fun PinScreen(
    pin: String,
    onPinChange: (String) -> Unit,
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
            text = "Enter PIN",
            style = MaterialTheme.typography.headlineMedium,
            modifier = Modifier.padding(bottom = 32.dp)
        )
        
        OutlinedTextField(
            value = pin,
            onValueChange = { 
                if (it.length <= 4 && it.all { char -> char.isDigit() }) {
                    onPinChange(it)
                    error = false
                }
            },
            label = { Text("4-digit PIN") },
            isError = error,
            supportingText = if (error) {
                { Text("PIN must be 4 digits") }
            } else null,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
            visualTransformation = PasswordVisualTransformation(),
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        
        Spacer(modifier = Modifier.height(24.dp))
        
        Button(
            onClick = {
                if (pin.length == 4) {
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
