package com.sqliblackboxpro

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp

@Composable
fun ModeScreen(
    selectedMode: ScanMode,
    onModeSelected: (ScanMode) -> Unit,
    onStartScan: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = "Select Scan Mode",
            style = MaterialTheme.typography.headlineMedium,
            modifier = Modifier.padding(bottom = 32.dp)
        )
        
        Column(
            modifier = Modifier
                .selectableGroup()
                .fillMaxWidth()
        ) {
            ModeOption(
                mode = ScanMode.STANDARD,
                label = "Standard",
                description = "Direct HTTP requests",
                isSelected = selectedMode == ScanMode.STANDARD,
                onSelected = onModeSelected
            )
            
            Spacer(modifier = Modifier.height(12.dp))
            
            ModeOption(
                mode = ScanMode.TOR,
                label = "Tor (SOCKS Proxy)",
                description = "Route through Tor network (127.0.0.1:9050)",
                isSelected = selectedMode == ScanMode.TOR,
                onSelected = onModeSelected
            )
            
            Spacer(modifier = Modifier.height(12.dp))
            
            ModeOption(
                mode = ScanMode.STEALTH,
                label = "Stealth",
                description = "Randomized User-Agent spoofing",
                isSelected = selectedMode == ScanMode.STEALTH,
                onSelected = onModeSelected
            )
        }
        
        Spacer(modifier = Modifier.height(32.dp))
        
        Button(
            onClick = onStartScan,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Start Scan")
        }
    }
}

@Composable
fun ModeOption(
    mode: ScanMode,
    label: String,
    description: String,
    isSelected: Boolean,
    onSelected: (ScanMode) -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .selectable(
                selected = isSelected,
                onClick = { onSelected(mode) },
                role = Role.RadioButton
            ),
        colors = CardDefaults.cardColors(
            containerColor = if (isSelected) 
                MaterialTheme.colorScheme.primaryContainer 
            else 
                MaterialTheme.colorScheme.surface
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            RadioButton(
                selected = isSelected,
                onClick = null
            )
            
            Spacer(modifier = Modifier.width(12.dp))
            
            Column {
                Text(
                    text = label,
                    style = MaterialTheme.typography.titleMedium
                )
                Text(
                    text = description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}
