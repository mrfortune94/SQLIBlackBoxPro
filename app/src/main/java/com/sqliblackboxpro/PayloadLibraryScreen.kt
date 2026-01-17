package com.sqliblackboxpro

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material3.*
import androidx.compose.material3.HorizontalDivider
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog

@Composable
fun PayloadLibraryScreen(
    onBack: () -> Unit,
    onAddCustomPayload: (String, String, String) -> Unit
) {
    var showAddDialog by remember { mutableStateOf(false) }
    var expandedPayload by remember { mutableStateOf<String?>(null) }
    val payloads = remember { SQLPayloads.getAllPayloadInfo() }
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("SQL Injection Library") },
                actions = {
                    IconButton(onClick = { showAddDialog = true }) {
                        Icon(Icons.Default.Add, "Add Custom Payload")
                    }
                }
            )
        }
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(horizontal = 16.dp)
        ) {
            // Group by category
            val grouped = payloads.groupBy { it.category }
            
            grouped.forEach { (category, categoryPayloads) ->
                item {
                    Text(
                        text = category,
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(vertical = 16.dp)
                    )
                }
                
                items(categoryPayloads) { payloadInfo ->
                    PayloadCard(
                        payloadInfo = payloadInfo,
                        isExpanded = expandedPayload == payloadInfo.payload,
                        onToggleExpand = {
                            expandedPayload = if (expandedPayload == payloadInfo.payload) {
                                null
                            } else {
                                payloadInfo.payload
                            }
                        },
                        onDelete = if (payloadInfo.isCustom) {
                            { SQLPayloads.removeCustomPayload(payloadInfo.payload) }
                        } else null
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                }
            }
            
            item {
                Spacer(modifier = Modifier.height(16.dp))
                Button(
                    onClick = onBack,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Close Library")
                }
                Spacer(modifier = Modifier.height(32.dp))
            }
        }
    }
    
    if (showAddDialog) {
        AddPayloadDialog(
            onDismiss = { showAddDialog = false },
            onAdd = { payload, description, category ->
                onAddCustomPayload(payload, description, category)
                showAddDialog = false
            }
        )
    }
}

@Composable
fun PayloadCard(
    payloadInfo: PayloadInfo,
    isExpanded: Boolean,
    onToggleExpand: () -> Unit,
    onDelete: (() -> Unit)?
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onToggleExpand() },
        colors = CardDefaults.cardColors(
            containerColor = if (payloadInfo.isCustom)
                MaterialTheme.colorScheme.tertiaryContainer
            else
                MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Column(
            modifier = Modifier.padding(12.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = payloadInfo.payload.take(50) + if (payloadInfo.payload.length > 50) "..." else "",
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier.weight(1f)
                )
                Row {
                    if (payloadInfo.isCustom && onDelete != null) {
                        IconButton(onClick = onDelete) {
                            Icon(
                                Icons.Default.Delete,
                                contentDescription = "Delete",
                                tint = MaterialTheme.colorScheme.error
                            )
                        }
                    }
                    Icon(
                        if (isExpanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                        contentDescription = if (isExpanded) "Collapse" else "Expand"
                    )
                }
            }
            
            if (isExpanded) {
                HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                
                // Full payload
                Text(
                    text = "Full Payload:",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = payloadInfo.payload,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                
                // Description
                Text(
                    text = "What This Payload Does:",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = payloadInfo.description,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                
                if (payloadInfo.isCustom) {
                    Chip(label = { Text("Custom Payload") })
                }
            }
        }
    }
}

@Composable
fun Chip(label: @Composable () -> Unit) {
    Surface(
        color = MaterialTheme.colorScheme.primary,
        shape = MaterialTheme.shapes.small
    ) {
        Box(modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)) {
            label()
        }
    }
}

@Composable
fun AddPayloadDialog(
    onDismiss: () -> Unit,
    onAdd: (payload: String, description: String, category: String) -> Unit
) {
    var payload by remember { mutableStateOf("") }
    var description by remember { mutableStateOf("") }
    var category by remember { mutableStateOf("Custom Payloads") }
    
    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
        ) {
            Column(
                modifier = Modifier
                    .padding(16.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                Text(
                    text = "Add Custom SQL Injection Payload",
                    style = MaterialTheme.typography.titleLarge,
                    modifier = Modifier.padding(bottom = 16.dp)
                )
                
                OutlinedTextField(
                    value = payload,
                    onValueChange = { payload = it },
                    label = { Text("SQL Payload") },
                    placeholder = { Text("' OR 1=1--") },
                    modifier = Modifier.fillMaxWidth(),
                    maxLines = 3
                )
                
                Spacer(modifier = Modifier.height(12.dp))
                
                OutlinedTextField(
                    value = description,
                    onValueChange = { description = it },
                    label = { Text("Description") },
                    placeholder = { Text("Explain what this payload does if successful...") },
                    modifier = Modifier.fillMaxWidth(),
                    maxLines = 5
                )
                
                Spacer(modifier = Modifier.height(12.dp))
                
                OutlinedTextField(
                    value = category,
                    onValueChange = { category = it },
                    label = { Text("Category") },
                    placeholder = { Text("Custom Payloads") },
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
                    Button(
                        onClick = {
                            if (payload.isNotBlank() && description.isNotBlank()) {
                                onAdd(payload, description, category)
                            }
                        },
                        enabled = payload.isNotBlank() && description.isNotBlank()
                    ) {
                        Text("Add Payload")
                    }
                }
            }
        }
    }
}
