package com.protecto.aegis.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

/**
 * PROJECT AEGIS - Quick Actions Component
 * 
 * Provides quick access to emergency response functions
 * including Dead Man's Switch and Faraday Mode activation.
 * 
 * Core Philosophy: DETECT → BLOCK → ISOLATE → RECORD → ANALYZE → ALERT → RECOVER
 */
@Composable
fun QuickActionsCard(
    isDeadMansSwitchActive: Boolean,
    isFaradayModeActive: Boolean,
    onDeadMansSwitchToggle: (Boolean) -> Unit,
    onFaradayModeToggle: (Boolean) -> Unit,
    onFullSystemScan: () -> Unit,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
        ) {
            Text(
                "Emergency Response",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            
            Spacer(modifier = Modifier.height(12.dp))
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                EmergencyActionButton(
                    icon = Icons.Default.Lock,
                    label = "Dead Man's Switch",
                    description = "Lockdown Mode",
                    isActive = isDeadMansSwitchActive,
                    activeColor = Color(0xFFFF5252),
                    inactiveColor = Color(0xFFE57373),
                    onClick = { onDeadMansSwitchToggle(!isDeadMansSwitchActive) },
                    modifier = Modifier.weight(1f)
                )
                
                EmergencyActionButton(
                    icon = Icons.Default.WifiOff,
                    label = "Faraday Mode",
                    description = "Network Isolation",
                    isActive = isFaradayModeActive,
                    activeColor = Color(0xFF2196F3),
                    inactiveColor = Color(0xFF64B5F6),
                    onClick = { onFaradayModeToggle(!isFaradayModeActive) },
                    modifier = Modifier.weight(1f)
                )
            }
            
            Spacer(modifier = Modifier.height(12.dp))
            
            SystemScanButton(
                onScan = onFullSystemScan,
                modifier = Modifier.fillMaxWidth()
            )
        }
    }
}

@Composable
fun EmergencyActionButton(
    icon: ImageVector,
    label: String,
    description: String,
    isActive: Boolean,
    activeColor: Color,
    inactiveColor: Color,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val backgroundColor = if (isActive) activeColor else inactiveColor.copy(alpha = 0.2f)
    val contentColor = if (isActive) Color.White else inactiveColor
    
    Button(
        onClick = onClick,
        modifier = modifier.height(100.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = backgroundColor,
            contentColor = contentColor
        ),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Icon(
                icon,
                contentDescription = null,
                modifier = Modifier.size(32.dp)
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                label,
                style = MaterialTheme.typography.bodySmall,
                fontWeight = FontWeight.Medium,
                maxLines = 1
            )
            Text(
                description,
                style = MaterialTheme.typography.bodySmall,
                maxLines = 1
            )
        }
    }
}

@Composable
fun SystemScanButton(
    onScan: () -> Unit,
    modifier: Modifier = Modifier,
    isScanning: Boolean = false
) {
    Button(
        onClick = onScan,
        modifier = modifier.height(56.dp),
        enabled = !isScanning,
        colors = ButtonDefaults.buttonColors(
            containerColor = MaterialTheme.colorScheme.primary
        ),
        shape = RoundedCornerShape(12.dp)
    ) {
        if (isScanning) {
            CircularProgressIndicator(
                modifier = Modifier.size(24.dp),
                color = MaterialTheme.colorScheme.onPrimary,
                strokeWidth = 2.dp
            )
            Spacer(modifier = Modifier.width(12.dp))
            Text("Scanning...")
        } else {
            Icon(Icons.Default.Search, contentDescription = null)
            Spacer(modifier = Modifier.width(8.dp))
            Text("Full System Scan")
        }
    }
}

@Composable
fun QuickActionRow(
    actions: List<QuickAction>,
    modifier: Modifier = Modifier
) {
    Row(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        actions.forEach { action ->
            QuickActionChip(
                icon = action.icon,
                label = action.label,
                onClick = action.onClick,
                modifier = Modifier.weight(1f)
            )
        }
    }
}

@Composable
fun QuickActionChip(
    icon: ImageVector,
    label: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    AssistChip(
        onClick = onClick,
        label = { Text(label) },
        leadingIcon = {
            Icon(
                icon,
                contentDescription = null,
                modifier = Modifier.size(20.dp)
            )
        },
        modifier = modifier
    )
}

data class QuickAction(
    val icon: ImageVector,
    val label: String,
    val onClick: () -> Unit
)
