package com.protecto.aegis.ui.dashboard

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.protecto.aegis.core.SystemState
import com.protecto.aegis.core.ThreatAlert
import com.protecto.aegis.response.LockdownMeasure
import com.protecto.aegis.response.FaradayMeasure
import java.text.SimpleDateFormat
import java.util.*

/**
 * PROJECT AEGIS - Security Dashboard Screen
 * 
 * Main UI dashboard for PROJECT AEGIS security platform.
 * Provides real-time monitoring of threat detection engines,
 * incident response controls, and system status.
 * 
 * Features:
 * - Overall risk score display
 * - Threat engine status cards
 * - Recent incidents list
 * - Quick action buttons (Dead Man's Switch, Faraday Mode)
 * - System integrity indicators
 * 
 * Core Philosophy: DETECT → BLOCK → ISOLATE → RECORD → ANALYZE → ALERT → RECOVER
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DashboardScreen(
    systemState: SystemState,
    overallRiskScore: Int,
    threatEnginesStatus: Map<String, ThreatEngineStatus>,
    recentIncidents: List<ThreatAlert>,
    systemIntegrity: SystemIntegrityStatus,
    onDeadMansSwitchToggle: (Boolean) -> Unit,
    onFaradayModeToggle: (Boolean) -> Unit,
    onFullSystemScan: () -> Unit,
    onThreatDismiss: (String) -> Unit,
    onNavigateToDetails: (String) -> Unit
) {
    var isDeadMansSwitchActive by remember { mutableStateOf(false) }
    var isFaradayModeActive by remember { mutableStateOf(false) }
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { 
                    Text(
                        "PROJECT AEGIS",
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.primary
                    )
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                ),
                actions = {
                    IconButton(onClick = { /* Open settings */ }) {
                        Icon(Icons.Default.Settings, contentDescription = "Settings")
                    }
                }
            )
        },
        containerColor = MaterialTheme.colorScheme.background
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Risk Score Header
            item {
                RiskScoreCard(
                    riskScore = overallRiskScore,
                    systemState = systemState,
                    onStateClick = { /* Show state details */ }
                )
            }
            
            // Quick Actions
            item {
                QuickActionsCard(
                    isDeadMansSwitchActive = isDeadMansSwitchActive,
                    isFaradayModeActive = isFaradayModeActive,
                    onDeadMansSwitchToggle = { 
                        isDeadMansSwitchActive = it
                        onDeadMansSwitchToggle(it)
                    },
                    onFaradayModeToggle = { 
                        isFaradayModeActive = it
                        onFaradayModeToggle(it)
                    },
                    onFullSystemScan = onFullSystemScan
                )
            }
            
            // Threat Engines Status
            item {
                Text(
                    "Threat Detection Engines",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
            }
            
            items(threatEnginesStatus.toList()) { (engineName, status) ->
                ThreatEngineStatusCard(
                    engineName = engineName,
                    status = status,
                    onClick = { onNavigateToDetails(engineName) }
                )
            }
            
            // Recent Incidents
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        "Recent Incidents",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    TextButton(onClick = { /* View all incidents */ }) {
                        Text("View All")
                    }
                }
            }
            
            if (recentIncidents.isEmpty()) {
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceVariant
                        )
                    ) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(32.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Column(
                                horizontalAlignment = Alignment.CenterHorizontally
                            ) {
                                Icon(
                                    Icons.Default.CheckCircle,
                                    contentDescription = "No incidents",
                                    tint = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(48.dp)
                                )
                                Spacer(modifier = Modifier.height(8.dp))
                                Text(
                                    "No Recent Incidents",
                                    style = MaterialTheme.typography.bodyLarge,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
            } else {
                items(recentIncidents.take(5)) { incident ->
                    IncidentCard(
                        incident = incident,
                        onDismiss = { onThreatDismiss(incident.id) },
                        onClick = { onNavigateToDetails(incident.id) }
                    )
                }
            }
            
            // System Integrity
            item {
                Text(
                    "System Integrity",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
            }
            
            item {
                SystemIntegrityCard(
                    integrity = systemIntegrity,
                    onClick = { /* View integrity details */ }
                )
            }
        }
    }
}

@Composable
fun RiskScoreCard(
    riskScore: Int,
    systemState: SystemState,
    onStateClick: () -> Unit
) {
    val (scoreColor, scoreText) = when {
        riskScore >= 80 -> Color.Red to "CRITICAL"
        riskScore >= 60 -> Color(0xFFFFA500) to "HIGH"
        riskScore >= 40 -> Color(0xFFFFFF00) to "MEDIUM"
        riskScore >= 20 -> Color(0xFF90EE90) to "LOW"
        else -> Color(0xFF00FF00) to "SAFE"
    }
    
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = when (systemState) {
                SystemState.LOCKDOWN -> Color(0xFFFFCDD2)
                SystemState.FARADAY -> Color(0xFFC5CAE9)
                SystemState.SCANNING -> Color(0xFFFFF9C4)
                else -> MaterialTheme.colorScheme.surfaceVariant
            }
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        "Overall Risk Score",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        "Status: ${systemState.name}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Box(
                    modifier = Modifier
                        .size(80.dp)
                        .background(
                            color = scoreColor,
                            shape = RoundedCornerShape(40.dp)
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = "$riskScore",
                        style = MaterialTheme.typography.headlineMedium,
                        fontWeight = FontWeight.Bold,
                        color = Color.Black
                    )
                }
            }
            
            Spacer(modifier = Modifier.height(12.dp))
            
            LinearProgressIndicator(
                progress = riskScore / 100f,
                modifier = Modifier.fillMaxWidth(),
                color = scoreColor
            )
            
            Spacer(modifier = Modifier.height(8.dp))
            
            Text(
                scoreText,
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.Bold,
                color = scoreColor
            )
        }
    }
}

@Composable
fun QuickActionsCard(
    isDeadMansSwitchActive: Boolean,
    isFaradayModeActive: Boolean,
    onDeadMansSwitchToggle: (Boolean) -> Unit,
    onFaradayModeToggle: (Boolean) -> Unit,
    onFullSystemScan: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
        ) {
            Text(
                "Quick Actions",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            
            Spacer(modifier = Modifier.height(12.dp))
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                // Dead Man's Switch
                ActionButton(
                    icon = Icons.Default.Lock,
                    label = "Dead Man's Switch",
                    isActive = isDeadMansSwitchActive,
                    activeColor = Color.Red,
                    onClick = { onDeadMansSwitchToggle(!isDeadMansSwitchActive) },
                    modifier = Modifier.weight(1f)
                )
                
                // Faraday Mode
                ActionButton(
                    icon = Icons.Default.WifiOff,
                    label = "Faraday Mode",
                    isActive = isFaradayModeActive,
                    activeColor = Color(0xFF2196F3),
                    onClick = { onFaradayModeToggle(!isFaradayModeActive) },
                    modifier = Modifier.weight(1f)
                )
            }
            
            Spacer(modifier = Modifier.height(12.dp))
            
            // Full System Scan
            Button(
                onClick = onFullSystemScan,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.primary
                )
            ) {
                Icon(Icons.Default.Search, contentDescription = null)
                Spacer(modifier = Modifier.width(8.dp))
                Text("Full System Scan")
            }
        }
    }
}

@Composable
fun ActionButton(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    isActive: Boolean,
    activeColor: Color,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Button(
        onClick = onClick,
        modifier = modifier.height(80.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = if (isActive) activeColor else MaterialTheme.colorScheme.surfaceVariant,
            contentColor = if (isActive) Color.White else MaterialTheme.colorScheme.onSurface
        )
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(icon, contentDescription = null)
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                label,
                style = MaterialTheme.typography.bodySmall,
                maxLines = 2
            )
        }
    }
}

@Composable
fun ThreatEngineStatusCard(
    engineName: String,
    status: ThreatEngineStatus,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        onClick = onClick
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    engineName,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    "${status.activeThreats} Active Threats",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            
            Box(
                modifier = Modifier
                    .size(12.dp)
                    .background(
                        color = when (status.state) {
                            EngineState.ACTIVE -> Color(0xFF4CAF50)
                            EngineState.IDLE -> Color(0xFFFFC107)
                            EngineState.ERROR -> Color(0xFFF44336)
                        },
                        shape = RoundedCornerShape(6.dp)
                    )
            )
        }
    }
}

@Composable
fun IncidentCard(
    incident: ThreatAlert,
    onDismiss: () -> Unit,
    onClick: () -> Unit
) {
    val severityColor = when (incident.severity) {
        com.protecto.aegis.core.Severity.CRITICAL -> Color.Red
        com.protecto.aegis.core.Severity.HIGH -> Color(0xFFFFA500)
        com.protecto.aegis.core.Severity.WARNING -> Color(0xFFFFFF00)
        com.protecto.aegis.core.Severity.INFO -> Color(0xFF90EE90)
    }
    
    Card(
        modifier = Modifier.fillMaxWidth(),
        onClick = onClick,
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .size(8.dp)
                            .background(
                                color = severityColor,
                                shape = RoundedCornerShape(4.dp)
                            )
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        incident.type.name.replace("_", " "),
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium
                    )
                }
                
                Spacer(modifier = Modifier.height(4.dp))
                
                Text(
                    getRelativeTimeString(incident.timestamp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                
                Text(
                    "Risk: ${incident.riskScore}",
                    style = MaterialTheme.typography.bodySmall,
                    color = severityColor,
                    fontWeight = FontWeight.Bold
                )
            }
            
            IconButton(onClick = onDismiss) {
                Icon(Icons.Default.Close, contentDescription = "Dismiss")
            }
        }
    }
}

@Composable
fun SystemIntegrityCard(
    integrity: SystemIntegrityStatus,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        onClick = onClick
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    "Merkle Tree Status",
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium
                )
                
                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .size(8.dp)
                            .background(
                                color = if (integrity.verified) Color(0xFF4CAF50) else Color(0xFFF44336),
                                shape = RoundedCornerShape(4.dp)
                            )
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        if (integrity.verified) "Verified" else "Tampered",
                        style = MaterialTheme.typography.bodySmall,
                        color = if (integrity.verified) Color(0xFF4CAF50) else Color(0xFFF44336)
                    )
                }
            }
            
            Spacer(modifier = Modifier.height(8.dp))
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    "Drift: ${String.format("%.2f", integrity.driftDelta)}%",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    "${integrity.logEntries} Entries",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

// Data classes for UI

data class ThreatEngineStatus(
    val state: EngineState,
    val activeThreats: Int,
    val lastScan: Long
)

enum class EngineState {
    ACTIVE,
    IDLE,
    ERROR
}

data class SystemIntegrityStatus(
    val verified: Boolean,
    val driftDelta: Float,
    val logEntries: Int
)

private fun getRelativeTimeString(timestamp: Long): String {
    val now = System.currentTimeMillis()
    val diff = now - timestamp
    
    return when {
        diff < 60000 -> "Just now"
        diff < 3600000 -> "${diff / 60000} min ago"
        diff < 86400000 -> "${diff / 3600000} hours ago"
        else -> SimpleDateFormat("MMM dd, HH:mm", Locale.getDefault()).format(Date(timestamp))
    }
}
