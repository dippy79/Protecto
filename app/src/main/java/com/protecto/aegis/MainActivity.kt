package com.protecto.aegis

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
import com.protecto.aegis.core.AegisSecurityService
import com.protecto.aegis.core.SystemState
import com.protecto.aegis.core.ThreatAlert
import com.protecto.aegis.ui.dashboard.DashboardScreen
import com.protecto.aegis.ui.dashboard.ThreatEngineStatus
import com.protecto.aegis.ui.dashboard.SystemIntegrityStatus
import com.protecto.aegis.ui.theme.AegisTheme

/**
 * PROJECT AEGIS - Main Activity
 * 
 * Entry point for the PROJECT AEGIS security platform.
 * Initializes the security service and provides the main UI.
 * 
 * Core Philosophy: DETECT → BLOCK → ISOLATE → RECORD → ANALYZE → ALERT → RECOVER
 */
class MainActivity : ComponentActivity() {
    
    private lateinit var securityService: AegisSecurityService
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Initialize security service
        securityService = AegisSecurityService()
        
        setContent {
            AegisTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    AegisApp()
                }
            }
        }
    }
    
    override fun onDestroy() {
        super.onDestroy()
        // Cleanup security service
    }
}

@Composable
fun AegisApp() {
    val navController = rememberNavController()
    val viewModel: AegisViewModel = viewModel()
    
    // Collect security service state
    val systemState by viewModel.systemState.collectAsState()
    val overallRiskScore by viewModel.overallRiskScore.collectAsState()
    val threatEnginesStatus by viewModel.threatEnginesStatus.collectAsState()
    val recentIncidents by viewModel.recentIncidents.collectAsState()
    val systemIntegrity by viewModel.systemIntegrity.collectAsState()
    
    NavHost(
        navController = navController,
        startDestination = "dashboard"
    ) {
        composable("dashboard") {
            DashboardScreen(
                systemState = systemState,
                overallRiskScore = overallRiskScore,
                threatEnginesStatus = threatEnginesStatus,
                recentIncidents = recentIncidents,
                systemIntegrity = systemIntegrity,
                onDeadMansSwitchToggle = { active ->
                    viewModel.toggleDeadMansSwitch(active)
                },
                onFaradayModeToggle = { active ->
                    viewModel.toggleFaradayMode(active)
                },
                onFullSystemScan = {
                    viewModel.performFullSystemScan()
                },
                onThreatDismiss = { threatId ->
                    viewModel.dismissThreat(threatId)
                },
                onNavigateToDetails = { destination ->
                    navController.navigate(destination)
                }
            )
        }
        
        composable("details/{destination}") { backStackEntry ->
            val destination = backStackEntry.arguments?.getString("destination") ?: "unknown"
            DetailsScreen(
                destination = destination,
                onBack = { navController.popBackStack() }
            )
        }
    }
}

@Composable
fun DetailsScreen(
    destination: String,
    onBack: () -> Unit
) {
    // Implementation for detail screens
    // This would show detailed information about specific threats or engines
}

// ViewModel for managing UI state
class AegisViewModel : androidx.lifecycle.ViewModel() {
    
    private val _systemState = androidx.compose.runtime.mutableStateOf(SystemState.MONITORING)
    val systemState: androidx.compose.runtime.State<SystemState> = _systemState
    
    private val _overallRiskScore = androidx.compose.runtime.mutableStateOf(0)
    val overallRiskScore: androidx.compose.runtime.State<Int> = _overallRiskScore
    
    private val _threatEnginesStatus = androidx.compose.runtime.mutableStateOf<Map<String, ThreatEngineStatus>>(
        mapOf(
            "USBGuardian 2.0" to ThreatEngineStatus(
                state = com.protecto.aegis.ui.dashboard.EngineState.ACTIVE,
                activeThreats = 0,
                lastScan = System.currentTimeMillis()
            ),
            "WirelessGuardian 2.0" to ThreatEngineStatus(
                state = com.protecto.aegis.ui.dashboard.EngineState.ACTIVE,
                activeThreats = 1,
                lastScan = System.currentTimeMillis()
            ),
            "ExfilGuard 2.0" to ThreatEngineStatus(
                state = com.protecto.aegis.ui.dashboard.EngineState.ACTIVE,
                activeThreats = 0,
                lastScan = System.currentTimeMillis()
            ),
            "AppRiskEngine 2.0" to ThreatEngineStatus(
                state = com.protecto.aegis.ui.dashboard.EngineState.ACTIVE,
                activeThreats = 2,
                lastScan = System.currentTimeMillis()
            )
        )
    )
    val threatEnginesStatus: androidx.compose.runtime.State<Map<String, ThreatEngineStatus>> = _threatEnginesStatus
    
    private val _recentIncidents = androidx.compose.runtime.mutableStateOf<List<ThreatAlert>>(emptyList())
    val recentIncidents: androidx.compose.runtime.State<List<ThreatAlert>> = _recentIncidents
    
    private val _systemIntegrity = androidx.compose.runtime.mutableStateOf(
        SystemIntegrityStatus(
            verified = true,
            driftDelta = 0.02f,
            logEntries = 1247
        )
    )
    val systemIntegrity: androidx.compose.runtime.State<SystemIntegrityStatus> = _systemIntegrity
    
    fun toggleDeadMansSwitch(active: Boolean) {
        if (active) {
            _systemState.value = SystemState.LOCKDOWN
            _overallRiskScore.value = 100
        } else {
            _systemState.value = SystemState.MONITORING
            _overallRiskScore.value = 45
        }
    }
    
    fun toggleFaradayMode(active: Boolean) {
        if (active) {
            _systemState.value = SystemState.FARADAY
            _overallRiskScore.value = 85
        } else {
            _systemState.value = SystemState.MONITORING
            _overallRiskScore.value = 45
        }
    }
    
    fun performFullSystemScan() {
        _systemState.value = SystemState.SCANNING
        
        // Simulate scan completion
        androidx.compose.runtime.SideEffect {
            kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Default).launch {
                kotlinx.coroutines.delay(3000)
                _systemState.value = SystemState.MONITORING
                _overallRiskScore.value = 35
            }
        }
    }
    
    fun dismissThreat(threatId: String) {
        _recentIncidents.value = _recentIncidents.value.filter { it.id != threatId }
    }
}
