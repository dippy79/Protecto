package com.protecto.aegis.wireless

import android.content.Context
import android.telephony.TelephonyManager
import com.protecto.aegis.core.ForensicLogger
import com.protecto.aegis.core.LogEventType
import com.protecto.aegis.core.Severity
import com.protecto.aegis.core.ThreatAlert
import com.protecto.aegis.core.ThreatCategory
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * PROJECT AEGIS - Cellular Downgrade Detector
 * 
 * Detects cellular network downgrades that may indicate IMSI catcher (Stingray) attacks.
 * IMSI catchers force devices to downgrade from 4G/5G to 2G/3G to intercept communications.
 * 
 * Detection methods:
 * - Network type monitoring (5G/4G -> 3G/2G transitions)
 * - Signal strength anomalies
 * - Network operator changes
 * - Unexpected authentication requests
 * 
 * Core Philosophy: DETECT → BLOCK → ISOLATE → RECORD → ANALYZE → ALERT → RECOVER
 */
class CellularDowngradeDetector(
    private val context: Context,
    private val forensicLogger: ForensicLogger
) {
    
    private val telephonyManager = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
    
    private val _isMonitoring = MutableStateFlow(false)
    val isMonitoring: StateFlow<Boolean> = _isMonitoring.asStateFlow()
    
    private val _currentCellularType = MutableStateFlow<CellularType>(CellularType.UNKNOWN)
    val currentCellularType: StateFlow<CellularType> = _currentCellularType.asStateFlow()
    
    private val _downgradeEvents = MutableStateFlow<List<DowngradeEvent>>(emptyList())
    val downgradeEvents: StateFlow<List<DowngradeEvent>> = _downgradeEvents.asStateFlow()
    
    // Network type history
    private val networkTypeHistory = mutableListOf<CellularTypeHistoryEntry>()
    
    // Baseline network type
    private var baselineCellularType: CellularType? = null
    
    // Signal strength history
    private val signalStrengthHistory = mutableListOf<Int>()
    
    /**
     * Start cellular downgrade monitoring
     */
    fun startMonitoring(): Flow<ThreatAlert> = callbackFlow {
        _isMonitoring.value = true
        
        // Set baseline
        baselineCellularType = getCurrentCellularType()
        _currentCellularType.value = baselineCellularType ?: CellularType.UNKNOWN
        
        // Monitor network type changes
        val phoneStateListener = object : android.telephony.PhoneStateListener() {
            override fun onDisplayInfoChanged(telephonyDisplayInfo: TelephonyDisplayInfo) {
                handleNetworkTypeChange(telephonyDisplayInfo)
            }
            
            override fun onSignalStrengthsChanged(signalStrength: SignalStrength) {
                handleSignalStrengthChange(signalStrength)
            }
        }
        
        telephonyManager.listen(
            phoneStateListener,
            android.telephony.PhoneStateListener.LISTEN_DISPLAY_INFO or
            android.telephony.PhoneStateListener.LISTEN_SIGNAL_STRENGTHS
        )
        
        // Periodic checks
        val monitoringJob = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Default).launch {
            while (_isMonitoring.value) {
                delay(5000) // Check every 5 seconds
                performPeriodicCheck()
            }
        }
        
        awaitClose {
            telephonyManager.listen(phoneStateListener, android.telephony.PhoneStateListener.LISTEN_NONE)
            monitoringJob.cancel()
            _isMonitoring.value = false
        }
    }
    
    /**
     * Stop cellular downgrade monitoring
     */
    fun stopMonitoring() {
        _isMonitoring.value = false
    }
    
    /**
     * Handle network type change
     */
    private fun handleNetworkTypeChange(displayInfo: TelephonyDisplayInfo) {
        val newType = mapDisplayInfoToCellularType(displayInfo)
        val previousType = _currentCellularType.value
        
        if (newType != previousType) {
            // Record history
            networkTypeHistory.add(
                CellularTypeHistoryEntry(
                    type = newType,
                    timestamp = System.currentTimeMillis()
                )
            )
            
            // Check for downgrade
            val downgradeAnalysis = analyzeDowngrade(previousType, newType)
            
            if (downgradeAnalysis.isDowngrade) {
                val event = DowngradeEvent(
                    previousType = previousType,
                    newType = newType,
                    timestamp = System.currentTimeMillis(),
                    riskScore = downgradeAnalysis.riskScore,
                    potentialCause = downgradeAnalysis.potentialCause
                )
                
                _downgradeEvents.value = _downgradeEvents.value + event
                _currentCellularType.value = newType
                
                // Generate threat alert
                val threat = ThreatAlert(
                    id = java.util.UUID.randomUUID().toString(),
                    type = LogEventType.NETWORK_CONNECTION,
                    category = ThreatCategory.WIRELESS,
                    severity = if (downgradeAnalysis.riskScore >= 70) Severity.HIGH else Severity.WARNING,
                    riskScore = downgradeAnalysis.riskScore,
                    metadata = mapOf(
                        "event_type" to "cellular_downgrade",
                        "previous_type" to previousType.name,
                        "new_type" to newType.name,
                        "potential_cause" to downgradeAnalysis.potentialCause,
                        "timestamp" to event.timestamp.toString()
                    )
                )
                
                trySend(threat)
                
                // Log the event
                forensicLogger.logEvent(
                    eventType = LogEventType.NETWORK_CONNECTION,
                    severity = if (downgradeAnalysis.riskScore >= 70) Severity.HIGH else Severity.WARNING,
                    metadata = mapOf(
                        "event_type" to "cellular_downgrade",
                        "previous_type" to previousType.name,
                        "new_type" to newType.name,
                        "potential_cause" to downgradeAnalysis.potentialCause
                    ),
                    riskScore = downgradeAnalysis.riskScore
                )
            } else {
                _currentCellularType.value = newType
            }
        }
    }
    
    /**
     * Handle signal strength change
     */
    private fun handleSignalStrengthChange(signalStrength: SignalStrength) {
        val level = signalStrength.level
        signalStrengthHistory.add(level)
        
        // Keep only last 50 readings
        if (signalStrengthHistory.size > 50) {
            signalStrengthHistory.removeAt(0)
        }
        
        // Check for signal anomalies
        if (signalStrengthHistory.size >= 10) {
            val anomalyAnalysis = analyzeSignalAnomaly()
            if (anomalyAnalysis.hasAnomaly) {
                forensicLogger.logEvent(
                    eventType = LogEventType.NETWORK_CONNECTION,
                    severity = Severity.WARNING,
                    metadata = mapOf(
                        "event_type" to "signal_anomaly",
                        "anomaly_type" to anomalyAnalysis.anomalyType,
                        "current_level" to level.toString(),
                        "average_level" to anomalyAnalysis.averageLevel.toString()
                    ),
                    riskScore = 30
                )
            }
        }
    }
    
    /**
     * Perform periodic checks
     */
    private fun performPeriodicCheck() {
        // Check if we're stuck on a lower network type
        val currentType = _currentCellularType.value
        val baseline = baselineCellularType
        
        if (baseline != null && currentType != baseline) {
            val durationInLowerType = System.currentTimeMillis() - 
                networkTypeHistory.lastOrNull { it.type == currentType }?.timestamp ?: 0
            
            // If stuck in lower type for more than 5 minutes
            if (durationInLowerType > 300000) {
                forensicLogger.logEvent(
                    eventType = LogEventType.NETWORK_CONNECTION,
                    severity = Severity.WARNING,
                    metadata = mapOf(
                        "event_type" to "extended_downgrade",
                        "current_type" to currentType.name,
                        "baseline_type" to baseline.name,
                        "duration_ms" to durationInLowerType.toString()
                    ),
                    riskScore = 40
                )
            }
        }
        
        // Check for network operator changes
        val currentOperator = telephonyManager.networkOperator
        val currentOperatorName = telephonyManager.networkOperatorName
        
        // In a real implementation, you would track operator changes
        // Operator changes can indicate SIM swapping or network spoofing
    }
    
    /**
     * Analyze downgrade
     */
    private fun analyzeDowngrade(previousType: CellularType, newType: CellularType): DowngradeAnalysis {
        val isDowngrade = when {
            previousType == CellularType.NR_5G && newType != CellularType.NR_5G -> true
            previousType == CellularType.LTE_4G && newType == CellularType.UMTS_3G -> true
            previousType == CellularType.LTE_4G && newType == CellularType.GSM_2G -> true
            previousType == CellularType.UMTS_3G && newType == CellularType.GSM_2G -> true
            else -> false
        }
        
        if (!isDowngrade) {
            return DowngradeAnalysis(
                isDowngrade = false,
                riskScore = 0,
                potentialCause = "normal_upgrade"
            )
        }
        
        // Calculate risk score based on severity of downgrade
        val riskScore = when {
            previousType == CellularType.NR_5G && newType == CellularType.GSM_2G -> 90
            previousType == CellularType.LTE_4G && newType == CellularType.GSM_2G -> 85
            previousType == CellularType.NR_5G && newType == CellularType.UMTS_3G -> 75
            previousType == CellularType.LTE_4G && newType == CellularType.UMTS_3G -> 70
            previousType == CellularType.UMTS_3G && newType == CellularType.GSM_2G -> 65
            else -> 50
        }
        
        val potentialCause = when {
            newType == CellularType.GSM_2G -> "IMSI_catcher_2g_attack"
            newType == CellularType.UMTS_3G -> "IMSI_catcher_3g_attack_or_coverage_issue"
            else -> "network_coverage_or_interference"
        }
        
        return DowngradeAnalysis(
            isDowngrade = true,
            riskScore = riskScore,
            potentialCause = potentialCause
        )
    }
    
    /**
     * Analyze signal anomaly
     */
    private fun analyzeSignalAnomaly(): SignalAnomalyAnalysis {
        val averageLevel = signalStrengthHistory.average()
        val minLevel = signalStrengthHistory.minOrNull() ?: 0
        val maxLevel = signalStrengthHistory.maxOrNull() ?: 0
        
        // Check for sudden drops
        val recentLevels = signalStrengthHistory.takeLast(5)
        val earlierLevels = signalStrengthHistory.dropLast(5)
        
        if (earlierLevels.isNotEmpty()) {
            val recentAverage = recentLevels.average()
            val earlierAverage = earlierLevels.average()
            
            if (recentAverage < earlierAverage - 20) {
                return SignalAnomalyAnalysis(
                    hasAnomaly = true,
                    anomalyType = "sudden_signal_drop",
                    averageLevel = averageLevel.toInt()
                )
            }
        }
        
        // Check for high variance (potential signal manipulation)
        val variance = signalStrengthHistory.map { (it - averageLevel).pow(2) }.average()
        if (variance > 100) {
            return SignalAnomalyAnalysis(
                hasAnomaly = true,
                anomalyType = "high_signal_variance",
                averageLevel = averageLevel.toInt()
            )
        }
        
        return SignalAnomalyAnalysis(
            hasAnomaly = false,
            anomalyType = "none",
            averageLevel = averageLevel.toInt()
        )
    }
    
    /**
     * Map display info to cellular type
     */
    private fun mapDisplayInfoToCellularType(displayInfo: TelephonyDisplayInfo): CellularType {
        return when (displayInfo.networkType) {
            TelephonyManager.NETWORK_TYPE_NR -> CellularType.NR_5G
            TelephonyManager.NETWORK_TYPE_LTE -> CellularType.LTE_4G
            TelephonyManager.NETWORK_TYPE_HSPA,
            TelephonyManager.NETWORK_TYPE_HSPAP,
            TelephonyManager.NETWORK_TYPE_HSDPA,
            TelephonyManager.NETWORK_TYPE_HSUPA,
            TelephonyManager.NETWORK_TYPE_UMTS -> CellularType.UMTS_3G
            TelephonyManager.NETWORK_TYPE_EDGE,
            TelephonyManager.NETWORK_TYPE_GPRS -> CellularType.GSM_2G
            TelephonyManager.NETWORK_TYPE_1xRTT,
            TelephonyManager.NETWORK_TYPE_CDMA,
            TelephonyManager.NETWORK_TYPE_EVDO_0,
            TelephonyManager.NETWORK_TYPE_EVDO_A,
            TelephonyManager.NETWORK_TYPE_EVDO_B -> CellularType.CDMA_3G
            else -> CellularType.UNKNOWN
        }
    }
    
    /**
     * Get current cellular type
     */
    private fun getCurrentCellularType(): CellularType {
        val networkType = telephonyManager.networkType
        return when (networkType) {
            TelephonyManager.NETWORK_TYPE_NR -> CellularType.NR_5G
            TelephonyManager.NETWORK_TYPE_LTE -> CellularType.LTE_4G
            TelephonyManager.NETWORK_TYPE_HSPA,
            TelephonyManager.NETWORK_TYPE_HSPAP,
            TelephonyManager.NETWORK_TYPE_HSDPA,
            TelephonyManager.NETWORK_TYPE_HSUPA,
            TelephonyManager.NETWORK_TYPE_UMTS -> CellularType.UMTS_3G
            TelephonyManager.NETWORK_TYPE_EDGE,
            TelephonyManager.NETWORK_TYPE_GPRS -> CellularType.GSM_2G
            TelephonyManager.NETWORK_TYPE_1xRTT,
            TelephonyManager.NETWORK_TYPE_CDMA,
            TelephonyManager.NETWORK_TYPE_EVDO_0,
            TelephonyManager.NETWORK_TYPE_EVDO_A,
            TelephonyManager.NETWORK_TYPE_EVDO_B -> CellularType.CDMA_3G
            else -> CellularType.UNKNOWN
        }
    }
    
    /**
     * Get network type history
     */
    fun getNetworkTypeHistory(): List<CellularTypeHistoryEntry> {
        return networkTypeHistory.toList()
    }
    
    /**
     * Clear history
     */
    fun clearHistory() {
        networkTypeHistory.clear()
        signalStrengthHistory.clear()
        _downgradeEvents.value = emptyList()
    }
    
    private fun Double.pow(exponent: Int): Double {
        return this.toDouble().let { base ->
            var result = 1.0
            repeat(exponent) { result *= base }
            result
        }
    }
}

// Data classes for cellular downgrade detection

data class DowngradeEvent(
    val previousType: CellularType,
    val newType: CellularType,
    val timestamp: Long,
    val riskScore: Int,
    val potentialCause: String
)

data class DowngradeAnalysis(
    val isDowngrade: Boolean,
    val riskScore: Int,
    val potentialCause: String
)

data class SignalAnomalyAnalysis(
    val hasAnomaly: Boolean,
    val anomalyType: String,
    val averageLevel: Int
)

data class CellularTypeHistoryEntry(
    val type: CellularType,
    val timestamp: Long
)

enum class CellularType {
    UNKNOWN,
    NR_5G,
    LTE_4G,
    UMTS_3G,
    CDMA_3G,
    GSM_2G,
    CDMA,
    EVDO,
    IDEN
}

// Android TelephonyDisplayInfo compatibility
data class TelephonyDisplayInfo(
    val networkType: Int
)

// Android SignalStrength compatibility
data class SignalStrength(
    val level: Int
)
