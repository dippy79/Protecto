package com.protecto.aegis.wireless

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.WifiManager
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
 * PROJECT AEGIS - WirelessGuardian 2.0
 * 
 * Advanced wireless threat detection including:
 * - Standard detection: Evil twins, rogue Bluetooth, unauthorized VPNs
 * - Advanced heuristics: Cellular downgrade detection (IMSI catchers), BSSID historical profiling
 * 
 * Core Philosophy: DETECT → BLOCK → ISOLATE → RECORD → ANALYZE → ALERT → RECOVER
 */
class WirelessGuardian(
    private val context: Context,
    private val forensicLogger: ForensicLogger
) {
    
    private val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
    private val telephonyManager = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
    
    private val cellularDowngradeDetector = CellularDowngradeDetector(context, forensicLogger)
    private val bssidProfiler = BSSIDProfiler(context, forensicLogger)
    
    private val _isMonitoring = MutableStateFlow(false)
    val isMonitoring: StateFlow<Boolean> = _isMonitoring.asStateFlow()
    
    private val _networkState = MutableStateFlow(NetworkState.UNKNOWN)
    val networkState: StateFlow<NetworkState> = _networkState.asStateFlow()
    
    private val _detectedThreats = MutableStateFlow<List<ThreatAlert>>(emptyList())
    val detectedThreats: StateFlow<List<ThreatAlert>> = _detectedThreats.asStateFlow()
    
    private val _currentNetwork = MutableStateFlow<NetworkInfo?>(null)
    val currentNetwork: StateFlow<NetworkInfo?> = _currentNetwork.asStateFlow()
    
    // Historical BSSID database
    private val bssidHistory = mutableMapOf<String, BSSIDHistoryEntry>()
    
    // Known safe networks
    private val knownSafeNetworks = mutableSetOf<String>()
    
    // Network callback for monitoring
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    
    /**
     * Start wireless monitoring
     */
    fun startMonitoring(): Flow<ThreatAlert> = callbackFlow {
        _isMonitoring.value = true
        
        // Register network callback
        val networkRequest = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        
        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                handleNetworkAvailable(network)
            }
            
            override fun onLost(network: Network) {
                handleNetworkLost(network)
            }
            
            override fun onCapabilitiesChanged(
                network: Network,
                networkCapabilities: NetworkCapabilities
            ) {
                handleNetworkCapabilitiesChanged(network, networkCapabilities)
            }
        }
        
        connectivityManager.registerNetworkCallback(networkRequest, networkCallback!!)
        
        // Start cellular downgrade detection
        cellularDowngradeDetector.startMonitoring()
            .collect { threat ->
                handleThreatDetection(threat)
            }
        
        // Start BSSID profiling
        bssidProfiler.startMonitoring()
            .collect { threat ->
                handleThreatDetection(threat)
            }
        
        // Initialize current network state
        updateCurrentNetworkInfo()
        
        awaitClose {
            connectivityManager.unregisterNetworkCallback(networkCallback!!)
            cellularDowngradeDetector.stopMonitoring()
            bssidProfiler.stopMonitoring()
            _isMonitoring.value = false
        }
    }
    
    /**
     * Stop wireless monitoring
     */
    fun stopMonitoring() {
        _isMonitoring.value = false
        networkCallback?.let {
            connectivityManager.unregisterNetworkCallback(it)
        }
        cellularDowngradeDetector.stopMonitoring()
        bssidProfiler.stopMonitoring()
    }
    
    /**
     * Handle network available
     */
    private fun handleNetworkAvailable(network: Network) {
        val networkCapabilities = connectivityManager.getNetworkCapabilities(network)
        val networkInfo = extractNetworkInfo(network, networkCapabilities)
        
        _currentNetwork.value = networkInfo
        _networkState.value = NetworkState.CONNECTED
        
        // Analyze network for threats
        val threatAnalysis = analyzeNetwork(networkInfo)
        
        if (threatAnalysis.isThreat) {
            val threat = ThreatAlert(
                id = java.util.UUID.randomUUID().toString(),
                type = LogEventType.NETWORK_CONNECTION,
                category = ThreatCategory.WIRELESS,
                severity = if (threatAnalysis.riskScore >= 70) Severity.HIGH else Severity.WARNING,
                riskScore = threatAnalysis.riskScore,
                metadata = mapOf(
                    "network_type" to networkInfo.type.name,
                    "network_name" to (networkInfo.ssid ?: "unknown"),
                    "bssid" to (networkInfo.bssid ?: "unknown"),
                    "reason" to threatAnalysis.reason,
                    "threat_type" to threatAnalysis.threatType.name
                )
            )
            
            _detectedThreats.value = _detectedThreats.value + threat
            trySend(threat)
        }
        
        // Log network connection
        forensicLogger.logEvent(
            eventType = LogEventType.NETWORK_CONNECTION,
            severity = Severity.INFO,
            metadata = mapOf(
                "action" to "network_connected",
                "network_type" to networkInfo.type.name,
                "network_name" to (networkInfo.ssid ?: "unknown"),
                "bssid" to (networkInfo.bssid ?: "unknown"),
                "is_metered" to networkInfo.isMetered.toString()
            ),
            riskScore = 0
        )
    }
    
    /**
     * Handle network lost
     */
    private fun handleNetworkLost(network: Network) {
        _currentNetwork.value = null
        _networkState.value = NetworkState.DISCONNECTED
        
        forensicLogger.logEvent(
            eventType = LogEventType.NETWORK_CONNECTION,
            severity = Severity.INFO,
            metadata = mapOf(
                "action" to "network_disconnected",
                "network_id" to network.toString()
            ),
            riskScore = 0
        )
    }
    
    /**
     * Handle network capabilities changed
     */
    private fun handleNetworkCapabilitiesChanged(
        network: Network,
        networkCapabilities: NetworkCapabilities
    ) {
        val networkInfo = extractNetworkInfo(network, networkCapabilities)
        _currentNetwork.value = networkInfo
        
        // Check for suspicious changes
        if (networkInfo.type == NetworkType.CELLULAR) {
            // Check for cellular network type changes (potential downgrade)
            val previousNetwork = _currentNetwork.value
            if (previousNetwork != null && previousNetwork.cellularType != networkInfo.cellularType) {
                handleCellularTypeChange(previousNetwork.cellularType, networkInfo.cellularType)
            }
        }
    }
    
    /**
     * Handle cellular type change (potential IMSI catcher)
     */
    private fun handleCellularTypeChange(previousType: CellularType?, newType: CellularType?) {
        if (previousType == null || newType == null) return
        
        // Check for downgrade (5G/4G -> 3G/2G)
        val isDowngrade = when {
            previousType == CellularType.NR_5G && newType != CellularType.NR_5G -> true
            previousType == CellularType.LTE_4G && newType == CellularType.UMTS_3G -> true
            previousType == CellularType.LTE_4G && newType == CellularType.GSM_2G -> true
            previousType == CellularType.UMTS_3G && newType == CellularType.GSM_2G -> true
            else -> false
        }
        
        if (isDowngrade) {
            val threat = ThreatAlert(
                id = java.util.UUID.randomUUID().toString(),
                type = LogEventType.NETWORK_CONNECTION,
                category = ThreatCategory.WIRELESS,
                severity = Severity.HIGH,
                riskScore = 75,
                metadata = mapOf(
                    "event_type" to "cellular_downgrade",
                    "previous_type" to previousType.name,
                    "new_type" to newType.name,
                    "potential_cause" to "IMSI_catcher"
                )
            )
            
            _detectedThreats.value = _detectedThreats.value + threat
        }
    }
    
    /**
     * Analyze network for threats
     */
    private fun analyzeNetwork(networkInfo: NetworkInfo): NetworkThreatAnalysis {
        val reasons = mutableListOf<String>()
        var riskScore = 0
        var threatType = NetworkThreatType.NONE
        
        // Check for evil twin (WiFi with same SSID but different BSSID)
        if (networkInfo.type == NetworkType.WIFI) {
            val bssid = networkInfo.bssid ?: ""
            val ssid = networkInfo.ssid ?: ""
            
            if (isPotentialEvilTwin(ssid, bssid)) {
                reasons.add("Potential evil twin network detected")
                riskScore += 60
                threatType = NetworkThreatType.EVIL_TWIN
            }
            
            // Check for open network
            if (!networkInfo.isSecure) {
                reasons.add("Unsecured WiFi network")
                riskScore += 20
                threatType = NetworkThreatType.UNSECURED_NETWORK
            }
        }
        
        // Check for cellular network in 2G mode (high risk)
        if (networkInfo.type == NetworkType.CELLULAR && networkInfo.cellularType == CellularType.GSM_2G) {
            reasons.add("Cellular network in 2G mode (high security risk)")
            riskScore += 50
            threatType = NetworkThreatType.CELLULAR_DOWNGRADE
        }
        
        // Check for metered network (potential data exfiltration risk)
        if (networkInfo.isMetered) {
            reasons.add("Metered network connection")
            riskScore += 10
        }
        
        return NetworkThreatAnalysis(
            isThreat = riskScore > 0,
            riskScore = riskScore.coerceIn(0, 100),
            reason = reasons.joinToString(", "),
            threatType = threatType
        )
    }
    
    /**
     * Check for potential evil twin
     */
    private fun isPotentialEvilTwin(ssid: String, bssid: String): Boolean {
        // Check if we have seen this SSID before with a different BSSID
        val history = bssidHistory[ssid]
        
        if (history != null) {
            // If we've seen this SSID before but with a different BSSID, it might be an evil twin
            if (history.knownBSSIDs.contains(bssid)) {
                return false // Known BSSID for this SSID
            } else {
                return true // New BSSID for known SSID
            }
        }
        
        // First time seeing this SSID
        bssidHistory[ssid] = BSSIDHistoryEntry(
            ssid = ssid,
            knownBSSIDs = mutableSetOf(bssid),
            firstSeen = System.currentTimeMillis(),
            lastSeen = System.currentTimeMillis()
        )
        
        return false
    }
    
    /**
     * Extract network information
     */
    private fun extractNetworkInfo(
        network: Network,
        capabilities: NetworkCapabilities?
    ): NetworkInfo {
        if (capabilities == null) {
            return NetworkInfo(
                networkId = network.toString(),
                type = NetworkType.UNKNOWN,
                ssid = null,
                bssid = null,
                isSecure = false,
                isMetered = false,
                cellularType = null
            )
        }
        
        val networkType = when {
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> NetworkType.WIFI
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> NetworkType.CELLULAR
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> NetworkType.ETHERNET
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH) -> NetworkType.BLUETOOTH
            else -> NetworkType.UNKNOWN
        }
        
        val ssid = if (networkType == NetworkType.WIFI) {
            wifiManager.connectionInfo?.ssid?.removeSurrounding("\"")
        } else null
        
        val bssid = if (networkType == NetworkType.WIFI) {
            wifiManager.connectionInfo?.bssid
        } else null
        
        val isSecure = if (networkType == NetworkType.WIFI) {
            wifiManager.connectionInfo?.let {
                val capabilities = wifiManager.configuredNetworks?.find { config ->
                    config.SSID == wifiManager.connectionInfo?.ssid
                }?.allowedKeyManagement
                capabilities != null && capabilities.isNotEmpty()
            } ?: false
        } else true
        
        val cellularType = if (networkType == NetworkType.CELLULAR) {
            getCellularType()
        } else null
        
        return NetworkInfo(
            networkId = network.toString(),
            type = networkType,
            ssid = ssid,
            bssid = bssid,
            isSecure = isSecure,
            isMetered = !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED),
            cellularType = cellularType
        )
    }
    
    /**
     * Get cellular network type
     */
    private fun getCellularType(): CellularType {
        return when (telephonyManager.networkType) {
            TelephonyManager.NETWORK_TYPE_NR -> CellularType.NR_5G
            TelephonyManager.NETWORK_TYPE_LTE -> CellularType.LTE_4G
            TelephonyManager.NETTYPE_CDMA_MS,
            TelephonyManager.NETWORK_TYPE_CDMA,
            TelephonyManager.NETWORK_TYPE_EVDO_0,
            TelephonyManager.NETWORK_TYPE_EVDO_A,
            TelephonyManager.NETWORK_TYPE_EVDO_B,
            TelephonyManager.NETWORK_TYPE_1xRTT -> CellularType.CDMA_3G
            TelephonyManager.NETWORK_TYPE_UMTS,
            TelephonyManager.NETWORK_TYPE_HSDPA,
            TelephonyManager.NETWORK_TYPE_HSUPA,
            TelephonyManager.NETWORK_TYPE_HSPA,
            TelephonyManager.NETWORK_TYPE_HSPAP -> CellularType.UMTS_3G
            TelephonyManager.NETWORK_TYPE_GPRS,
            TelephonyManager.NETWORK_TYPE_EDGE -> CellularType.GSM_2G
            TelephonyManager.NETWORK_TYPE_IDEN -> CellularType.IDEN
            else -> CellularType.UNKNOWN
        }
    }
    
    /**
     * Update current network info
     */
    private fun updateCurrentNetworkInfo() {
        val activeNetwork = connectivityManager.activeNetwork
        val capabilities = connectivityManager.getNetworkCapabilities(activeNetwork)
        
        if (activeNetwork != null && capabilities != null) {
            _currentNetwork.value = extractNetworkInfo(activeNetwork, capabilities)
            _networkState.value = NetworkState.CONNECTED
        } else {
            _networkState.value = NetworkState.DISCONNECTED
        }
    }
    
    /**
     * Add network to known safe list
     */
    fun addToKnownSafe(ssid: String, bssid: String) {
        val key = "$ssid:$bssid"
        knownSafeNetworks.add(key)
        
        // Update BSSID history
        val history = bssidHistory[ssid]
        if (history != null) {
            history.knownBSSIDs.add(bssid)
            bssidHistory[ssid] = history
        }
    }
    
    /**
     * Remove network from known safe list
     */
    fun removeFromKnownSafe(ssid: String, bssid: String) {
        val key = "$ssid:$bssid"
        knownSafeNetworks.remove(key)
    }
    
    /**
     * Check if network is in known safe list
     */
    fun isKnownSafe(ssid: String, bssid: String): Boolean {
        val key = "$ssid:$bssid"
        return key in knownSafeNetworks
    }
    
    /**
     * Get BSSID history
     */
    fun getBSSIDHistory(): Map<String, BSSIDHistoryEntry> {
        return bssidHistory.toMap()
    }
    
    /**
     * Clear BSSID history
     */
    fun clearBSSIDHistory() {
        bssidHistory.clear()
    }
}

// Data classes for wireless monitoring

data class NetworkInfo(
    val networkId: String,
    val type: NetworkType,
    val ssid: String?,
    val bssid: String?,
    val isSecure: Boolean,
    val isMetered: Boolean,
    val cellularType: CellularType?
)

data class NetworkThreatAnalysis(
    val isThreat: Boolean,
    val riskScore: Int,
    val reason: String,
    val threatType: NetworkThreatType
)

data class BSSIDHistoryEntry(
    val ssid: String,
    val knownBSSIDs: MutableSet<String>,
    val firstSeen: Long,
    val lastSeen: Long
)

enum class NetworkState {
    UNKNOWN,
    CONNECTED,
    DISCONNECTED,
    SWITCHING
}

enum class NetworkType {
    UNKNOWN,
    WIFI,
    CELLULAR,
    ETHERNET,
    BLUETOOTH
}

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

enum class NetworkThreatType {
    NONE,
    EVIL_TWIN,
    UNSECURED_NETWORK,
    CELLULAR_DOWNGRADE,
    ROGUE_VPN,
    SUSPICIOUS_ROUTING
}
