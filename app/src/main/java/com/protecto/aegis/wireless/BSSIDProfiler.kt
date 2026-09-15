package com.protecto.aegis.wireless

import android.content.Context
import android.net.wifi.WifiManager
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
 * PROJECT AEGIS - BSSID Historical Profiler
 * 
 * Profiles WiFi BSSIDs (Basic Service Set Identifiers) over time to detect
 * network spoofing and evil twin attacks. 
 * 
 * Detection methods:
 * - BSSID history tracking
 * - SSID-BSSID correlation analysis
 * - MAC address pattern detection
 * - Location-based network profiling
 * 
 * Core Philosophy: DETECT → BLOCK → ISOLATE → RECORD → ANALYZE → ALERT → RECOVER
 */
class BSSIDProfiler(
    private val context: Context,
    private val forensicLogger: ForensicLogger
) {
    
    private val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
    
    private val _isMonitoring = MutableStateFlow(false)
    val isMonitoring: StateFlow<Boolean> = _isMonitoring.asStateFlow()
    
    private val _bssidProfiles = MutableStateFlow<Map<String, BSSIDProfile>>(emptyMap())
    val bssidProfiles: StateFlow<Map<String, BSSIDProfile>> = _bssidProfiles.asStateFlow()
    
    private val _suspiciousNetworks = MutableStateFlow<List<SuspiciousNetwork>>(emptyList())
    val suspiciousNetworks: StateFlow<List<SuspiciousNetwork>> = _suspiciousNetworks.asStateFlow()
    
    // BSSID profile database
    private val profileDatabase = mutableMapOf<String, BSSIDProfile>()
    
    // SSID to BSSID mapping
    private val ssidToBssidMap = mutableMapOf<String, MutableSet<String>>()
    
    // Known legitimate BSSIDs
    private val knownLegitimateBSSIDs = mutableSetOf<String>()
    
    /**
     * Start BSSID profiling
     */
    fun startMonitoring(): Flow<ThreatAlert> = callbackFlow {
        _isMonitoring.value = true
        
        // Scan for current network
        scanCurrentNetwork()
        
        // WiFi scan receiver
        val wifiScanReceiver = object : android.content.BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent) {
                if (intent.action == WifiManager.SCAN_RESULTS_AVAILABLE_ACTION) {
                    handleScanResults()
                }
            }
        }
        
        val filter = android.content.IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION)
        context.registerReceiver(wifiScanReceiver, filter)
        
        // Periodic scans
        val scanJob = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Default).launch {
            while (_isMonitoring.value) {
                delay(60000) // Scan every minute
                performWifiScan()
            }
        }
        
        awaitClose {
            context.unregisterReceiver(wifiScanReceiver)
            scanJob.cancel()
            _isMonitoring.value = false
        }
    }
    
    /**
     * Stop BSSID profiling
     */
    fun stopMonitoring() {
        _isMonitoring.value = false
    }
    
    /**
     * Scan current network
     */
    private fun scanCurrentNetwork() {
        val connectionInfo = wifiManager.connectionInfo
        if (connectionInfo != null) {
            val bssid = connectionInfo.bssid
            val ssid = connectionInfo.ssid?.removeSurrounding("\"")
            
            if (bssid != null && ssid != null) {
                profileBSSID(bssid, ssid)
            }
        }
    }
    
    /**
     * Perform WiFi scan
     */
    private fun performWifiScan() {
        val success = wifiManager.startScan()
        if (!success) {
            forensicLogger.logEvent(
                eventType = LogEventType.NETWORK_CONNECTION,
                severity = Severity.WARNING,
                metadata = mapOf(
                    "event_type" to "wifi_scan_failed",
                    "reason" to "scan_start_failed"
                ),
                riskScore = 10
            )
        }
    }
    
    /**
     * Handle scan results
     */
    private fun handleScanResults() {
        val scanResults = wifiManager.scanResults
        
        for (result in scanResults) {
            val bssid = result.BSSID
            val ssid = result.SSID
            
            if (bssid.isNotEmpty() && ssid.isNotEmpty()) {
                profileBSSID(bssid, ssid)
            }
        }
        
        // Analyze for suspicious patterns
        analyzeForSuspiciousNetworks()
    }
    
    /**
     * Profile a BSSID
     */
    private fun profileBSSID(bssid: String, ssid: String) {
        val existingProfile = profileDatabase[bssid]
        
        if (existingProfile != null) {
            // Update existing profile
            val updatedProfile = existingProfile.copy(
                lastSeen = System.currentTimeMillis(),
                encounterCount = existingProfile.encounterCount + 1,
                associatedSSIDs = existingProfile.associatedSSIDs + ssid
            )
            profileDatabase[bssid] = updatedProfile
        } else {
            // Create new profile
            val newProfile = BSSIDProfile(
                bssid = bssid,
                firstSeen = System.currentTimeMillis(),
                lastSeen = System.currentTimeMillis(),
                encounterCount = 1,
                associatedSSIDs = setOf(ssid),
                manufacturer = identifyManufacturer(bssid),
                isRandomMac = isRandomMacAddress(bssid),
                signalStrengthHistory = mutableListOf(),
                riskScore = calculateInitialRiskScore(bssid, ssid)
            )
            profileDatabase[bssid] = newProfile
        }
        
        // Update SSID to BSSID mapping
        if (!ssidToBssidMap.containsKey(ssid)) {
            ssidToBssidMap[ssid] = mutableSetOf()
        }
        ssidToBssidMap[ssid]?.add(bssid)
        
        _bssidProfiles.value = profileDatabase.toMap()
    }
    
    /**
     * Identify manufacturer from BSSID (OUI)
     */
    private fun identifyManufacturer(bssid: String): String {
        val oui = bssid.substring(0, 8).replace(":", "").uppercase()
        
        // Common manufacturer OUIs
        val manufacturerMap = mapOf(
            "000000" to "Xerox Corporation",
            "001018" to "Broadcom Corporation",
            "0011BB" to "Apple, Inc.",
            "0017C4" to "Apple, Inc.",
            "001A11" to "Apple, Inc.",
            "001B63" to "Apple, Inc.",
            "001CF0" to "Apple, Inc.",
            "0022F3" to "Apple, Inc.",
            "002436" to "Apple, Inc.",
            "0026B9" to "Apple, Inc.",
            "003065" to "Apple, Inc.",
            "00E0FC" to "Apple, Inc.",
            "0418B6" to "Apple, Inc.",
            "10F9A9" to "Apple, Inc.",
            "1C7BE6" to "Apple, Inc.",
            "28CFE9" to "Apple, Inc.",
            "3CB75A" to "Apple, Inc.",
            "40A6D9" to "Apple, Inc.",
            "4CA9D0" to "Apple, Inc.",
            "5855CA" to "Apple, Inc.",
            "64B9E8" to "Apple, Inc.",
            "6C4090" to "Apple, Inc.",
            "74C246" to "Apple, Inc.",
            "787F70" to "Apple, Inc.",
            "7CA908" to "Apple, Inc.",
            "88E9FE" to "Apple, Inc.",
            "8CFBAD" to "Apple, Inc.",
            "984B50" to "Apple, Inc.",
            "A4D1D2" to "Apple, Inc.",
            "ACBC32" to "Apple, Inc.",
            "B88AFB" to "Apple, Inc.",
            "BC5FF4" to "Apple, Inc.",
            "C4B3E1" to "Apple, Inc.",
            "CC20E8" to "Apple, Inc.",
            "D4A45D" to "Apple, Inc.",
            "E0ACD8" to "Apple, Inc.",
            "F01898" to "Apple, Inc.",
            "F8FFC2" to "Apple, Inc.",
            "FCA691" to "Apple, Inc.",
            "001319" to "Netgear, Inc.",
            "00158A" to "Netgear, Inc.",
            "001E58" to "Netgear, Inc.",
            "00226B" to "Netgear, Inc.",
            "0024B2" to "Netgear, Inc.",
            "002659" to "Netgear, Inc.",
            "0040F4" to "Netgear, Inc.",
            "0050CB" to "Netgear, Inc.",
            "00158A" to "Netgear, Inc.",
            "000C41" to "Netgear, Inc.",
            "001112" to "Netgear, Inc.",
            "0013C8" to "Cisco Systems",
            "0015C5" to "Cisco Systems",
            "001517" to "Cisco Systems",
            "001650" to "Cisco Systems",
            "0017C4" to "Cisco Systems",
            "0018B9" to "Cisco Systems",
            "001A4B" to "Cisco Systems",
            "001B9E" to "Cisco Systems",
            "001CF0" to "Cisco Systems",
            "001D45" to "Cisco Systems",
            "001E13" to "Cisco Systems",
            "001E49" to "Cisco Systems",
            "001E79" to "Cisco Systems",
            "001F6C" to "Cisco Systems",
            "00215A" to "Cisco Systems",
            "002233" to "Cisco Systems",
            "002290" to "Cisco Systems",
            "002355" to "Cisco Systems",
            "0024AB" to "Cisco Systems",
            "0024DB" to "Cisco Systems",
            "00259C" to "Cisco Systems",
            "002698" to "Cisco Systems",
            "002722" to "Cisco Systems",
            "002915" to "Cisco Systems",
            "0050BF" to "Cisco Systems",
            "005056" to "Cisco Systems",
            "005073" to "Cisco Systems",
            "0050BA" to "Cisco Systems",
            "00E0F7" to "Cisco Systems",
            "00F0F2" to "Cisco Systems",
            "0415BE" to "Cisco Systems",
            "14CC1D" to "Cisco Systems",
            "18EF63" to "Cisco Systems",
            "1C5834" to "Cisco Systems",
            "28930A" to "Cisco Systems",
            "30DB8A" to "Cisco Systems",
            "3417EB" to "Cisco Systems",
            "40A677" to "Cisco Systems",
            "50FA84" to "Cisco Systems",
            "5C4CAA" to "Cisco Systems",
            "684265" to "Cisco Systems",
            "70CA9B" to "Cisco Systems",
            "74A2E6" to "Cisco Systems",
            "78BC1C" to "Cisco Systems",
            "84A8E2" to "Cisco Systems",
            "8C9A1D" to "Cisco Systems",
            "8C9360" to "Cisco Systems",
            "94A088" to "Cisco Systems",
            "A45296" to "Cisco Systems",
            "ACF30B" to "Cisco Systems",
            "B0EA94" to "Cisco Systems",
            "B4A4F3" to "Cisco Systems",
            "C04A00" to "Cisco Systems",
            "C84C75" to "Cisco Systems",
            "CCA356" to "Cisco Systems",
            "D0B2C4" to "Cisco Systems",
            "D455C2" to "Cisco Systems",
            "D8B4FD" to "Cisco Systems",
            "E0F84C" to "Cisco Systems",
            "E8EA60" to "Cisco Systems",
            "F4CFE2" to "Cisco Systems",
            "F41F18" to "Cisco Systems",
            "FCA843" to "Cisco Systems",
            "FCC2B4" to "Cisco Systems",
            "0011E0" to "Intel Corporate",
            "0012F0" to "Intel Corporate",
            "0013CE" to "Intel Corporate",
            "0014BF" to "Intel Corporate",
            "001517" to "Intel Corporate",
            "0015C0" to "Intel Corporate",
            "0016D6" to "Intel Corporate",
            "0018DE" to "Intel Corporate",
            "001B21" to "Intel Corporate",
            "001BE0" to "Intel Corporate",
            "001CB0" to "Intel Corporate",
            "001D09" to "Intel Corporate",
            "001E67" to "Intel Corporate",
            "001F3B" to "Intel Corporate",
            "002191" to "Intel Corporate",
            "00226C" to "Intel Corporate",
            "002354" to "Intel Corporate",
            "002417" to "Intel Corporate",
            "0024D1" to "Intel Corporate",
            "002655" to "Intel Corporate",
            "002719" to "Intel Corporate",
            "0030D4" to "Intel Corporate",
            "00E04C" to "Intel Corporate",
            "04D4C4" to "Intel Corporate",
            "1490AD" to "Intel Corporate",
            "188B73" to "Intel Corporate",
            "1CC0DE" to "Intel Corporate",
            "207A93" to "Intel Corporate",
            "24F5A2" to "Intel Corporate",
            "3C970E" to "Intel Corporate",
            "4061C0" to "Intel Corporate",
            "4C9614" to "Intel Corporate",
            "50E549" to "Intel Corporate",
            "5404A6" to "Intel Corporate",
            "58FA84" to "Intel Corporate",
            "60A44C" to "Intel Corporate",
            "64D144" to "Intel Corporate",
            "68F728" to "Intel Corporate",
            "7085C2" to "Intel Corporate",
            "782BCA" to "Intel Corporate",
            "84A8E2" to "Intel Corporate",
            "8C9A3B" to "Intel Corporate",
            "9458F8" to "Intel Corporate",
            "A0D1D6" to "Intel Corporate",
            "A41731" to "Intel Corporate",
            "AC728A" to "Intel Corporate",
            "B0AAE3" to "Intel Corporate",
            "B42E99" to "Intel Corporate",
            "BC5FF4" to "Intel Corporate",
            "C460DE" to "Intel Corporate",
            "C85B76" to "Intel Corporate",
            "CCB255" to "Intel Corporate",
            "D84CFA" to "Intel Corporate",
            "DCFB2E" to "Intel Corporate",
            "E068B6" to "Intel Corporate",
            "E0DB55" to "Intel Corporate",
            "E4D3D1" to "Intel Corporate",
            "E8E0B7" to "Intel Corporate",
            "F04F7C" to "Intel Corporate",
            "F46D04" to "Intel Corporate",
            "F8CAB8" to "Intel Corporate",
            "FCACB5" to "Intel Corporate"
        )
        
        return manufacturerMap[oui] ?: "Unknown Manufacturer"
    }
    
    /**
     * Check if BSSID is a random MAC address
     */
    private fun isRandomMacAddress(bssid: String): Boolean {
        // Random MAC addresses have the locally-administered bit set
        // This is the second least significant bit of the first octet
        val firstOctet = bssid.substring(0, 2).replace(":", "").toInt(16)
        return (firstOctet and 0x02) != 0
    }
    
    /**
     * Calculate initial risk score for BSSID
     */
    private fun calculateInitialRiskScore(bssid: String, ssid: String): Int {
        var riskScore = 0
        
        // Random MAC addresses are higher risk
        if (isRandomMacAddress(bssid)) {
            riskScore += 20
        }
        
        // Unknown manufacturer is higher risk
        val manufacturer = identifyManufacturer(bssid)
        if (manufacturer == "Unknown Manufacturer") {
            riskScore += 15
        }
        
        // Check if SSID is commonly spoofed
        if (isCommonlySpoofedSSID(ssid)) {
            riskScore += 25
        }
        
        return riskScore.coerceIn(0, 100)
    }
    
    /**
     * Check if SSID is commonly spoofed
     */
    private fun isCommonlySpoofedSSID(ssid: String): Boolean {
        val commonSSIDs = setOf(
            "FreeWiFi",
            "Free Public WiFi",
            "Airport WiFi",
            "Starbucks WiFi",
            "McDonalds Free WiFi",
            "Public WiFi",
            "Guest Network",
            "Xfinitywifi",
            "attwifi",
            "CableWiFi"
        )
        
        return ssid in commonSSIDs
    }
    
    /**
     * Analyze for suspicious networks
     */
    private fun analyzeForSuspiciousNetworks() {
        val suspiciousNetworks = mutableListOf<SuspiciousNetwork>()
        
        // Check for SSID spoofing (same SSID, different BSSIDs)
        for ((ssid, bssids) in ssidToBssidMap) {
            if (bssids.size > 1) {
                // Multiple BSSIDs for same SSID - potential evil twin
                for (bssid in bssids) {
                    val profile = profileDatabase[bssid]
                    if (profile != null && profile !in knownLegitimateBSSIDs) {
                        suspiciousNetworks.add(
                            SuspiciousNetwork(
                                ssid = ssid,
                                bssid = bssid,
                                threatType = "evil_twin_candidate",
                                riskScore = 60,
                                reason = "Multiple BSSIDs for same SSID",
                                timestamp = System.currentTimeMillis()
                            )
                        )
                    }
                }
            }
        }
        
        // Check for random MAC addresses appearing as legitimate
        for ((bssid, profile) in profileDatabase) {
            if (profile.isRandomMac && profile.encounterCount > 5) {
                suspiciousNetworks.add(
                    SuspiciousNetwork(
                        ssid = profile.associatedSSIDs.firstOrNull() ?: "unknown",
                        bssid = bssid,
                        threatType = "persistent_random_mac",
                        riskScore = 40,
                        reason = "Random MAC address seen multiple times",
                        timestamp = System.currentTimeMillis()
                    )
                )
            }
        }
        
        _suspiciousNetworks.value = suspiciousNetworks
        
        // Log suspicious networks
        for (network in suspiciousNetworks) {
            forensicLogger.logEvent(
                eventType = LogEventType.NETWORK_CONNECTION,
                severity = if (network.riskScore >= 60) Severity.HIGH else Severity.WARNING,
                metadata = mapOf(
                    "event_type" to "suspicious_network_detected",
                    "ssid" to network.ssid,
                    "bssid" to network.bssid,
                    "threat_type" to network.threatType,
                    "risk_score" to network.riskScore.toString(),
                    "reason" to network.reason
                ),
                riskScore = network.riskScore
            )
        }
    }
    
    /**
     * Mark BSSID as legitimate
     */
    fun markAsLegitimate(bssid: String) {
        knownLegitimateBSSIDs.add(bssid)
        
        val profile = profileDatabase[bssid]
        if (profile != null) {
            val updatedProfile = profile.copy(riskScore = 0)
            profileDatabase[bssid] = updatedProfile
            _bssidProfiles.value = profileDatabase.toMap()
        }
    }
    
    /**
     * Get BSSID profile
     */
    fun getBSSIDProfile(bssid: String): BSSIDProfile? {
        return profileDatabase[bssid]
    }
    
    /**
     * Get all profiles
     */
    fun getAllProfiles(): Map<String, BSSIDProfile> {
        return profileDatabase.toMap()
    }
    
    /**
     * Clear all profiles
     */
    fun clearAllProfiles() {
        profileDatabase.clear()
        ssidToBssidMap.clear()
        knownLegitimateBSSIDs.clear()
        _bssidProfiles.value = emptyMap()
        _suspiciousNetworks.value = emptyList()
    }
}

// Data classes for BSSID profiling

data class BSSIDProfile(
    val bssid: String,
    val firstSeen: Long,
    val lastSeen: Long,
    val encounterCount: Int,
    val associatedSSIDs: Set<String>,
    val manufacturer: String,
    val isRandomMac: Boolean,
    val signalStrengthHistory: MutableList<Int>,
    val riskScore: Int
)

data class SuspiciousNetwork(
    val ssid: String,
    val bssid: String,
    val threatType: String,
    val riskScore: Int,
    val reason: String,
    val timestamp: Long
)
