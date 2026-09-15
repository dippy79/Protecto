package com.protecto.aegis.exfil

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
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
 * PROJECT AEGIS - ExfilGuard 2.0
 * 
 * Advanced data exfiltration detection including:
 * - Standard detection: Background volume spikes, suspicious IP routing
 * - Advanced heuristics: DNS tunneling detection, JA3/JA3S TLS fingerprinting
 * 
 * Core Philosophy: DETECT → BLOCK → ISOLATE → RECORD → ANALYZE → ALERT → RECOVER
 */
class ExfilGuard(
    private val context: Context,
    private val forensicLogger: ForensicLogger
) {
    
    private val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    
    private val dnsTunnelingDetector = DNSTunnelingDetector(context, forensicLogger)
    private val tlsFingerprinter = TLSFingerprinter(context, forensicLogger)
    
    private val _isMonitoring = MutableStateFlow(false)
    val isMonitoring: StateFlow<Boolean> = _isMonitoring.asStateFlow()
    
    private val _dataTransferStats = MutableStateFlow(DataTransferStats())
    val dataTransferStats: StateFlow<DataTransferStats> = _dataTransferStats.asStateFlow()
    
    private val _detectedThreats = MutableStateFlow<List<ThreatAlert>>(emptyList())
    val detectedThreats: StateFlow<List<ThreatAlert>> = _detectedThreats.asStateFlow()
    
    // Traffic baselines
    private val trafficBaseline = TrafficBaseline()
    
    // Active connections tracking
    private val activeConnections = mutableMapOf<String, ConnectionInfo>()
    
    // Data transfer history
    private val transferHistory = mutableListOf<DataTransferEvent>()
    
    /**
     * Start exfiltration monitoring
     */
    fun startMonitoring(): Flow<ThreatAlert> = callbackFlow {
        _isMonitoring.value = true
        
        // Start DNS tunneling detection
        dnsTunnelingDetector.startMonitoring()
            .collect { threat ->
                handleThreatDetection(threat)
            }
        
        // Start TLS fingerprinting
        tlsFingerprinter.startMonitoring()
            .collect { threat ->
                handleThreatDetection(threat)
            }
        
        // Monitor network changes
        val networkRequest = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        
        val networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                handleNetworkAvailable(network)
            }
            
            override fun onLost(network: Network) {
                handleNetworkLost(network)
            }
        }
        
        connectivityManager.registerNetworkCallback(networkRequest, networkCallback)
        
        // Periodic traffic analysis
        val analysisJob = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Default).launch {
            while (_isMonitoring.value) {
                delay(10000) // Analyze every 10 seconds
                performTrafficAnalysis()
            }
        }
        
        awaitClose {
            connectivityManager.unregisterNetworkCallback(networkCallback)
            dnsTunnelingDetector.stopMonitoring()
            tlsFingerprinter.stopMonitoring()
            analysisJob.cancel()
            _isMonitoring.value = false
        }
    }
    
    /**
     * Stop exfiltration monitoring
     */
    fun stopMonitoring() {
        _isMonitoring.value = false
    }
    
    /**
     * Handle network available
     */
    private fun handleNetworkAvailable(network: Network) {
        val capabilities = connectivityManager.getNetworkCapabilities(network)
        if (capabilities != null) {
            // Initialize traffic baseline
            initializeBaseline()
        }
    }
    
    /**
     * Handle network lost
     */
    private fun handleNetworkLost(network: Network) {
        // Clean up connections for this network
        activeConnections.clear()
    }
    
    /**
     * Initialize traffic baseline
     */
    private fun initializeBaseline() {
        // In a real implementation, you would monitor normal traffic patterns
        // for a period to establish baseline metrics
        trafficBaseline.isInitialized = true
        trafficBaseline.baselineTimestamp = System.currentTimeMillis()
    }
    
    /**
     * Perform traffic analysis
     */
    private fun performTrafficAnalysis() {
        if (!trafficBaseline.isInitialized) return
        
        // Analyze volume spikes
        val volumeAnalysis = analyzeVolumeSpikes()
        if (volumeAnalysis.hasSpike) {
            handleVolumeSpike(volumeAnalysis)
        }
        
        // Analyze connection patterns
        val connectionAnalysis = analyzeConnectionPatterns()
        if (connectionAnalysis.isSuspicious) {
            handleSuspiciousConnections(connectionAnalysis)
        }
        
        // Update statistics
        updateDataTransferStats()
    }
    
    /**
     * Analyze volume spikes
     */
    private fun analyzeVolumeSpikes(): VolumeAnalysis {
        val currentStats = _dataTransferStats.value
        val totalBytes = currentStats.bytesSent + currentStats.bytesReceived
        
        // Calculate bytes per second
        val timeWindow = 10.0 // 10 seconds
        val bytesPerSecond = totalBytes / timeWindow
        
        // Check for significant increase from baseline
        val baselineBytesPerSecond = trafficBaseline.averageBytesPerSecond
        val spikeMultiplier = if (baselineBytesPerSecond > 0) {
            bytesPerSecond / baselineBytesPerSecond
        } else {
            1.0
        }
        
        val hasSpike = spikeMultiplier > 5.0 // 5x increase from baseline
        
        return VolumeAnalysis(
            hasSpike = hasSpike,
            currentBytesPerSecond = bytesPerSecond,
            baselineBytesPerSecond = baselineBytesPerSecond,
            spikeMultiplier = spikeMultiplier,
            riskScore = if (hasSpike) (spikeMultiplier * 10).toInt().coerceIn(0, 100) else 0
        )
    }
    
    /**
     * Handle volume spike
     */
    private fun handleVolumeSpike(analysis: VolumeAnalysis) {
        val threat = ThreatAlert(
            id = java.util.UUID.randomUUID().toString(),
            type = LogEventType.NETWORK_CONNECTION,
            category = ThreatCategory.DATA,
            severity = if (analysis.riskScore >= 70) Severity.HIGH else Severity.WARNING,
            riskScore = analysis.riskScore,
            metadata = mapOf(
                "event_type" to "volume_spike",
                "current_bps" to analysis.currentBytesPerSecond.toString(),
                "baseline_bps" to analysis.baselineBytesPerSecond.toString(),
                "spike_multiplier" to analysis.spikeMultiplier.toString()
            )
        )
        
        _detectedThreats.value = _detectedThreats.value + threat
        
        forensicLogger.logEvent(
            eventType = LogEventType.NETWORK_CONNECTION,
            severity = if (analysis.riskScore >= 70) Severity.HIGH else Severity.WARNING,
            metadata = mapOf(
                "event_type" to "volume_spike",
                "current_bps" to analysis.currentBytesPerSecond.toString(),
                "baseline_bps" to analysis.baselineBytesPerSecond.toString(),
                "spike_multiplier" to analysis.spikeMultiplier.toString()
            ),
            riskScore = analysis.riskScore
        )
    }
    
    /**
     * Analyze connection patterns
     */
    private fun analyzeConnectionPatterns(): ConnectionAnalysis {
        val suspiciousConnections = mutableListOf<ConnectionInfo>()
        
        for (connection in activeConnections.values) {
            // Check for connections to suspicious IPs
            if (isSuspiciousIP(connection.remoteAddress)) {
                suspiciousConnections.add(connection)
            }
            
            // Check for connections to non-standard ports
            if (isNonStandardPort(connection.remotePort)) {
                suspiciousConnections.add(connection)
            }
            
            // Check for long-lived connections (potential data exfiltration)
            if (connection.duration > 3600000) { // 1 hour
                suspiciousConnections.add(connection)
            }
        }
        
        return ConnectionAnalysis(
            isSuspicious = suspiciousConnections.isNotEmpty(),
            suspiciousConnections = suspiciousConnections,
            riskScore = (suspiciousConnections.size * 15).coerceIn(0, 100)
        )
    }
    
    /**
     * Handle suspicious connections
     */
    private fun handleSuspiciousConnections(analysis: ConnectionAnalysis) {
        for (connection in analysis.suspiciousConnections) {
            val threat = ThreatAlert(
                id = java.util.UUID.randomUUID().toString(),
                type = LogEventType.NETWORK_CONNECTION,
                category = ThreatCategory.DATA,
                severity = Severity.WARNING,
                riskScore = 30,
                metadata = mapOf(
                    "event_type" to "suspicious_connection",
                    "remote_address" to connection.remoteAddress,
                    "remote_port" to connection.remotePort.toString(),
                    "protocol" to connection.protocol,
                    "duration_ms" to connection.duration.toString()
                )
            )
            
            _detectedThreats.value = _detectedThreats.value + threat
        }
    }
    
    /**
     * Check if IP is suspicious
     */
    private fun isSuspiciousIP(ip: String): Boolean {
        // Check for private IPs (usually safe)
        if (ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("172.")) {
            return false
        }
        
        // Check for localhost
        if (ip == "127.0.0.1" || ip == "::1") {
            return false
        }
        
        // In a real implementation, you would check against threat intelligence feeds
        // For now, just flag certain patterns
        return ip.startsWith("185.") || ip.startsWith("46.") || ip.startsWith("5.")
    }
    
    /**
     * Check if port is non-standard
     */
    private fun isNonStandardPort(port: Int): Boolean {
        val standardPorts = setOf(
            21,   // FTP
            22,   // SSH
            23,   // Telnet
            25,   // SMTP
            53,   // DNS
            80,   // HTTP
            110,  // POP3
            143,  // IMAP
            443,  // HTTPS
            465,  // SMTPS
            587,  // SMTP Submission
            993,  // IMAPS
            995,  // POP3S
            3306, // MySQL
            3389, // RDP
            5432, // PostgreSQL
            5900, // VNC
            8080, // HTTP Alternate
            8443  // HTTPS Alternate
        )
        
        return port !in standardPorts
    }
    
    /**
     * Update data transfer statistics
     */
    private fun updateDataTransferStats() {
        // In a real implementation, you would use TrafficStats API
        // For now, simulate with mock data
        val currentStats = _dataTransferStats.value
        val newStats = currentStats.copy(
            bytesSent = currentStats.bytesSent + (0..1000).random().toLong(),
            bytesReceived = currentStats.bytesReceived + (0..1000).random().toLong(),
            lastUpdated = System.currentTimeMillis()
        )
        _dataTransferStats.value = newStats
        
        // Update baseline
        if (trafficBaseline.isInitialized) {
            trafficBaseline.averageBytesPerSecond = 
                (trafficBaseline.averageBytesPerSecond * 0.9) + 
                ((newStats.bytesSent + newStats.bytesReceived) / 10.0 * 0.1)
        }
    }
    
    /**
     * Record data transfer event
     */
    fun recordDataTransfer(event: DataTransferEvent) {
        transferHistory.add(event)
        
        // Keep only last 1000 events
        if (transferHistory.size > 1000) {
            transferHistory.removeAt(0)
        }
        
        // Update stats
        val currentStats = _dataTransferStats.value
        val newStats = currentStats.copy(
            bytesSent = currentStats.bytesSent + event.bytesSent,
            bytesReceived = currentStats.bytesReceived + event.bytesReceived,
            lastUpdated = System.currentTimeMillis()
        )
        _dataTransferStats.value = newStats
    }
    
    /**
     * Track connection
     */
    fun trackConnection(connection: ConnectionInfo) {
        activeConnections[connection.connectionId] = connection
    }
    
    /**
     * Remove connection
     */
    fun removeConnection(connectionId: String) {
        activeConnections.remove(connectionId)
    }
    
    /**
     * Get active connections
     */
    fun getActiveConnections(): List<ConnectionInfo> {
        return activeConnections.values.toList()
    }
    
    /**
     * Get transfer history
     */
    fun getTransferHistory(): List<DataTransferEvent> {
        return transferHistory.toList()
    }
    
    /**
     * Clear history
     */
    fun clearHistory() {
        transferHistory.clear()
        activeConnections.clear()
        _detectedThreats.value = emptyList()
    }
    
    /**
     * Handle threat detection
     */
    private fun handleThreatDetection(threat: ThreatAlert) {
        _detectedThreats.value = _detectedThreats.value + threat
    }
}

// Data classes for exfiltration monitoring

data class DataTransferStats(
    val bytesSent: Long = 0,
    val bytesReceived: Long = 0,
    val lastUpdated: Long = System.currentTimeMillis()
)

data class DataTransferEvent(
    val connectionId: String,
    val bytesSent: Long,
    val bytesReceived: Long,
    val timestamp: Long = System.currentTimeMillis()
)

data class ConnectionInfo(
    val connectionId: String,
    val localAddress: String,
    val localPort: Int,
    val remoteAddress: String,
    val remotePort: Int,
    val protocol: String,
    val establishedTime: Long = System.currentTimeMillis(),
    val duration: Long = 0
) {
    val currentDuration: Long
        get() = System.currentTimeMillis() - establishedTime
}

data class VolumeAnalysis(
    val hasSpike: Boolean,
    val currentBytesPerSecond: Double,
    val baselineBytesPerSecond: Double,
    val spikeMultiplier: Double,
    val riskScore: Int
)

data class ConnectionAnalysis(
    val isSuspicious: Boolean,
    val suspiciousConnections: List<ConnectionInfo>,
    val riskScore: Int
)

data class TrafficBaseline(
    var isInitialized: Boolean = false,
    var baselineTimestamp: Long = 0,
    var averageBytesPerSecond: Double = 0.0
)
