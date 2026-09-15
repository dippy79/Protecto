package com.protecto.aegis.app

import android.content.Context
import android.provider.Settings
import android.view.accessibility.AccessibilityManager
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
 * PROJECT AEGIS - Accessibility Abuse Detector
 * 
 * Detects abuse of Android accessibility services which can be used for:
 * - Reading sensitive information (passwords, messages)
 * - Performing automated actions without user consent
 * - Keylogging and screen scraping
 * - Bypassing security controls
 * 
 * Detection methods:
 * - Monitor enabled accessibility services
 * - Detect suspicious accessibility service behavior
 * - Identify services with excessive permissions
 * - Check for accessibility service spam
 * 
 * Core Philosophy: DETECT → BLOCK → ISOLATE → RECORD → ANALYZE → ALERT → RECOVER
 */
class AccessibilityAbuseDetector(
    private val context: Context,
    private val forensicLogger: ForensicLogger
) {
    
    private val accessibilityManager = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
    
    private val _isMonitoring = MutableStateFlow(false)
    val isMonitoring: StateFlow<Boolean> = _isMonitoring.asStateFlow()
    
    private val _enabledServices = MutableStateFlow<List<AccessibilityServiceInfo>>(emptyList())
    val enabledServices: StateFlow<List<AccessibilityServiceInfo>> = _enabledServices.asStateFlow()
    
    private val _detectedAbuse = MutableStateFlow<List<AccessibilityAbuseAlert>>(emptyList())
    val detectedAbuse: StateFlow<List<AccessibilityAbuseAlert>> = _detectedAbuse.asStateFlow()
    
    // Known safe accessibility services
    private val knownSafeServices = setOf(
        "com.google.android.marvin.talkback.TalkBackService",
        "com.samsung.android.accessibility.talkback.TalkBackService",
        "com.android.talkback.TalkBackService",
        "com.google.android.accessibility.accessibilitymenu.AccessibilityMenuService",
        "com.samsung.accessibility.AccessibilityMenuService"
    )
    
    // Suspicious accessibility service patterns
    private val suspiciousPatterns = listOf(
        "keylogger",
        "screen",
        "capture",
        "spy",
        "monitor",
        "steal",
        "hack",
        "exploit"
    )
    
    /**
     * Start accessibility abuse monitoring
     */
    fun startMonitoring(): Flow<ThreatAlert> = callbackFlow {
        _isMonitoring.value = true
        
        // Initial scan
        performInitialScan()
        
        // Monitor accessibility service changes
        val accessibilityReceiver = object : android.content.BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: android.content.Intent) {
                when (intent.action) {
                    "android.accessibilityservice.accessibility_state" -> {
                        performInitialScan()
                    }
                }
            }
        }
        
        val filter = android.content.IntentFilter("android.accessibilityservice.accessibility_state")
        context.registerReceiver(accessibilityReceiver, filter)
        
        // Periodic checks
        val checkJob = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Default).launch {
            while (_isMonitoring.value) {
                delay(30000) // Check every 30 seconds
                performPeriodicCheck()
            }
        }
        
        awaitClose {
            context.unregisterReceiver(accessibilityReceiver)
            checkJob.cancel()
            _isMonitoring.value = false
        }
    }
    
    /**
     * Stop accessibility abuse monitoring
     */
    fun stopMonitoring() {
        _isMonitoring.value = false
    }
    
    /**
     * Perform initial scan
     */
    private fun performInitialScan() {
        val enabledServices = getEnabledAccessibilityServices()
        _enabledServices.value = enabledServices
        
        // Analyze each service
        for (service in enabledServices) {
            val abuseAnalysis = analyzeAccessibilityService(service)
            
            if (abuseAnalysis.isAbusive) {
                val alert = AccessibilityAbuseAlert(
                    serviceName = service.serviceName,
                    packageName = service.packageName,
                    abuseType = abuseAnalysis.abuseType,
                    riskScore = abuseAnalysis.riskScore,
                    reasons = abuseAnalysis.reasons,
                    timestamp = System.currentTimeMillis()
                )
                
                _detectedAbuse.value = _detectedAbuse.value + alert
                
                val threat = ThreatAlert(
                    id = java.util.UUID.randomUUID().toString(),
                    type = LogEventType.APP_PERMISSION_CHANGE,
                    category = ThreatCategory.APP,
                    severity = if (abuseAnalysis.riskScore >= 70) Severity.HIGH else Severity.WARNING,
                    riskScore = abuseAnalysis.riskScore,
                    metadata = mapOf(
                        "event_type" to "accessibility_abuse_detected",
                        "service_name" to service.serviceName,
                        "package_name" to service.packageName,
                        "abuse_type" to abuseAnalysis.abuseType,
                        "reasons" to abuseAnalysis.reasons.joinToString(",")
                    )
                )
                
                trySend(threat)
                
                forensicLogger.logEvent(
                    eventType = LogEventType.APP_PERMISSION_CHANGE,
                    severity = if (abuseAnalysis.riskScore >= 70) Severity.HIGH else Severity.WARNING,
                    metadata = mapOf(
                        "event_type" to "accessibility_abuse_detected",
                        "service_name" to service.serviceName,
                        "package_name" to service.packageName,
                        "abuse_type" to abuseAnalysis.abuseType,
                        "reasons" to abuseAnalysis.reasons.joinToString(",")
                    ),
                    riskScore = abuseAnalysis.riskScore
                )
            }
        }
    }
    
    /**
     * Perform periodic check
     */
    private fun performPeriodicCheck() {
        val currentServices = getEnabledAccessibilityServices()
        val previousServices = _enabledServices.value
        
        // Check for new services
        val newServices = currentServices.filter { current ->
            previousServices.none { it.serviceName == current.serviceName }
        }
        
        // Check for removed services
        val removedServices = previousServices.filter { previous ->
            currentServices.none { it.serviceName == previous.serviceName }
        }
        
        // Handle new services
        for (service in newServices) {
            val abuseAnalysis = analyzeAccessibilityService(service)
            
            if (abuseAnalysis.isAbusive) {
                val alert = AccessibilityAbuseAlert(
                    serviceName = service.serviceName,
                    packageName = service.packageName,
                    abuseType = abuseAnalysis.abuseType,
                    riskScore = abuseAnalysis.riskScore,
                    reasons = abuseAnalysis.reasons,
                    timestamp = System.currentTimeMillis()
                )
                
                _detectedAbuse.value = _detectedAbuse.value + alert
                
                val threat = ThreatAlert(
                    id = java.util.UUID.randomUUID().toString(),
                    type = LogEventType.APP_PERMISSION_CHANGE,
                    category = ThreatCategory.APP,
                    severity = if (abuseAnalysis.riskScore >= 70) Severity.HIGH else Severity.WARNING,
                    riskScore = abuseAnalysis.riskScore,
                    metadata = mapOf(
                        "event_type" to "new_accessibility_service",
                        "service_name" to service.serviceName,
                        "package_name" to service.packageName,
                        "abuse_type" to abuseAnalysis.abuseType,
                        "reasons" to abuseAnalysis.reasons.joinToString(",")
                    )
                )
                
                trySend(threat)
            }
        }
        
        // Log removed services
        for (service in removedServices) {
            forensicLogger.logEvent(
                eventType = LogEventType.APP_PERMISSION_CHANGE,
                severity = Severity.INFO,
                metadata = mapOf(
                    "event_type" to "accessibility_service_removed",
                    "service_name" to service.serviceName,
                    "package_name" to service.packageName
                ),
                riskScore = 0
            )
        }
        
        _enabledServices.value = currentServices
    }
    
    /**
     * Get enabled accessibility services
     */
    private fun getEnabledAccessibilityServices(): List<AegisAccessibilityServiceInfo> {
        val services = mutableListOf<AegisAccessibilityServiceInfo>()
        
        try {
            val enabledServices = accessibilityManager.getEnabledAccessibilityServiceList(
                android.view.accessibility.AccessibilityServiceInfo.FEEDBACK_ALL_MASK
            )
            
            for (service in enabledServices) {
                val serviceInfo = AegisAccessibilityServiceInfo(
                    serviceName = service.id,
                    packageName = service.resolveInfo.serviceInfo.packageName,
                    eventTypes = service.eventTypes,
                    feedbackTypes = service.feedbackType,
                    flags = service.flags,
                    capabilities = service.capabilities,
                    description = service.loadDescription(context.packageManager)
                )
                services.add(serviceInfo)
            }
        } catch (e: Exception) {
            // Log error but continue
        }
        
        return services
    }
    
    /**
     * Analyze accessibility service for abuse
     */
    private fun analyzeAccessibilityService(service: AegisAccessibilityServiceInfo): AccessibilityAbuseAnalysis {
        val reasons = mutableListOf<String>()
        var riskScore = 0
        var abuseType = "unknown"
        
        // Check if known safe service
        if (service.serviceName in knownSafeServices) {
            return AccessibilityAbuseAnalysis(
                isAbusive = false,
                riskScore = 0,
                abuseType = "none",
                reasons = emptyList()
            )
        }
        
        // Check for suspicious patterns in service name
        val serviceNameLower = service.serviceName.lowercase()
        for (pattern in suspiciousPatterns) {
            if (pattern in serviceNameLower) {
                riskScore += 30
                reasons.add("suspicious_pattern:$pattern")
                abuseType = "suspicious_name"
            }
        }
        
        // Check for excessive event types
        if (service.eventTypes.size > 20) {
            riskScore += 20
            reasons.add("excessive_event_types:${service.eventTypes.size}")
            abuseType = "excessive_monitoring"
        }
        
        // Check for sensitive event types
        val sensitiveEvents = listOf(
            android.view.accessibility.AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED,
            android.view.accessibility.AccessibilityEvent.TYPE_VIEW_FOCUSED,
            android.view.accessibility.AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED,
            android.view.accessibility.AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED
        )
        
        for (eventType in sensitiveEvents) {
            if (eventType in service.eventTypes) {
                riskScore += 15
                reasons.add("sensitive_event_type:$eventType")
                abuseType = "sensitive_monitoring"
            }
        }
        
        // Check for package name suspiciousness
        val packageNameLower = service.packageName.lowercase()
        if (packageNameLower.contains("unknown") || 
            packageNameLower.contains("temp") ||
            packageNameLower.contains("test")) {
            riskScore += 25
            reasons.add("suspicious_package_name")
            abuseType = "suspicious_origin"
        }
        
        // Check for missing description
        if (service.description.isNullOrEmpty()) {
            riskScore += 15
            reasons.add("missing_description")
        }
        
        // Check for unknown package
        try {
            context.packageManager.getPackageInfo(service.packageName, 0)
        } catch (e: Exception) {
            riskScore += 40
            reasons.add("unknown_package")
            abuseType = "unknown_origin"
        }
        
        return AccessibilityAbuseAnalysis(
            isAbusive = riskScore > 30,
            riskScore = riskScore.coerceIn(0, 100),
            abuseType = abuseType,
            reasons = reasons
        )
    }
    
    /**
     * Check if accessibility is enabled
     */
    fun isAccessibilityEnabled(): Boolean {
        return accessibilityManager.isEnabled
    }
    
    /**
     * Get enabled accessibility service count
     */
    fun getEnabledServiceCount(): Int {
        return _enabledServices.value.size
    }
    
    /**
     * Disable accessibility service (requires user interaction)
     */
    fun requestDisableAccessibilityService(serviceName: String) {
        // This would require user interaction via UI
        // For now, just log the request
        forensicLogger.logEvent(
            eventType = LogEventType.APP_PERMISSION_CHANGE,
            severity = Severity.INFO,
            metadata = mapOf(
                "action" to "request_disable_accessibility",
                "service_name" to serviceName
            ),
            riskScore = 0
        )
    }
    
    /**
     * Mark service as safe
     */
    fun markServiceAsSafe(serviceName: String) {
        // In a real implementation, this would be persistent
        // For now, just remove from detected abuse
        val currentAbuse = _detectedAbuse.value.toMutableList()
        currentAbuse.removeAll { it.serviceName == serviceName }
        _detectedAbuse.value = currentAbuse
    }
    
    /**
     * Get abuse history
     */
    fun getAbuseHistory(): List<AccessibilityAbuseAlert> {
        return _detectedAbuse.value
    }
    
    /**
     * Clear abuse history
     */
    fun clearAbuseHistory() {
        _detectedAbuse.value = emptyList()
    }
}

// Data classes for accessibility abuse detection

data class AccessibilityServiceInfo(
    val serviceName: String,
    val packageName: String,
    val eventTypes: List<Int>,
    val feedbackTypes: Int,
    val flags: Int,
    val capabilities: Int,
    val description: String?
)

data class AccessibilityAbuseAnalysis(
    val isAbusive: Boolean,
    val riskScore: Int,
    val abuseType: String,
    val reasons: List<String>
)

data class AccessibilityAbuseAlert(
    val serviceName: String,
    val packageName: String,
    val abuseType: String,
    val riskScore: Int,
    val reasons: List<String>,
    val timestamp: Long
)
