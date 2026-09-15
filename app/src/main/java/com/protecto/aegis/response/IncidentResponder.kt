package com.protecto.aegis.response

import android.content.Context
import com.protecto.aegis.core.ForensicLogger
import com.protecto.aegis.core.LogEventType
import com.protecto.aegis.core.Severity
import com.protecto.aegis.core.ThreatAlert
import com.protecto.aegis.core.ThreatCategory
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * PROJECT AEGIS - Incident Responder
 * 
 * Automated incident response system that triggers appropriate responses
 * based on threat severity and category. Implements the response phase of
 * the security lifecycle.
 * 
 * Response Matrix:
 * - PHYSICAL + CRITICAL → Dead Man's Switch (Lockdown Mode)
 * - WIRELESS + CRITICAL → Faraday Mode (Network Isolation)
 * - DATA + HIGH → Traffic blocking, DNS filtering
 * - APP + HIGH → App quarantine, permission revocation
 * - SYSTEM + CRITICAL → Full system lockdown
 * 
 * Core Philosophy: DETECT → BLOCK → ISOLATE → RECORD → ANALYZE → ALERT → RECOVER
 */
class IncidentResponder(
    private val context: Context,
    private val forensicLogger: ForensicLogger
) {
    
    private val deadMansSwitch = DeadMansSwitch(context, forensicLogger)
    private val faradayMode = FaradayMode(context, forensicLogger)
    
    private val _isResponding = MutableStateFlow(false)
    val isResponding: StateFlow<Boolean> = _isResponding.asStateFlow()
    
    private val _activeResponses = MutableStateFlow<List<ActiveResponse>>(emptyList())
    val activeResponses: StateFlow<List<ActiveResponse>> = _activeResponses.asStateFlow()
    
    private val _responseHistory = MutableStateFlow<List<IncidentResponse>>(emptyList())
    val responseHistory: StateFlow<List<IncidentResponse>> = _responseHistory.asStateFlow()
    
    // Response rules
    private val responseRules = mapOf(
        Pair(ThreatCategory.PHYSICAL, Severity.CRITICAL) to ResponseAction.DEAD_MANS_SWITCH,
        Pair(ThreatCategory.WIRELESS, Severity.CRITICAL) to ResponseAction.FARADAY_MODE,
        Pair(ThreatCategory.DATA, Severity.HIGH) to ResponseAction.TRAFFIC_BLOCK,
        Pair(ThreatCategory.DATA, Severity.CRITICAL) to ResponseAction.FARADAY_MODE,
        Pair(ThreatCategory.APP, Severity.HIGH) to ResponseAction.APP_QUARANTINE,
        Pair(ThreatCategory.APP, Severity.CRITICAL) to ResponseAction.DEAD_MANS_SWITCH,
        Pair(ThreatCategory.SYSTEM, Severity.HIGH) to ResponseAction.PARTIAL_LOCKDOWN,
        Pair(ThreatCategory.SYSTEM, Severity.CRITICAL) to ResponseAction.FULL_LOCKDOWN
    )
    
    /**
     * Handle threat with automated response
     */
    fun handleThreat(threat: ThreatAlert) {
        _isResponding.value = true
        
        // Determine appropriate response based on threat category and severity
        val responseAction = determineResponseAction(threat)
        
        // Execute response
        val response = executeResponse(threat, responseAction)
        
        // Update active responses
        val currentResponses = _activeResponses.value.toMutableList()
        currentResponses.add(ActiveResponse(
            threatId = threat.id,
            action = responseAction,
            startTime = System.currentTimeMillis(),
            status = ResponseStatus.ACTIVE
        ))
        _activeResponses.value = currentResponses
        
        // Update response history
        val history = _responseHistory.value.toMutableList()
        history.add(response)
        _responseHistory.value = history
        
        _isResponding.value = false
    }
    
    /**
     * Determine response action based on threat
     */
    private fun determineResponseAction(threat: ThreatAlert): ResponseAction {
        return responseRules[Pair(threat.category, threat.severity)] ?: ResponseAction.MONITOR_ONLY
    }
    
    /**
     * Execute response action
     */
    private fun executeResponse(threat: ThreatAlert, action: ResponseAction): IncidentResponse {
        val startTime = System.currentTimeMillis()
        var success = false
        var details = mutableMapOf<String, Any>()
        
        when (action) {
            ResponseAction.DEAD_MANS_SWITCH -> {
                try {
                    deadMansSwitch.activate()
                    success = true
                    details["lockdown_mode"] = "full"
                } catch (e: Exception) {
                    details["error"] = e.message ?: "Unknown error"
                }
            }
            
            ResponseAction.FARADAY_MODE -> {
                try {
                    faradayMode.activate()
                    success = true
                    details["isolation_mode"] = "full"
                } catch (e: Exception) {
                    details["error"] = e.message ?: "Unknown error"
                }
            }
            
            ResponseAction.TRAFFIC_BLOCK -> {
                try {
                    // Block specific traffic
                    blockSpecificTraffic(threat)
                    success = true
                    details["blocked_traffic"] = true
                } catch (e: Exception) {
                    details["error"] = e.message ?: "Unknown error"
                }
            }
            
            ResponseAction.APP_QUARANTINE -> {
                try {
                    // Quarantine the app
                    val packageName = threat.metadata["package_name"] as? String
                    if (packageName != null) {
                        quarantineApp(packageName)
                        success = true
                        details["quarantined_app"] = packageName
                    } else {
                        details["error"] = "No package name in threat metadata"
                    }
                } catch (e: Exception) {
                    details["error"] = e.message ?: "Unknown error"
                }
            }
            
            ResponseAction.PARTIAL_LOCKDOWN -> {
                try {
                    // Activate partial lockdown
                    val measures = setOf(
                        LockdownMeasure.UI_OBSCURATION,
                        LockdownMeasure.BIOMETRICS_DISABLE
                    )
                    deadMansSwitch.activatePartialLockdown(measures)
                    success = true
                    details["lockdown_mode"] = "partial"
                } catch (e: Exception) {
                    details["error"] = e.message ?: "Unknown error"
                }
            }
            
            ResponseAction.FULL_LOCKDOWN -> {
                try {
                    // Activate full lockdown and Faraday mode
                    deadMansSwitch.activate()
                    faradayMode.activate()
                    success = true
                    details["lockdown_mode"] = "full_system"
                    details["isolation_mode"] = "full"
                } catch (e: Exception) {
                    details["error"] = e.message ?: "Unknown error"
                }
            }
            
            ResponseAction.MONITOR_ONLY -> {
                // Just log and monitor
                success = true
                details["action"] = "monitor_only"
            }
        }
        
        return IncidentResponse(
            threatId = threat.id,
            action = action,
            success = success,
            startTime = startTime,
            endTime = System.currentTimeMillis(),
            details = details,
            automatic = true
        )
    }
    
    /**
     * Block specific traffic
     */
    private fun blockSpecificTraffic(threat: ThreatAlert) {
        // In a real implementation, you would use iptables or VPN service
        // to block specific IPs, domains, or ports
        
        val ipAddress = threat.metadata["remote_address"] as? String
        val domain = threat.metadata["domain"] as? String
        val port = threat.metadata["port"] as? Int
        
        if (ipAddress != null) {
            // Block IP address
            forensicLogger.logEvent(
                eventType = LogEventType.INCIDENT_RESPONSE,
                severity = Severity.INFO,
                metadata = mapOf(
                    "action" to "block_ip",
                    "ip_address" to ipAddress,
                    "threat_id" to threat.id
                ),
                riskScore = 0
            )
        }
        
        if (domain != null) {
            // Block domain
            forensicLogger.logEvent(
                eventType = LogEventType.INCIDENT_RESPONSE,
                severity = Severity.INFO,
                metadata = mapOf(
                    "action" to "block_domain",
                    "domain" to domain,
                    "threat_id" to threat.id
                ),
                riskScore = 0
            )
        }
        
        if (port != null) {
            // Block port
            forensicLogger.logEvent(
                eventType = LogEventType.INCIDENT_RESPONSE,
                severity = Severity.INFO,
                metadata = mapOf(
                    "action" to "block_port",
                    "port" to port.toString(),
                    "threat_id" to threat.id
                ),
                riskScore = 0
            )
        }
    }
    
    /**
     * Quarantine app
     */
    private fun quarantineApp(packageName: String) {
        // In a real implementation, you would use DevicePolicyManager
        // to suspend or disable the app
        
        forensicLogger.logEvent(
            eventType = LogEventType.INCIDENT_RESPONSE,
            severity = Severity.INFO,
            metadata = mapOf(
                "action" to "quarantine_app",
                "package_name" to packageName
            ),
            riskScore = 0
        )
    }
    
    /**
     * Manually trigger response
     */
    fun triggerManualResponse(action: ResponseAction, details: Map<String, Any> = emptyMap()) {
        _isResponding.value = true
        
        val startTime = System.currentTimeMillis()
        var success = false
        val responseDetails = mutableMapOf<String, Any>()
        
        when (action) {
            ResponseAction.DEAD_MANS_SWITCH -> {
                try {
                    deadMansSwitch.activate()
                    success = true
                    responseDetails["lockdown_mode"] = "full"
                } catch (e: Exception) {
                    responseDetails["error"] = e.message ?: "Unknown error"
                }
            }
            
            ResponseAction.FARADAY_MODE -> {
                try {
                    faradayMode.activate()
                    success = true
                    responseDetails["isolation_mode"] = "full"
                } catch (e: Exception) {
                    responseDetails["error"] = e.message ?: "Unknown error"
                }
            }
            
            else -> {
                responseDetails["error"] = "Manual response not implemented for this action"
            }
        }
        
        responseDetails.putAll(details)
        
        val response = IncidentResponse(
            threatId = "manual_${System.currentTimeMillis()}",
            action = action,
            success = success,
            startTime = startTime,
            endTime = System.currentTimeMillis(),
            details = responseDetails,
            automatic = false
        )
        
        // Update response history
        val history = _responseHistory.value.toMutableList()
        history.add(response)
        _responseHistory.value = history
        
        _isResponding.value = false
    }
    
    /**
     * Cancel active response
     */
    fun cancelResponse(threatId: String) {
        val currentResponses = _activeResponses.value.toMutableList()
        val response = currentResponses.find { it.threatId == threatId }
        
        if (response != null) {
            when (response.action) {
                ResponseAction.DEAD_MANS_SWITCH -> {
                    deadMansSwitch.deactivate()
                }
                ResponseAction.FARADAY_MODE -> {
                    faradayMode.deactivate()
                }
                ResponseAction.PARTIAL_LOCKDOWN -> {
                    deadMansSwitch.deactivate()
                }
                ResponseAction.FULL_LOCKDOWN -> {
                    deadMansSwitch.deactivate()
                    faradayMode.deactivate()
                }
                else -> {
                    // No action needed for other responses
                }
            }
            
            // Update response status
            val updatedResponse = response.copy(
                status = ResponseStatus.CANCELLED,
                endTime = System.currentTimeMillis()
            )
            
            currentResponses.remove(response)
            _activeResponses.value = currentResponses
            
            // Log cancellation
            forensicLogger.logEvent(
                eventType = LogEventType.INCIDENT_RESPONSE,
                severity = Severity.INFO,
                metadata = mapOf(
                    "action" to "response_cancelled",
                    "threat_id" to threatId,
                    "response_action" to response.action.name
                ),
                riskScore = 0
            )
        }
    }
    
    /**
     * Get active response for threat
     */
    fun getActiveResponse(threatId: String): ActiveResponse? {
        return _activeResponses.value.find { it.threatId == threatId }
    }
    
    /**
     * Get all active responses
     */
    fun getAllActiveResponses(): List<ActiveResponse> {
        return _activeResponses.value
    }
    
    /**
     * Get response history
     */
    fun getResponseHistory(): List<IncidentResponse> {
        return _responseHistory.value
    }
    
    /**
     * Clear response history
     */
    fun clearResponseHistory() {
        _responseHistory.value = emptyList()
    }
    
    /**
     * Get response statistics
     */
    fun getResponseStatistics(): ResponseStatistics {
        val history = _responseHistory.value
        
        val totalResponses = history.size
        val successfulResponses = history.count { it.success }
        val failedResponses = history.count { !it.success }
        val automaticResponses = history.count { it.automatic }
        val manualResponses = history.count { !it.automatic }
        
        val actionBreakdown = history.groupBy { it.action }
            .mapValues { it.value.size }
        
        return ResponseStatistics(
            totalResponses = totalResponses,
            successfulResponses = successfulResponses,
            failedResponses = failedResponses,
            automaticResponses = automaticResponses,
            manualResponses = manualResponses,
            actionBreakdown = actionBreakdown
        )
    }
}

// Data classes for incident response

data class ActiveResponse(
    val threatId: String,
    val action: ResponseAction,
    val startTime: Long,
    val status: ResponseStatus
) {
    val duration: Long
        get() = if (status == ResponseStatus.ACTIVE) {
            System.currentTimeMillis() - startTime
        } else {
            0
        }
}

data class IncidentResponse(
    val threatId: String,
    val action: ResponseAction,
    val success: Boolean,
    val startTime: Long,
    val endTime: Long,
    val details: Map<String, Any>,
    val automatic: Boolean
) {
    val duration: Long
        get() = endTime - startTime
}

data class ResponseStatistics(
    val totalResponses: Int,
    val successfulResponses: Int,
    val failedResponses: Int,
    val automaticResponses: Int,
    val manualResponses: Int,
    val actionBreakdown: Map<ResponseAction, Int>
)

enum class ResponseAction {
    DEAD_MANS_SWITCH,
    FARADAY_MODE,
    TRAFFIC_BLOCK,
    APP_QUARANTINE,
    PARTIAL_LOCKDOWN,
    FULL_LOCKDOWN,
    MONITOR_ONLY
}

enum class ResponseStatus {
    ACTIVE,
    COMPLETED,
    CANCELLED,
    FAILED
}
