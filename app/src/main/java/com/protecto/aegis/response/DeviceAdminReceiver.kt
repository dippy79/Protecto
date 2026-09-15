package com.protecto.aegis.response

import android.app.admin.DeviceAdminReceiver
import android.content.Context
import android.content.Intent
import com.protecto.aegis.core.ForensicLogger
import com.protecto.aegis.core.LogEventType
import com.protecto.aegis.core.Severity

/**
 * PROJECT AEGIS - Device Admin Receiver
 * 
 * Handles device admin events for incident response capabilities.
 * Enables advanced security controls when device admin permissions are granted.
 * 
 * Core Philosophy: DETECT → BLOCK → ISOLATE → RECORD → ANALYZE → ALERT → RECOVER
 */
class DeviceAdminReceiver : DeviceAdminReceiver() {
    
    override fun onEnabled(context: Context, intent: Intent) {
        super.onEnabled(context, intent)
        
        // Log device admin enabled
        try {
            val forensicLogger = ForensicLogger(context)
            forensicLogger.logEvent(
                eventType = LogEventType.INCIDENT_RESPONSE,
                severity = Severity.INFO,
                metadata = mapOf(
                    "action" to "device_admin_enabled",
                    "timestamp" to System.currentTimeMillis().toString()
                ),
                riskScore = 0
            )
        } catch (e: Exception) {
            // Forensic logger might not be available yet
        }
    }
    
    override fun onDisabled(context: Context, intent: Intent) {
        super.onDisabled(context, intent)
        
        // Log device admin disabled
        try {
            val forensicLogger = ForensicLogger(context)
            forensicLogger.logEvent(
                eventType = LogEventType.INCIDENT_RESPONSE,
                severity = Severity.WARNING,
                metadata = mapOf(
                    "action" to "device_admin_disabled",
                    "timestamp" to System.currentTimeMillis().toString()
                ),
                riskScore = 30
            )
        } catch (e: Exception) {
            // Forensic logger might not be available
        }
    }
    
    override fun onPasswordChanged(context: Context, intent: Intent) {
        super.onPasswordChanged(context, intent)
        
        // Log password change (potential security event)
        try {
            val forensicLogger = ForensicLogger(context)
            forensicLogger.logEvent(
                eventType = LogEventType.INCIDENT_RESPONSE,
                severity = Severity.INFO,
                metadata = mapOf(
                    "action" to "password_changed",
                    "timestamp" to System.currentTimeMillis().toString()
                ),
                riskScore = 10
            )
        } catch (e: Exception) {
            // Ignore errors
        }
    }
    
    override fun onPasswordFailed(context: Context, intent: Intent) {
        super.onPasswordFailed(context, intent)
        
        // Log failed password attempt (potential attack)
        try {
            val forensicLogger = ForensicLogger(context)
            forensicLogger.logEvent(
                eventType = LogEventType.INCIDENT_RESPONSE,
                severity = Severity.WARNING,
                metadata = mapOf(
                    "action" to "password_failed",
                    "timestamp" to System.currentTimeMillis().toString()
                ),
                riskScore = 40
            )
        } catch (e: Exception) {
            // Ignore errors
        }
    }
    
    override fun onPasswordSucceeded(context: Context, intent: Intent) {
        super.onPasswordSucceeded(context, intent)
        
        // Log successful password attempt
        try {
            val forensicLogger = ForensicLogger(context)
            forensicLogger.logEvent(
                eventType = LogEventType.INCIDENT_RESPONSE,
                severity = Severity.INFO,
                metadata = mapOf(
                    "action" to "password_succeeded",
                    "timestamp" to System.currentTimeMillis().toString()
                ),
                riskScore = 0
            )
        } catch (e: Exception) {
            // Ignore errors
        }
    }
    
    override fun onLockTaskModeEntering(context: Context, intent: Intent, pkg: String?) {
        super.onLockTaskModeEntering(context, intent, pkg)
        
        // Log lock task mode entering (app pinning)
        try {
            val forensicLogger = ForensicLogger(context)
            forensicLogger.logEvent(
                eventType = LogEventType.INCIDENT_RESPONSE,
                severity = Severity.INFO,
                metadata = mapOf(
                    "action" to "lock_task_mode_entering",
                    "package" to (pkg ?: "unknown"),
                    "timestamp" to System.currentTimeMillis().toString()
                ),
                riskScore = 0
            )
        } catch (e: Exception) {
            // Ignore errors
        }
    }
    
    override fun onLockTaskModeExiting(context: Context, intent: Intent) {
        super.onLockTaskModeExiting(context, intent)
        
        // Log lock task mode exiting
        try {
            val forensicLogger = ForensicLogger(context)
            forensicLogger.logEvent(
                eventType = LogEventType.INCIDENT_RESPONSE,
                severity = Severity.INFO,
                metadata = mapOf(
                    "action" to "lock_task_mode_exiting",
                    "timestamp" to System.currentTimeMillis().toString()
                ),
                riskScore = 0
            )
        } catch (e: Exception) {
            // Ignore errors
        }
    }
}
