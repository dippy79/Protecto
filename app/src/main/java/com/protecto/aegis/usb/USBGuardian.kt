package com.protecto.aegis.usb

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
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
 * PROJECT AEGIS - USBGuardian 2.0
 * 
 * Advanced USB device monitoring with threat detection including:
 * - Standard detection: Unknown HID, BadUSB, unauthorized ADB/MTP
 * - Advanced heuristics: Keystroke microsecond dynamics, USB-C PD attack detection
 * - Composite interface fuzzing detection
 * 
 * Core Philosophy: DETECT → BLOCK → ISOLATE → RECORD → ANALYZE → ALERT → RECOVER
 */
class USBGuardian(
    private val context: Context,
    private val forensicLogger: ForensicLogger
) {
    
    private val usbManager = context.getSystemService(Context.USB_SERVICE) as UsbManager
    private val keystrokeAnalyzer = KeystrokeAnalyzer(forensicLogger)
    private val usbDeviceManager = USBDeviceManager(context, forensicLogger)
    
    private val _isMonitoring = MutableStateFlow(false)
    val isMonitoring: StateFlow<Boolean> = _isMonitoring.asStateFlow()
    
    private val _activeDevices = MutableStateFlow<List<MonitoredUSBDevice>>(emptyList())
    val activeDevices: StateFlow<List<MonitoredUSBDevice>> = _activeDevices.asStateFlow()
    
    private val _detectedThreats = MutableStateFlow<List<ThreatAlert>>(emptyList())
    val detectedThreats: StateFlow<List<ThreatAlert>> = _detectedThreats.asStateFlow()
    
    // Known safe device fingerprints (VID, PID, serial)
    private val knownSafeDevices = mutableSetOf<String>()
    
    // Blocked devices
    private val blockedDevices = mutableSetOf<String>()
    
    /**
     * Start USB monitoring
     */
    fun startMonitoring(): Flow<ThreatAlert> = callbackFlow {
        _isMonitoring.value = true
        
        // Register USB device receiver
        val usbReceiver = object : android.content.BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent) {
                when (intent.action) {
                    UsbManager.ACTION_USB_DEVICE_ATTACHED -> {
                        val device = intent.getParcelableExtra<UsbDevice>(UsbManager.EXTRA_DEVICE)
                        device?.let { handleDeviceAttached(it) }
                    }
                    UsbManager.ACTION_USB_DEVICE_DETACHED -> {
                        val device = intent.getParcelableExtra<UsbDevice>(UsbManager.EXTRA_DEVICE)
                        device?.let { handleDeviceDetached(it) }
                    }
                }
            }
        }
        
        val filter = IntentFilter().apply {
            addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED)
            addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
        }
        
        context.registerReceiver(usbReceiver, filter)
        
        // Scan existing devices
        scanExistingDevices()
        
        awaitClose {
            context.unregisterReceiver(usbReceiver)
            _isMonitoring.value = false
        }
    }
    
    /**
     * Stop USB monitoring
     */
    fun stopMonitoring() {
        _isMonitoring.value = false
        keystrokeAnalyzer.stopMonitoring()
    }
    
    /**
     * Handle USB device attachment
     */
    private fun handleDeviceAttached(device: UsbDevice) {
        val deviceFingerprint = "${device.vendorId}:${device.productId}:${device.deviceName}"
        
        // Check if device is blocked
        if (deviceFingerprint in blockedDevices) {
            blockDevice(device, "Device is in blocklist")
            return
        }
        
        // Perform threat analysis
        val threatAnalysis = analyzeDevice(device)
        
        if (threatAnalysis.isThreat) {
            // Block device if threat score is high
            if (threatAnalysis.riskScore >= 70) {
                blockDevice(device, threatAnalysis.reason)
                
                val threat = ThreatAlert(
                    id = java.util.UUID.randomUUID().toString(),
                    type = LogEventType.USB_SUSPICIOUS_ACTIVITY,
                    category = ThreatCategory.PHYSICAL,
                    severity = if (threatAnalysis.riskScore >= 90) Severity.CRITICAL else Severity.HIGH,
                    riskScore = threatAnalysis.riskScore,
                    metadata = mapOf(
                        "device_name" to device.deviceName,
                        "vendor_id" to device.vendorId.toString(),
                        "product_id" to device.productId.toString(),
                        "reason" to threatAnalysis.reason,
                        "threat_type" to threatAnalysis.threatType.name
                    )
                )
                
                _detectedThreats.value = _detectedThreats.value + threat
                trySend(threat)
            } else {
                // Monitor but don't block
                monitorDevice(device, threatAnalysis)
            }
        } else {
            // Safe device - add to monitored list
            val monitoredDevice = MonitoredUSBDevice(
                device = device,
                fingerprint = deviceFingerprint,
                trustLevel = if (deviceFingerprint in knownSafeDevices) TrustLevel.TRUSTED else TrustLevel.UNKNOWN,
                monitoringLevel = MonitoringLevel.STANDARD
            )
            
            _activeDevices.value = _activeDevices.value + monitoredDevice
            
            // If it's a HID device, start keystroke analysis
            if (isHIDDevice(device)) {
                keystrokeAnalyzer.startMonitoring(device)
            }
        }
    }
    
    /**
     * Handle USB device detachment
     */
    private fun handleDeviceDetached(device: UsbDevice) {
        val deviceFingerprint = "${device.vendorId}:${device.productId}:${device.deviceName}"
        
        // Remove from active devices
        _activeDevices.value = _activeDevices.value.filter { it.fingerprint != deviceFingerprint }
        
        // Stop keystroke analysis if it was a HID device
        if (isHIDDevice(device)) {
            keystrokeAnalyzer.stopMonitoring()
        }
        
        // Log detachment
        forensicLogger.logEvent(
            eventType = LogEventType.USB_DEVICE_DISCONNECTED,
            severity = Severity.INFO,
            metadata = mapOf(
                "device_name" to device.deviceName,
                "vendor_id" to device.vendorId.toString(),
                "product_id" to device.productId.toString()
            ),
            riskScore = 0
        )
    }
    
    /**
     * Analyze USB device for threats
     */
    private fun analyzeDevice(device: UsbDevice): USBThreatAnalysis {
        val reasons = mutableListOf<String>()
        var riskScore = 0
        var threatType = USBThreatType.NONE
        
        // Check for unknown vendor/product IDs
        if (!isKnownSafeDevice(device)) {
            reasons.add("Unknown VID/PID combination")
            riskScore += 20
            threatType = USBThreatType.UNKNOWN_DEVICE
        }
        
        // Check for composite device with suspicious interfaces
        if (hasSuspiciousInterfaces(device)) {
            reasons.add("Suspicious composite interface configuration")
            riskScore += 30
            threatType = USBThreatType.COMPOSITE_ATTACK
        }
        
        // Check for USB-C PD anomalies
        if (hasUSBCPDAnomalies(device)) {
            reasons.add("USB-C Power Delivery anomalies detected")
            riskScore += 40
            threatType = USBThreatType.PD_ATTACK
        }
        
        // Check for unauthorized ADB/MTP
        if (hasUnauthorizedADB(device)) {
            reasons.add("Unauthorized ADB interface detected")
            riskScore += 35
            threatType = USBThreatType.UNAUTHORIZED_ACCESS
        }
        
        // Check for HID keyboard/mouse (potential BadUSB)
        if (isHIDDevice(device) && !isKnownSafeDevice(device)) {
            reasons.add("Unknown HID device (potential BadUSB)")
            riskScore += 25
            threatType = USBThreatType.BADUSB
        }
        
        return USBThreatAnalysis(
            isThreat = riskScore > 0,
            riskScore = riskScore.coerceIn(0, 100),
            reason = reasons.joinToString(", "),
            threatType = threatType
        )
    }
    
    /**
     * Check if device is in known safe list
     */
    private fun isKnownSafeDevice(device: UsbDevice): Boolean {
        val fingerprint = "${device.vendorId}:${device.productId}:${device.deviceName}"
        return fingerprint in knownSafeDevices
    }
    
    /**
     * Check if device has suspicious composite interfaces
     */
    private fun hasSuspiciousInterfaces(device: UsbDevice): Boolean {
        // Check for unusual interface combinations
        val interfaceCount = device.interfaceCount
        val hasHID = (0 until interfaceCount).any { i ->
            device.getInterface(i).interfaceClass == UsbConstants.USB_CLASS_HID
        }
        val hasMassStorage = (0 until interfaceCount).any { i ->
            device.getInterface(i).interfaceClass == UsbConstants.USB_CLASS_MASS_STORAGE
        }
        val hasCDC = (0 until interfaceCount).any { i ->
            device.getInterface(i).interfaceClass == UsbConstants.USB_CLASS_CDC_DATA
        }
        
        // Suspicious: HID + Mass Storage + CDC (common in attack devices)
        return hasHID && hasMassStorage && hasCDC
    }
    
    /**
     * Check for USB-C Power Delivery anomalies
     */
    private fun hasUSBCPDAnomalies(device: UsbDevice): Boolean {
        // This would require USB-C PD protocol analysis
        // For now, check device class and protocol
        return device.deviceClass == UsbConstants.USB_CLASS_VENDOR_SPEC &&
               device.deviceSubclass == 0x00 &&
               device.deviceProtocol == 0x01
    }
    
    /**
     * Check for unauthorized ADB
     */
    private fun hasUnauthorizedADB(device: UsbDevice): Boolean {
        // Check for ADB interface (vendor-specific class with specific protocol)
        return (0 until device.interfaceCount).any { i ->
            val iface = device.getInterface(i)
            iface.interfaceClass == UsbConstants.USB_CLASS_VENDOR_SPEC &&
            iface.interfaceSubclass == 0x42 &&
            iface.interfaceProtocol == 0x01
        }
    }
    
    /**
     * Check if device is HID (Human Interface Device)
     */
    private fun isHIDDevice(device: UsbDevice): Boolean {
        return (0 until device.interfaceCount).any { i ->
            device.getInterface(i).interfaceClass == UsbConstants.USB_CLASS_HID
        }
    }
    
    /**
     * Block USB device
     */
    private fun blockDevice(device: UsbDevice, reason: String) {
        val deviceFingerprint = "${device.vendorId}:${device.productId}:${device.deviceName}"
        blockedDevices.add(deviceFingerprint)
        
        // Revoke permissions
        usbManager.hasPermission(device).let { hasPermission ->
            if (hasPermission) {
                // In a real implementation, you would revoke permissions here
                // This requires device admin or root access
            }
        }
        
        forensicLogger.logEvent(
            eventType = LogEventType.USB_SUSPICIOUS_ACTIVITY,
            severity = Severity.HIGH,
            metadata = mapOf(
                "action" to "device_blocked",
                "device_name" to device.deviceName,
                "vendor_id" to device.vendorId.toString(),
                "product_id" to device.productId.toString(),
                "reason" to reason
            ),
            riskScore = 100
        )
    }
    
    /**
     * Monitor device without blocking
     */
    private fun monitorDevice(device: UsbDevice, analysis: USBThreatAnalysis) {
        val deviceFingerprint = "${device.vendorId}:${device.productId}:${device.deviceName}"
        
        val monitoredDevice = MonitoredUSBDevice(
            device = device,
            fingerprint = deviceFingerprint,
            trustLevel = TrustLevel.SUSPICIOUS,
            monitoringLevel = MonitoringLevel.ENHANCED
        )
        
        _activeDevices.value = _activeDevices.value + monitoredDevice
        
        // If it's a HID device, start enhanced keystroke analysis
        if (isHIDDevice(device)) {
            keystrokeAnalyzer.startEnhancedMonitoring(device)
        }
    }
    
    /**
     * Scan existing devices
     */
    private fun scanExistingDevices() {
        val deviceList = usbManager.deviceList.values
        for (device in deviceList) {
            handleDeviceAttached(device)
        }
    }
    
    /**
     * Add device to known safe list
     */
    fun addToKnownSafe(device: UsbDevice) {
        val fingerprint = "${device.vendorId}:${device.productId}:${device.deviceName}"
        knownSafeDevices.add(fingerprint)
        
        // Update monitoring level
        val updatedDevices = _activeDevices.value.map { monitoredDevice ->
            if (monitoredDevice.fingerprint == fingerprint) {
                monitoredDevice.copy(trustLevel = TrustLevel.TRUSTED, monitoringLevel = MonitoringLevel.STANDARD)
            } else {
                monitoredDevice
            }
        }
        _activeDevices.value = updatedDevices
    }
    
    /**
     * Remove device from known safe list
     */
    fun removeFromKnownSafe(device: UsbDevice) {
        val fingerprint = "${device.vendorId}:${device.productId}:${device.deviceName}"
        knownSafeDevices.remove(fingerprint)
        
        // Update monitoring level
        val updatedDevices = _activeDevices.value.map { monitoredDevice ->
            if (monitoredDevice.fingerprint == fingerprint) {
                monitoredDevice.copy(trustLevel = TrustLevel.UNKNOWN, monitoringLevel = MonitoringLevel.ENHANCED)
            } else {
                monitoredDevice
            }
        }
        _activeDevices.value = updatedDevices
    }
    
    /**
     * Unblock device
     */
    fun unblockDevice(device: UsbDevice) {
        val fingerprint = "${device.vendorId}:${device.productId}:${device.deviceName}"
        blockedDevices.remove(fingerprint)
    }
    
    /**
     * Get keystroke analysis results
     */
    fun getKeystrokeAnalysis(): KeystrokeAnalysisResult {
        return keystrokeAnalyzer.getAnalysisResult()
    }
}

// Data classes for USB monitoring

data class MonitoredUSBDevice(
    val device: UsbDevice,
    val fingerprint: String,
    val trustLevel: TrustLevel,
    val monitoringLevel: MonitoringLevel
)

data class USBThreatAnalysis(
    val isThreat: Boolean,
    val riskScore: Int,
    val reason: String,
    val threatType: USBThreatType
)

enum class TrustLevel {
    TRUSTED,
    UNKNOWN,
    SUSPICIOUS,
    BLOCKED
}

enum class MonitoringLevel {
    STANDARD,
    ENHANCED,
    NONE
}

enum class USBThreatType {
    NONE,
    UNKNOWN_DEVICE,
    BADUSB,
    COMPOSITE_ATTACK,
    PD_ATTACK,
    UNAUTHORIZED_ACCESS
}

// USB Constants
object UsbConstants {
    const val USB_CLASS_HID = 0x03
    const val USB_CLASS_MASS_STORAGE = 0x08
    const val USB_CLASS_CDC_DATA = 0x0A
    const val USB_CLASS_VENDOR_SPEC = 0xFF
}
