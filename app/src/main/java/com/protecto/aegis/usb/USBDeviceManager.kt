package com.protecto.aegis.usb

import android.content.Context
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import com.protecto.aegis.core.ForensicLogger
import com.protecto.aegis.core.LogEventType
import com.protecto.aegis.core.Severity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * PROJECT AEGIS - USB Device Manager
 * 
 * Manages USB device enumeration, permission handling, and device classification.
 * Provides detailed device information for threat analysis.
 * 
 * Core Philosophy: DETECT → BLOCK → ISOLATE → RECORD → ANALYZE → ALERT → RECOVER
 */
class USBDeviceManager(
    private val context: Context,
    private val forensicLogger: ForensicLogger
) {
    
    private val usbManager = context.getSystemService(Context.USB_SERVICE) as UsbManager
    
    // Device classification database
    private val deviceDatabase = USBDeviceDatabase()
    
    /**
     * Get detailed device information
     */
    suspend fun getDeviceInfo(device: UsbDevice): USBDeviceInfo = withContext(Dispatchers.IO) {
        USBDeviceInfo(
            deviceId = device.deviceId,
            deviceName = device.deviceName,
            vendorId = device.vendorId,
            productId = device.productId,
            deviceClass = device.deviceClass,
            deviceSubclass = device.deviceSubclass,
            deviceProtocol = device.deviceProtocol,
            interfaceCount = device.interfaceCount,
            interfaces = getInterfaceInfo(device),
            vendorName = getVendorName(device.vendorId),
            productName = getProductName(device.vendorId, device.productId),
            classification = deviceDatabase.classifyDevice(device),
            hasPermission = usbManager.hasPermission(device)
        )
    }
    
    /**
     * Get interface information
     */
    private fun getInterfaceInfo(device: UsbDevice): List<USBInterfaceInfo> {
        val interfaces = mutableListOf<USBInterfaceInfo>()
        
        for (i in 0 until device.interfaceCount) {
            val usbInterface = device.getInterface(i)
            val endpointCount = usbInterface.endpointCount
            
            val endpoints = mutableListOf<USBEndpointInfo>()
            for (j in 0 until endpointCount) {
                val endpoint = usbInterface.getEndpoint(j)
                endpoints.add(
                    USBEndpointInfo(
                        address = endpoint.address,
                        number = endpoint.number,
                        direction = if (endpoint.direction == UsbConstants.USB_DIR_IN) "IN" else "OUT",
                        type = when (endpoint.type) {
                            UsbConstants.USB_ENDPOINT_XFER_BULK -> "BULK"
                            UsbConstants.USB_ENDPOINT_XFER_CONTROL -> "CONTROL"
                            UsbConstants.USB_ENDPOINT_XFER_INT -> "INTERRUPT"
                            UsbConstants.USB_ENDPOINT_XFER_ISOC -> "ISOCHRONOUS"
                            else -> "UNKNOWN"
                        },
                        maxPacketSize = endpoint.maxPacketSize,
                        interval = endpoint.interval
                    )
                )
            }
            
            interfaces.add(
                USBInterfaceInfo(
                    id = usbInterface.id,
                    interfaceClass = usbInterface.interfaceClass,
                    interfaceSubclass = usbInterface.interfaceSubclass,
                    interfaceProtocol = usbInterface.interfaceProtocol,
                    name = usbInterface.name,
                    endpointCount = endpointCount,
                    endpoints = endpoints,
                    className = getClassName(usbInterface.interfaceClass)
                )
            )
        }
        
        return interfaces
    }
    
    /**
     * Get vendor name from VID
     */
    private fun getVendorName(vendorId: Int): String {
        return deviceDatabase.getVendorName(vendorId) ?: "Unknown Vendor (0x${vendorId.toString(16)})"
    }
    
    /**
     * Get product name from VID/PID
     */
    private fun getProductName(vendorId: Int, productId: Int): String {
        return deviceDatabase.getProductName(vendorId, productId) ?: "Unknown Product (0x${productId.toString(16)})"
    }
    
    /**
     * Get class name from class code
     */
    private fun getClassName(classCode: Int): String {
        return when (classCode) {
            UsbConstants.USB_CLASS_PER_INTERFACE -> "Per Interface"
            UsbConstants.USB_CLASS_AUDIO -> "Audio"
            UsbConstants.USB_CLASS_COMM -> "Communications"
            UsbConstants.USB_CLASS_HID -> "Human Interface Device"
            UsbConstants.USB_CLASS_PHYSICAL -> "Physical"
            UsbConstants.USB_CLASS_STILL_IMAGE -> "Still Image"
            UsbConstants.USB_CLASS_PRINTER -> "Printer"
            UsbConstants.USB_CLASS_MASS_STORAGE -> "Mass Storage"
            UsbConstants.USB_CLASS_HUB -> "Hub"
            UsbConstants.USB_CLASS_CDC_DATA -> "CDC Data"
            UsbConstants.USB_CLASS_CSCID -> "Smart Card"
            UsbConstants.USB_CLASS_CONTENT_SEC -> "Content Security"
            UsbConstants.USB_CLASS_VIDEO -> "Video"
            UsbConstants.USB_CLASS_PERSONAL_HEALTHCARE -> "Personal Healthcare"
            UsbConstants.USB_CLASS_AUDIO_VIDEO -> "Audio/Video"
            UsbConstants.USB_CLASS_BILLBOARD -> "Billboard"
            UsbConstants.USB_CLASS_MIDI -> "MIDI"
            UsbConstants.USB_CLASS_VENDOR_SPEC -> "Vendor Specific"
            else -> "Unknown Class"
        }
    }
    
    /**
     * Request USB device permission
     */
    fun requestPermission(device: UsbDevice): Boolean {
        return try {
            usbManager.requestPermission(device, null)
            true
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Check if device has permission
     */
    fun hasPermission(device: UsbDevice): Boolean {
        return usbManager.hasPermission(device)
    }
    
    /**
     * Get all connected devices
     */
    fun getAllDevices(): Map<String, UsbDevice> {
        return usbManager.deviceList
    }
    
    /**
     * Get device by device ID
     */
    fun getDevice(deviceId: Int): UsbDevice? {
        return usbManager.deviceList.values.firstOrNull { it.deviceId == deviceId }
    }
    
    /**
     * Log device connection
     */
    suspend fun logDeviceConnection(device: UsbDevice, connected: Boolean) {
        val deviceInfo = getDeviceInfo(device)
        
        forensicLogger.logEvent(
            eventType = if (connected) LogEventType.USB_DEVICE_CONNECTED else LogEventType.USB_DEVICE_DISCONNECTED,
            severity = Severity.INFO,
            metadata = mapOf(
                "device_name" to deviceInfo.deviceName,
                "vendor_id" to deviceInfo.vendorId.toString(),
                "product_id" to deviceInfo.productId.toString(),
                "vendor_name" to deviceInfo.vendorName,
                "product_name" to deviceInfo.productName,
                "device_class" to deviceInfo.deviceClass.toString(),
                "interface_count" to deviceInfo.interfaceCount.toString(),
                "classification" to deviceInfo.classification.name,
                "has_permission" to deviceInfo.hasPermission.toString()
            ),
            riskScore = 0
        )
    }
    
    /**
     * Check if device is potentially dangerous
     */
    fun isPotentiallyDangerous(device: UsbDevice): Boolean {
        val classification = deviceDatabase.classifyDevice(device)
        
        return when (classification) {
            USBDeviceClassification.UNKNOWN -> true
            USBDeviceClassification.KEYBOARD -> false // Usually safe
            USBDeviceClassification.MOUSE -> false // Usually safe
            USBDeviceClassification.STORAGE -> true // Could be malicious
            USBDeviceClassification.NETWORK -> true // Could be malicious
            USBDeviceClassification.COMPOSITE -> true // Could be malicious
            USBDeviceClassification.HUB -> false // Usually safe
            USBDeviceClassification.AUDIO -> false // Usually safe
            USBDeviceClassification.VIDEO -> false // Usually safe
            USBDeviceClassification.VENDOR_SPECIFIC -> true // Unknown vendor devices
        }
    }
}

// Data classes for USB device information

data class USBDeviceInfo(
    val deviceId: Int,
    val deviceName: String,
    val vendorId: Int,
    val productId: Int,
    val deviceClass: Int,
    val deviceSubclass: Int,
    val deviceProtocol: Int,
    val interfaceCount: Int,
    val interfaces: List<USBInterfaceInfo>,
    val vendorName: String,
    val productName: String,
    val classification: USBDeviceClassification,
    val hasPermission: Boolean
)

data class USBInterfaceInfo(
    val id: Int,
    val interfaceClass: Int,
    val interfaceSubclass: Int,
    val interfaceProtocol: Int,
    val name: String?,
    val endpointCount: Int,
    val endpoints: List<USBEndpointInfo>,
    val className: String
)

data class USBEndpointInfo(
    val address: Int,
    val number: Int,
    val direction: String,
    val type: String,
    val maxPacketSize: Int,
    val interval: Int
)

enum class USBDeviceClassification {
    UNKNOWN,
    KEYBOARD,
    MOUSE,
    STORAGE,
    NETWORK,
    COMPOSITE,
    HUB,
    AUDIO,
    VIDEO,
    VENDOR_SPECIFIC
}

// USB Constants
object UsbConstants {
    const val USB_DIR_IN = 0x80
    const val USB_DIR_OUT = 0x00
    
    const val USB_ENDPOINT_XFER_CONTROL = 0
    const val USB_ENDPOINT_XFER_ISOC = 1
    const val USB_ENDPOINT_XFER_BULK = 2
    const val USB_ENDPOINT_XFER_INT = 3
    
    const val USB_CLASS_PER_INTERFACE = 0x00
    const val USB_CLASS_AUDIO = 0x01
    const val USB_CLASS_COMM = 0x02
    const val USB_CLASS_HID = 0x03
    const val USB_CLASS_PHYSICAL = 0x05
    const val USB_CLASS_STILL_IMAGE = 0x06
    const val USB_CLASS_PRINTER = 0x07
    const val USB_CLASS_MASS_STORAGE = 0x08
    const val USB_CLASS_HUB = 0x09
    const val USB_CLASS_CDC_DATA = 0x0A
    const val USB_CLASS_CSCID = 0x0B
    const val USB_CLASS_CONTENT_SEC = 0x0D
    const val USB_CLASS_VIDEO = 0x0E
    const val USB_CLASS_PERSONAL_HEALTHCARE = 0x0F
    const val USB_CLASS_AUDIO_VIDEO = 0x10
    const val USB_CLASS_BILLBOARD = 0x11
    const val USB_CLASS_MIDI = 0x12
    const val USB_CLASS_VENDOR_SPEC = 0xFF
}

/**
 * USB Device Database
 * Contains known device classifications and vendor/product mappings
 */
class USBDeviceDatabase {
    
    // Known vendor IDs and names
    private val vendorDatabase = mapOf(
        0x046D to "Logitech",
        0x04B4 to "Cypress Semiconductor",
        0x05AC to "Apple",
        0x045E to "Microsoft",
        0x0483 to "STMicroelectronics",
        0x0FCF to "Dimon",
        0x2341 to "Arduino",
        0x16C0 to "Van Ooijen Technische Informatica",
        0x0951 to "Kingston",
        0x0781 to "SanDisk",
        0x0EA0 to "Ours Technology",
        0x14CD to "Super Top",
        0x1234 to "Unknown Vendor"
    )
    
    // Known device classifications
    private val deviceClassifications = mapOf(
        // HID devices
        Pair(0x03, 0x01) to USBDeviceClassification.KEYBOARD,
        Pair(0x03, 0x02) to USBDeviceClassification.MOUSE,
        
        // Mass storage
        Pair(0x08, 0x06) to USBDeviceClassification.STORAGE,
        
        // Network
        Pair(0x0A, 0x00) to USBDeviceClassification.NETWORK,
        
        // Audio
        Pair(0x01, 0x01) to USBDeviceClassification.AUDIO,
        
        // Video
        Pair(0x0E, 0x01) to USBDeviceClassification.VIDEO
    )
    
    fun getVendorName(vendorId: Int): String? {
        return vendorDatabase[vendorId]
    }
    
    fun getProductName(vendorId: Int, productId: Int): String? {
        // In a real implementation, this would query a comprehensive database
        // For now, return null for unknown products
        return null
    }
    
    fun classifyDevice(device: android.hardware.usb.UsbDevice): USBDeviceClassification {
        // Check device class first
        when (device.deviceClass) {
            0x03 -> {
                // HID - check subclass
                return when (device.deviceSubclass) {
                    0x01 -> USBDeviceClassification.KEYBOARD
                    0x02 -> USBDeviceClassification.MOUSE
                    else -> USBDeviceClassification.HID
                }
            }
            0x08 -> return USBDeviceClassification.STORAGE
            0x09 -> return USBDeviceClassification.HUB
            0x0A -> return USBDeviceClassification.NETWORK
            0x01 -> return USBDeviceClassification.AUDIO
            0x0E -> return USBDeviceClassification.VIDEO
            0x00 -> {
                // Class defined at interface level - check interfaces
                if (device.interfaceCount > 1) {
                    return USBDeviceClassification.COMPOSITE
                }
                
                // Check first interface
                val firstInterface = device.getInterface(0)
                return when (firstInterface.interfaceClass) {
                    0x03 -> USBDeviceClassification.HID
                    0x08 -> USBDeviceClassification.STORAGE
                    0x09 -> USBDeviceClassification.HUB
                    0x0A -> USBDeviceClassification.NETWORK
                    0x01 -> USBDeviceClassification.AUDIO
                    0x0E -> USBDeviceClassification.VIDEO
                    0xFF -> USBDeviceClassification.VENDOR_SPECIFIC
                    else -> USBDeviceClassification.UNKNOWN
                }
            }
            0xFF -> return USBDeviceClassification.VENDOR_SPECIFIC
            else -> return USBDeviceClassification.UNKNOWN
        }
    }
}
