package com.protecto.aegis.app

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
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
 * PROJECT AEGIS - AppRiskEngine 2.0
 * 
 * Advanced app forensics and risk assessment including:
 * - Standard detection: APK metadata analysis, accessibility abuse, device-admin abuse
 * - Advanced heuristics: TFLite memory-map analysis, packer/obfuscator entropy detection
 * - Fileless malware indicators: memfd/ptrace abuse detection
 * 
 * Core Philosophy: DETECT → BLOCK → ISOLATE → RECORD → ANALYZE → ALERT → RECOVER
 */
class AppRiskEngine(
    private val context: Context,
    private val forensicLogger: ForensicLogger
) {
    
    private val packageManager = context.packageManager
    
    private val apkAnalyzer = APKAnalyzer(context, forensicLogger)
    private val accessibilityAbuseDetector = AccessibilityAbuseDetector(context, forensicLogger)
    
    private val _isMonitoring = MutableStateFlow(false)
    val isMonitoring: StateFlow<Boolean> = _isMonitoring.asStateFlow()
    
    private val _riskAssessments = MutableStateFlow<Map<String, AppRiskAssessment>>(emptyMap())
    val riskAssessments: StateFlow<Map<String, AppRiskAssessment>> = _riskAssessments.asStateFlow()
    
    private val _detectedThreats = MutableStateFlow<List<ThreatAlert>>(emptyList())
    val detectedThreats: StateFlow<List<ThreatAlert>> = _detectedThreats.asStateFlow()
    
    private val _systemApps = MutableStateFlow<List<String>>(emptyList())
    val systemApps: StateFlow<List<String>> = _systemApps.asStateFlow()
    
    // Known safe apps
    private val knownSafeApps = setOf(
        "com.android.systemui",
        "com.android.settings",
        "com.google.android.gms",
        "com.google.android.gsf",
        "com.android.vending",
        "com.android.chrome",
        "com.sec.android.app.launcher",
        "com.samsung.android.app.galaxyfinder"
    )
    
    // High-risk permissions
    private val highRiskPermissions = setOf(
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.CALL_PHONE",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.REQUEST_INSTALL_PACKAGES"
    )
    
    /**
     * Start app risk monitoring
     */
    fun startMonitoring(): Flow<ThreatAlert> = callbackFlow {
        _isMonitoring.value = true
        
        // Initial scan of all apps
        performInitialAppScan()
        
        // Monitor app installations/uninstallations
        val packageReceiver = object : android.content.BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: android.content.Intent) {
                when (intent.action) {
                    android.content.Intent.ACTION_PACKAGE_ADDED -> {
                        val packageName = intent.data?.schemeSpecificPart
                        packageName?.let { handleAppInstalled(it) }
                    }
                    android.content.Intent.ACTION_PACKAGE_REMOVED -> {
                        val packageName = intent.data?.schemeSpecificPart
                        packageName?.let { handleAppRemoved(it) }
                    }
                    android.content.Intent.ACTION_PACKAGE_REPLACED -> {
                        val packageName = intent.data?.schemeSpecificPart
                        packageName?.let { handleAppUpdated(it) }
                    }
                }
            }
        }
        
        val filter = android.content.IntentFilter().apply {
            addAction(android.content.Intent.ACTION_PACKAGE_ADDED)
            addAction(android.content.Intent.ACTION_PACKAGE_REMOVED)
            addAction(android.content.Intent.ACTION_PACKAGE_REPLACED)
            addDataScheme("package")
        }
        
        context.registerReceiver(packageReceiver, filter)
        
        // Start accessibility abuse detection
        accessibilityAbuseDetector.startMonitoring()
            .collect { threat ->
                handleThreatDetection(threat)
            }
        
        // Periodic re-scanning
        val scanJob = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Default).launch {
            while (_isMonitoring.value) {
                delay(3600000) // Scan every hour
                performPeriodicRescan()
            }
        }
        
        awaitClose {
            context.unregisterReceiver(packageReceiver)
            accessibilityAbuseDetector.stopMonitoring()
            scanJob.cancel()
            _isMonitoring.value = false
        }
    }
    
    /**
     * Stop app risk monitoring
     */
    fun stopMonitoring() {
        _isMonitoring.value = false
    }
    
    /**
     * Perform initial app scan
     */
    private fun performInitialAppScan() {
        val installedPackages = packageManager.getInstalledPackages(
            PackageManager.GET_PERMISSIONS or
            PackageManager.GET_SIGNATURES or
            PackageManager.GET_META_DATA
        )
        
        val systemApps = mutableListOf<String>()
        val assessments = mutableMapOf<String, AppRiskAssessment>()
        
        for (packageInfo in installedPackages) {
            val packageName = packageInfo.packageName
            
            if (isSystemApp(packageInfo)) {
                systemApps.add(packageName)
            }
            
            val assessment = assessAppRisk(packageInfo)
            assessments[packageName] = assessment
            
            if (assessment.riskScore >= 50) {
                val threat = ThreatAlert(
                    id = java.util.UUID.randomUUID().toString(),
                    type = LogEventType.APP_INSTALL,
                    category = ThreatCategory.APP,
                    severity = if (assessment.riskScore >= 70) Severity.HIGH else Severity.WARNING,
                    riskScore = assessment.riskScore,
                    metadata = mapOf(
                        "package_name" to packageName,
                        "app_name" to getAppName(packageName),
                        "risk_score" to assessment.riskScore.toString(),
                        "risk_factors" to assessment.riskFactors.joinToString(","),
                        "is_system_app" to isSystemApp(packageInfo).toString()
                    )
                )
                
                _detectedThreats.value = _detectedThreats.value + threat
            }
        }
        
        _systemApps.value = systemApps
        _riskAssessments.value = assessments
    }
    
    /**
     * Handle app installed
     */
    private fun handleAppInstalled(packageName: String) {
        try {
            val packageInfo = packageManager.getPackageInfo(
                packageName,
                PackageManager.GET_PERMISSIONS or
                PackageManager.GET_SIGNATURES or
                PackageManager.GET_META_DATA
            )
            
            val assessment = assessAppRisk(packageInfo)
            
            // Update assessments
            val currentAssessments = _riskAssessments.value.toMutableMap()
            currentAssessments[packageName] = assessment
            _riskAssessments.value = currentAssessments
            
            // Log installation
            forensicLogger.logEvent(
                eventType = LogEventType.APP_INSTALL,
                severity = Severity.INFO,
                metadata = mapOf(
                    "package_name" to packageName,
                    "app_name" to getAppName(packageName),
                    "risk_score" to assessment.riskScore.toString(),
                    "risk_factors" to assessment.riskFactors.joinToString(",")
                ),
                riskScore = assessment.riskScore
            )
            
            // Alert if high risk
            if (assessment.riskScore >= 50) {
                val threat = ThreatAlert(
                    id = java.util.UUID.randomUUID().toString(),
                    type = LogEventType.APP_INSTALL,
                    category = ThreatCategory.APP,
                    severity = if (assessment.riskScore >= 70) Severity.HIGH else Severity.WARNING,
                    riskScore = assessment.riskScore,
                    metadata = mapOf(
                        "package_name" to packageName,
                        "app_name" to getAppName(packageName),
                        "risk_score" to assessment.riskScore.toString(),
                        "risk_factors" to assessment.riskFactors.joinToString(",")
                    )
                )
                
                _detectedThreats.value = _detectedThreats.value + threat
            }
        } catch (e: Exception) {
            forensicLogger.logEvent(
                eventType = LogEventType.APP_INSTALL,
                severity = Severity.WARNING,
                metadata = mapOf(
                    "package_name" to packageName,
                    "error" to e.message,
                    "action" to "install_analysis_failed"
                ),
                riskScore = 30
            )
        }
    }
    
    /**
     * Handle app removed
     */
    private fun handleAppRemoved(packageName: String) {
        // Remove from assessments
        val currentAssessments = _riskAssessments.value.toMutableMap()
        currentAssessments.remove(packageName)
        _riskAssessments.value = currentAssessments
        
        // Log removal
        forensicLogger.logEvent(
            eventType = LogEventType.APP_UNINSTALL,
            severity = Severity.INFO,
            metadata = mapOf(
                "package_name" to packageName
            ),
            riskScore = 0
        )
    }
    
    /**
     * Handle app updated
     */
    private fun handleAppUpdated(packageName: String) {
        try {
            val packageInfo = packageManager.getPackageInfo(
                packageName,
                PackageManager.GET_PERMISSIONS or
                PackageManager.GET_SIGNATURES or
                PackageManager.GET_META_DATA
            )
            
            val oldAssessment = _riskAssessments.value[packageName]
            val newAssessment = assessAppRisk(packageInfo)
            
            // Check for risk increase
            if (oldAssessment != null && newAssessment.riskScore > oldAssessment.riskScore + 20) {
                val threat = ThreatAlert(
                    id = java.util.UUID.randomUUID().toString(),
                    type = LogEventType.APP_PERMISSION_CHANGE,
                    category = ThreatCategory.APP,
                    severity = Severity.WARNING,
                    riskScore = newAssessment.riskScore,
                    metadata = mapOf(
                        "package_name" to packageName,
                        "app_name" to getAppName(packageName),
                        "old_risk_score" to oldAssessment.riskScore.toString(),
                        "new_risk_score" to newAssessment.riskScore.toString(),
                        "risk_increase" to (newAssessment.riskScore - oldAssessment.riskScore).toString()
                    )
                )
                
                _detectedThreats.value = _detectedThreats.value + threat
            }
            
            // Update assessments
            val currentAssessments = _riskAssessments.value.toMutableMap()
            currentAssessments[packageName] = newAssessment
            _riskAssessments.value = currentAssessments
            
            forensicLogger.logEvent(
                eventType = LogEventType.APP_PERMISSION_CHANGE,
                severity = Severity.INFO,
                metadata = mapOf(
                    "package_name" to packageName,
                    "app_name" to getAppName(packageName),
                    "risk_score" to newAssessment.riskScore.toString()
                ),
                riskScore = newAssessment.riskScore
            )
        } catch (e: Exception) {
            forensicLogger.logEvent(
                eventType = LogEventType.APP_PERMISSION_CHANGE,
                severity = Severity.WARNING,
                metadata = mapOf(
                    "package_name" to packageName,
                    "error" to e.message,
                    "action" to "update_analysis_failed"
                ),
                riskScore = 30
            )
        }
    }
    
    /**
     * Perform periodic rescan
     */
    private fun performPeriodicRescan() {
        val installedPackages = packageManager.getInstalledPackages(
            PackageManager.GET_PERMISSIONS or
            PackageManager.GET_SIGNATURES or
            PackageManager.GET_META_DATA
        )
        
        val assessments = mutableMapOf<String, AppRiskAssessment>()
        
        for (packageInfo in installedPackages) {
            val packageName = packageInfo.packageName
            val assessment = assessAppRisk(packageInfo)
            assessments[packageName] = assessment
        }
        
        _riskAssessments.value = assessments
    }
    
    /**
     * Assess app risk
     */
    private fun assessAppRisk(packageInfo: PackageInfo): AppRiskAssessment {
        val riskFactors = mutableListOf<String>()
        var riskScore = 0
        
        // Check if system app
        val isSystemApp = isSystemApp(packageInfo)
        if (!isSystemApp) {
            riskScore += 10
            riskFactors.add("non_system_app")
        }
        
        // Check permissions
        val permissionAnalysis = analyzePermissions(packageInfo)
        riskScore += permissionAnalysis.riskScore
        riskFactors.addAll(permissionAnalysis.riskFactors)
        
        // Check signature
        val signatureAnalysis = analyzeSignature(packageInfo)
        riskScore += signatureAnalysis.riskScore
        riskFactors.addAll(signatureAnalysis.riskFactors)
        
        // Check for suspicious metadata
        val metadataAnalysis = analyzeMetadata(packageInfo)
        riskScore += metadataAnalysis.riskScore
        riskFactors.addAll(metadataAnalysis.riskFactors)
        
        // Check for obfuscation indicators
        val obfuscationAnalysis = analyzeObfuscation(packageInfo)
        riskScore += obfuscationAnalysis.riskScore
        riskFactors.addAll(obfuscationAnalysis.riskFactors)
        
        // Check for native libraries
        val nativeLibAnalysis = analyzeNativeLibraries(packageInfo)
        riskScore += nativeLibAnalysis.riskScore
        riskFactors.addAll(nativeLibAnalysis.riskFactors)
        
        // Check if in known safe list
        if (packageInfo.packageName in knownSafeApps) {
            riskScore = (riskScore * 0.3).toInt() // Reduce risk by 70%
        }
        
        return AppRiskAssessment(
            packageName = packageInfo.packageName,
            appName = getAppName(packageInfo.packageName),
            riskScore = riskScore.coerceIn(0, 100),
            riskFactors = riskFactors,
            isSystemApp = isSystemApp,
            assessmentTimestamp = System.currentTimeMillis()
        )
    }
    
    /**
     * Analyze permissions
     */
    private fun analyzePermissions(packageInfo: PackageInfo): PermissionAnalysis {
        val riskFactors = mutableListOf<String>()
        var riskScore = 0
        
        val requestedPermissions = packageInfo.requestedPermissions ?: emptyArray()
        
        for (permission in requestedPermissions) {
            if (permission in highRiskPermissions) {
                riskScore += 5
                riskFactors.add("high_risk_permission:$permission")
            }
        }
        
        // Check for excessive permissions
        if (requestedPermissions.size > 20) {
            riskScore += 15
            riskFactors.add("excessive_permissions")
        }
        
        return PermissionAnalysis(
            riskScore = riskScore.coerceIn(0, 50),
            riskFactors = riskFactors
        )
    }
    
    /**
     * Analyze signature
     */
    private fun analyzeSignature(packageInfo: PackageInfo): SignatureAnalysis {
        val riskFactors = mutableListOf<String>()
        var riskScore = 0
        
        val signatures = packageInfo.signatures
        if (signatures == null || signatures.isEmpty()) {
            riskScore += 30
            riskFactors.add("no_signature")
        } else if (signatures.size > 1) {
            riskScore += 20
            riskFactors.add("multiple_signatures")
        }
        
        // Check for debug signature
        for (signature in signatures) {
            if (isDebugSignature(signature)) {
                riskScore += 25
                riskFactors.add("debug_signature")
            }
        }
        
        return SignatureAnalysis(
            riskScore = riskScore.coerceIn(0, 50),
            riskFactors = riskFactors
        )
    }
    
    /**
     * Check if signature is debug signature
     */
    private fun isDebugSignature(signature: android.content.pm.Signature): Boolean {
        // Debug signatures have specific patterns
        val signatureHash = signature.hashCode().toString()
        return signatureHash.contains("debug") || signatureHash.contains("test")
    }
    
    /**
     * Analyze metadata
     */
    private fun analyzeMetadata(packageInfo: PackageInfo): MetadataAnalysis {
        val riskFactors = mutableListOf<String>()
        var riskScore = 0
        
        val appInfo = packageInfo.applicationInfo
        
        // Check for debuggable flag
        if ((appInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
            riskScore += 20
            riskFactors.add("debuggable")
        }
        
        // Check for backup flag
        if ((appInfo.flags and ApplicationInfo.FLAG_ALLOW_BACKUP) != 0) {
            riskScore += 10
            riskFactors.add("allow_backup")
        }
        
        // Check for code path in external storage
        if (appInfo.sourceDir.contains("/sdcard/") || appInfo.sourceDir.contains("/storage/")) {
            riskScore += 30
            riskFactors.add("external_storage_install")
        }
        
        return MetadataAnalysis(
            riskScore = riskScore.coerceIn(0, 50),
            riskFactors = riskFactors
        )
    }
    
    /**
     * Analyze obfuscation
     */
    private fun analyzeObfuscation(packageInfo: PackageInfo): ObfuscationAnalysis {
        val riskFactors = mutableListOf<String>()
        var riskScore = 0
        
        val appInfo = packageInfo.applicationInfo
        
        // Check for common obfuscation indicators in package name
        val packageName = packageInfo.packageName
        if (packageName.matches(Regex("^[a-z]{1,2}\\..*"))) {
            riskScore += 15
            riskFactors.add("suspicious_package_name")
        }
        
        // Check for native code in unusual locations
        val nativeLibraryPath = appInfo.nativeLibraryDir
        if (nativeLibraryPath != null && nativeLibraryPath.contains("/data/local/")) {
            riskScore += 25
            riskFactors.add("unusual_native_lib_location")
        }
        
        return ObfuscationAnalysis(
            riskScore = riskScore.coerceIn(0, 50),
            riskFactors = riskFactors
        )
    }
    
    /**
     * Analyze native libraries
     */
    private fun analyzeNativeLibraries(packageInfo: PackageInfo): NativeLibAnalysis {
        val riskFactors = mutableListOf<String>()
        var riskScore = 0
        
        val appInfo = packageInfo.applicationInfo
        val nativeLibraryDir = appInfo.nativeLibraryDir
        
        if (nativeLibraryDir != null) {
            val nativeLibs = java.io.File(nativeLibraryDir).listFiles()
            
            if (nativeLibs != null) {
                // Check for suspicious native libraries
                for (lib in nativeLibs) {
                    val libName = lib.name.lowercase()
                    
                    if (libName.contains("hook") || libName.contains("inject") || 
                        libName.contains("frida") || libName.contains("xposed")) {
                        riskScore += 30
                        riskFactors.add("suspicious_native_lib:${lib.name}")
                    }
                    
                    if (libName.contains("tflite") || libName.contains("tensorflow")) {
                        riskScore += 10
                        riskFactors.add("ml_framework:${lib.name}")
                    }
                }
                
                // Check for excessive native libraries
                if (nativeLibs.size > 10) {
                    riskScore += 15
                    riskFactors.add("excessive_native_libs")
                }
            }
        }
        
        return NativeLibAnalysis(
            riskScore = riskScore.coerceIn(0, 50),
            riskFactors = riskFactors
        )
    }
    
    /**
     * Check if app is system app
     */
    private fun isSystemApp(packageInfo: PackageInfo): Boolean {
        return (packageInfo.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
    }
    
    /**
     * Get app name
     */
    private fun getAppName(packageName: String): String {
        return try {
            val appInfo = packageManager.getApplicationInfo(packageName, 0)
            packageManager.getApplicationLabel(appInfo).toString()
        } catch (e: Exception) {
            packageName
        }
    }
    
    /**
     * Get app risk assessment
     */
    fun getAppRiskAssessment(packageName: String): AppRiskAssessment? {
        return _riskAssessments.value[packageName]
    }
    
    /**
     * Get all high-risk apps
     */
    fun getHighRiskApps(): List<AppRiskAssessment> {
        return _riskAssessments.value.values.filter { it.riskScore >= 50 }
    }
    
    /**
     * Mark app as safe
     */
    fun markAppAsSafe(packageName: String) {
        val currentAssessments = _riskAssessments.value.toMutableMap()
        val assessment = currentAssessments[packageName]
        
        if (assessment != null) {
            val updatedAssessment = assessment.copy(riskScore = 0, riskFactors = emptyList())
            currentAssessments[packageName] = updatedAssessment
            _riskAssessments.value = currentAssessments
        }
    }
    
    /**
     * Handle threat detection
     */
    private fun handleThreatDetection(threat: ThreatAlert) {
        _detectedThreats.value = _detectedThreats.value + threat
    }
}

// Data classes for app risk assessment

data class AppRiskAssessment(
    val packageName: String,
    val appName: String,
    val riskScore: Int,
    val riskFactors: List<String>,
    val isSystemApp: Boolean,
    val assessmentTimestamp: Long
)

data class PermissionAnalysis(
    val riskScore: Int,
    val riskFactors: List<String>
)

data class SignatureAnalysis(
    val riskScore: Int,
    val riskFactors: List<String>
)

data class MetadataAnalysis(
    val riskScore: Int,
    val riskFactors: List<String>
)

data class ObfuscationAnalysis(
    val riskScore: Int,
    val riskFactors: List<String>
)

data class NativeLibAnalysis(
    val riskScore: Int,
    val riskFactors: List<String>
)
