package com.protecto.aegis.app

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import com.protecto.aegis.core.ForensicLogger
import com.protecto.aegis.core.LogEventType
import com.protecto.aegis.core.Severity
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

/**
 * PROJECT AEGIS - APK Analyzer
 * 
 * Deep analysis of APK files for security assessment including:
 * - APK metadata extraction
 * - Signature verification
 * - Permission analysis
 * - Native library analysis
 * - Code entropy calculation (obfuscation detection)
 * - Resource analysis
 * 
 * Core Philosophy: DETECT → BLOCK → ISOLATE → RECORD → ANALYZE → ALERT → RECOVER
 */
class APKAnalyzer(
    private val context: Context,
    private val forensicLogger: ForensicLogger
) {
    
    private val packageManager = context.packageManager
    
    /**
     * Perform comprehensive APK analysis
     */
    fun analyzeAPK(packageName: String): APKAnalysisResult {
        return try {
            val packageInfo = packageManager.getPackageInfo(
                packageName,
                PackageManager.GET_PERMISSIONS or
                PackageManager.GET_SIGNATURES or
                PackageManager.GET_META_DATA or
                PackageManager.GET_SHARED_LIBRARY_FILES
            )
            
            val appInfo = packageInfo.applicationInfo
            val apkPath = appInfo.sourceDir
            
            APKAnalysisResult(
                packageName = packageName,
                appName = getAppName(packageName),
                apkPath = apkPath,
                apkSize = File(apkPath).length(),
                versionName = packageInfo.versionName,
                versionCode = packageInfo.versionCode,
                targetSdk = packageInfo.applicationInfo.targetSdkVersion,
                minSdk = packageInfo.applicationInfo.minSdkVersion,
                permissions = packageInfo.requestedPermissions?.toList() ?: emptyList(),
                signatures = analyzeSignatures(packageInfo),
                nativeLibraries = analyzeNativeLibraries(apkPath),
                metadata = analyzeMetadata(packageInfo),
                entropy = calculateAPKEntropy(apkPath),
                isSystemApp = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                isDebuggable = (appInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0,
                analysisTimestamp = System.currentTimeMillis()
            )
        } catch (e: Exception) {
            forensicLogger.logEvent(
                eventType = LogEventType.APP_INSTALL,
                severity = Severity.WARNING,
                metadata = mapOf(
                    "package_name" to packageName,
                    "error" to e.message,
                    "action" to "apk_analysis_failed"
                ),
                riskScore = 30
            )
            
            APKAnalysisResult.error(packageName, e.message ?: "Unknown error")
        }
    }
    
    /**
     * Analyze signatures
     */
    private fun analyzeSignatures(packageInfo: PackageInfo): SignatureAnalysis {
        val signatures = packageInfo.signatures
        
        if (signatures == null || signatures.isEmpty()) {
            return SignatureAnalysis(
                signatureCount = 0,
                signatureHashes = emptyList(),
                hasValidSignature = false,
                hasDebugSignature = false,
                isSelfSigned = false
            )
        }
        
        val signatureHashes = mutableListOf<String>()
        var hasDebugSignature = false
        
        for (signature in signatures) {
            val hash = sha256(signature.toByteArray())
            signatureHashes.add(hash)
            
            if (isDebugSignature(signature)) {
                hasDebugSignature = true
            }
        }
        
        return SignatureAnalysis(
            signatureCount = signatures.size,
            signatureHashes = signatureHashes,
            hasValidSignature = true,
            hasDebugSignature = hasDebugSignature,
            isSelfSigned = signatures.size == 1
        )
    }
    
    /**
     * Check if signature is debug signature
     */
    private fun isDebugSignature(signature: android.content.pm.Signature): Boolean {
        val signatureBytes = signature.toByteArray()
        val signatureString = signatureBytes.joinToString("") { "%02x".format(it) }
        
        // Debug signatures have specific patterns
        return signatureString.contains("a9:02:1b") || 
               signatureString.contains("androiddebugkey") ||
               signatureString.contains("debug")
    }
    
    /**
     * Analyze native libraries
     */
    private fun analyzeNativeLibraries(apkPath: String): NativeLibraryAnalysis {
        val nativeLibs = mutableListOf<NativeLibraryInfo>()
        
        try {
            val zipFile = ZipFile(apkPath)
            val entries = zipFile.entries()
            
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                if (entry.name.startsWith("lib/") && entry.name.endsWith(".so")) {
                    val libInfo = NativeLibraryInfo(
                        name = entry.name.substringAfterLast("/"),
                        path = entry.name,
                        size = entry.size,
                        architecture = extractArchitecture(entry.name),
                        isSuspicious = isSuspiciousNativeLib(entry.name)
                    )
                    nativeLibs.add(libInfo)
                }
            }
            
            zipFile.close()
        } catch (e: Exception) {
            // Log error but continue
        }
        
        return NativeLibraryAnalysis(
            libraryCount = nativeLibs.size,
            libraries = nativeLibs,
            hasSuspiciousLibraries = nativeLibs.any { it.isSuspicious },
            architectures = nativeLibs.map { it.architecture }.distinct()
        )
    }
    
    /**
     * Extract architecture from library path
     */
    private fun extractArchitecture(path: String): String {
        return when {
            path.contains("armeabi-v7a") -> "armeabi-v7a"
            path.contains("arm64-v8a") -> "arm64-v8a"
            path.contains("x86") -> "x86"
            path.contains("x86_64") -> "x86_64"
            else -> "unknown"
        }
    }
    
    /**
     * Check if native library is suspicious
     */
    private fun isSuspiciousNativeLib(name: String): String {
        val suspiciousKeywords = listOf(
            "hook", "inject", "frida", "xposed", "substrate",
            "root", "su", "busybox", "magisk",
            " exploit", "payload", "shell", "reverse"
        )
        
        val lowerName = name.lowercase()
        return suspiciousKeywords.any { lowerName.contains(it) }.toString()
    }
    
    /**
     * Analyze metadata
     */
    private fun analyzeMetadata(packageInfo: PackageInfo): MetadataAnalysis {
        val appInfo = packageInfo.applicationInfo
        val metaData = appInfo.metaData
        
        val customMetadata = mutableMapOf<String, String>()
        metaData?.let {
            for (key in it.keySet()) {
                customMetadata[key] = it.get(key).toString()
            }
        }
        
        return MetadataAnalysis(
            flags = appInfo.flags,
            flagsStr = decodeFlags(appInfo.flags),
            customMetadata = customMetadata,
            hasBackupEnabled = (appInfo.flags and ApplicationInfo.FLAG_ALLOW_BACKUP) != 0,
            hasDebuggableEnabled = (appInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0,
            hasLargeHeapEnabled = (appInfo.flags and ApplicationInfo.FLAG_LARGE_HEAP) != 0
        )
    }
    
    /**
     * Decode application flags
     */
    private fun decodeFlags(flags: Int): List<String> {
        val flagList = mutableListOf<String>()
        
        if ((flags and ApplicationInfo.FLAG_SYSTEM) != 0) {
            flagList.add("SYSTEM")
        }
        if ((flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
            flagList.add("DEBUGGABLE")
        }
        if ((flags and ApplicationInfo.FLAG_ALLOW_BACKUP) != 0) {
            flagList.add("ALLOW_BACKUP")
        }
        if ((flags and ApplicationInfo.FLAG_LARGE_HEAP) != 0) {
            flagList.add("LARGE_HEAP")
        }
        if ((flags and ApplicationInfo.FLAG_EXTERNAL_STORAGE) != 0) {
            flagList.add("EXTERNAL_STORAGE")
        }
        if ((flags and ApplicationInfo.FLAG_HAS_CODE) != 0) {
            flagList.add("HAS_CODE")
        }
        if ((flags and ApplicationInfo.FLAG_PERSISTENT) != 0) {
            flagList.add("PERSISTENT")
        }
        if ((flags and ApplicationInfo.FLAG_FACTORY_TEST) != 0) {
            flagList.add("FACTORY_TEST")
        }
        
        return flagList
    }
    
    /**
     * Calculate APK entropy (obfuscation detection)
     */
    private fun calculateAPKEntropy(apkPath: String): Double {
        return try {
            val file = File(apkPath)
            val bytes = file.readBytes()
            calculateShannonEntropy(bytes)
        } catch (e: Exception) {
            0.0
        }
    }
    
    /**
     * Calculate Shannon entropy
     */
    private fun calculateShannonEntropy(bytes: ByteArray): Double {
        if (bytes.isEmpty()) return 0.0
        
        val frequency = mutableMapOf<Byte, Int>()
        for (byte in bytes) {
            frequency[byte] = frequency.getOrDefault(byte, 0) + 1
        }
        
        val length = bytes.size.toDouble()
        var entropy = 0.0
        
        for (count in frequency.values) {
            val probability = count / length
            if (probability > 0) {
                entropy -= probability * kotlin.math.ln(probability) / kotlin.math.ln(2.0)
            }
        }
        
        return entropy
    }
    
    /**
     * Calculate SHA-256 hash
     */
    private fun sha256(input: ByteArray): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(input)
        return bytes.joinToString("") { "%02x".format(it) }
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
     * Compare two APK analyses
     */
    fun compareAPKAnalyses(analysis1: APKAnalysisResult, analysis2: APKAnalysisResult): APKComparison {
        val differences = mutableListOf<String>()
        
        if (analysis1.versionCode != analysis2.versionCode) {
            differences.add("version_code_changed:${analysis1.versionCode}->${analysis2.versionCode}")
        }
        
        if (analysis1.signatures.signatureHashes != analysis2.signatures.signatureHashes) {
            differences.add("signature_changed")
        }
        
        if (analysis1.permissions != analysis2.permissions) {
            val newPerms = analysis2.permissions - analysis1.permissions
            val removedPerms = analysis1.permissions - analysis2.permissions
            
            if (newPerms.isNotEmpty()) {
                differences.add("permissions_added:${newPerms.joinToString(",")}")
            }
            if (removedPerms.isNotEmpty()) {
                differences.add("permissions_removed:${removedPerms.joinToString(",")}")
            }
        }
        
        if (analysis1.nativeLibraries.libraryCount != analysis2.nativeLibraries.libraryCount) {
            differences.add("native_libs_changed:${analysis1.nativeLibraries.libraryCount}->${analysis2.nativeLibraries.libraryCount}")
        }
        
        val entropyDelta = kotlin.math.abs(analysis1.entropy - analysis2.entropy)
        if (entropyDelta > 0.5) {
            differences.add("entropy_changed:$entropyDelta")
        }
        
        return APKComparison(
            packageName = analysis1.packageName,
            analysis1Timestamp = analysis1.analysisTimestamp,
            analysis2Timestamp = analysis2.analysisTimestamp,
            differences = differences,
            hasSignificantChanges = differences.isNotEmpty(),
            riskScore = if (differences.isNotEmpty()) {
                when {
                    differences.any { it.contains("signature_changed") } -> 80
                    differences.any { it.contains("permissions_added") } -> 50
                    differences.any { it.contains("native_libs_changed") } -> 40
                    else -> 30
                }
            } else {
                0
            }
        )
    }
}

// Data classes for APK analysis

data class APKAnalysisResult(
    val packageName: String,
    val appName: String,
    val apkPath: String,
    val apkSize: Long,
    val versionName: String?,
    val versionCode: Long,
    val targetSdk: Int,
    val minSdk: Int,
    val permissions: List<String>,
    val signatures: SignatureAnalysis,
    val nativeLibraries: NativeLibraryAnalysis,
    val metadata: MetadataAnalysis,
    val entropy: Double,
    val isSystemApp: Boolean,
    val isDebuggable: Boolean,
    val analysisTimestamp: Long,
    val isError: Boolean = false,
    val errorMessage: String? = null
) {
    companion object {
        fun error(packageName: String, errorMessage: String) = APKAnalysisResult(
            packageName = packageName,
            appName = packageName,
            apkPath = "",
            apkSize = 0,
            versionName = null,
            versionCode = 0,
            targetSdk = 0,
            minSdk = 0,
            permissions = emptyList(),
            signatures = SignatureAnalysis(
                signatureCount = 0,
                signatureHashes = emptyList(),
                hasValidSignature = false,
                hasDebugSignature = false,
                isSelfSigned = false
            ),
            nativeLibraries = NativeLibraryAnalysis(
                libraryCount = 0,
                libraries = emptyList(),
                hasSuspiciousLibraries = false,
                architectures = emptyList()
            ),
            metadata = MetadataAnalysis(
                flags = 0,
                flagsStr = emptyList(),
                customMetadata = emptyMap(),
                hasBackupEnabled = false,
                hasDebuggableEnabled = false,
                hasLargeHeapEnabled = false
            ),
            entropy = 0.0,
            isSystemApp = false,
            isDebuggable = false,
            analysisTimestamp = System.currentTimeMillis(),
            isError = true,
            errorMessage = errorMessage
        )
    }
}

data class SignatureAnalysis(
    val signatureCount: Int,
    val signatureHashes: List<String>,
    val hasValidSignature: Boolean,
    val hasDebugSignature: Boolean,
    val isSelfSigned: Boolean
)

data class NativeLibraryAnalysis(
    val libraryCount: Int,
    val libraries: List<NativeLibraryInfo>,
    val hasSuspiciousLibraries: Boolean,
    val architectures: List<String>
)

data class NativeLibraryInfo(
    val name: String,
    val path: String,
    val size: Long,
    val architecture: String,
    val isSuspicious: String
)

data class MetadataAnalysis(
    val flags: Int,
    val flagsStr: List<String>,
    val customMetadata: Map<String, String>,
    val hasBackupEnabled: Boolean,
    val hasDebuggableEnabled: Boolean,
    val hasLargeHeapEnabled: Boolean
)

data class APKComparison(
    val packageName: String,
    val analysis1Timestamp: Long,
    val analysis2Timestamp: Long,
    val differences: List<String>,
    val hasSignificantChanges: Boolean,
    val riskScore: Int
)
