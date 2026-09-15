package com.protecto.aegis.core

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import java.security.KeyStore
import java.security.Signature
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

/**
 * PROJECT AEGIS - Hash-Chained Forensic Logger
 * 
 * Implements cryptographic log sealing using hash-chaining to ensure
 * tamper-evident forensic logging. Each log entry includes the hash of
 * the previous entry, creating an immutable chain.
 * 
 * All logs are signed using hardware-backed Keystore for maximum security.
 */
class ForensicLogger(private val context: Context) {
    
    private val keystore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()
    
    private val encryptedPrefs = EncryptedSharedPreferences.create(
        context,
        "aegis_forensic_logs",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )
    
    private val chainPrefs = EncryptedSharedPreferences.create(
        context,
        "aegis_log_chains",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )
    
    private var currentChainId: String? = null
    private var previousHash: String? = null
    
    init {
        initializeKeystoreKeys()
        loadOrCreateLogChain()
    }
    
    private fun initializeKeystoreKeys() {
        // Generate signing key for log entries
        if (!keystore.containsAlias("aegis_log_signing_key")) {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                "AndroidKeyStore"
            )
            
            val keyGenSpec = KeyGenParameterSpec.Builder(
                "aegis_log_signing_key",
                KeyProperties.PURPOSE_SIGN
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setSignatureAlgorithms("SHA256withECDSA")
                .setUserAuthenticationRequired(false)
                .build()
            
            keyGenerator.init(keyGenSpec)
            keyGenerator.generateKey()
        }
    }
    
    private fun loadOrCreateLogChain() {
        currentChainId = chainPrefs.getString("current_chain_id", null)
        
        if (currentChainId == null) {
            // Create new chain
            currentChainId = UUID.randomUUID().toString()
            previousHash = "GENESIS" // First entry has no previous hash
            
            chainPrefs.edit()
                .putString("current_chain_id", currentChainId)
                .putString("${currentChainId}_genesis", previousHash)
                .putInt("${currentChainId}_count", 0)
                .putLong("${currentChainId}_last_verified", System.currentTimeMillis())
                .putBoolean("${currentChainId}_tamper_detected", false)
                .apply()
        } else {
            // Load existing chain
            previousHash = chainPrefs.getString("${currentChainId}_last_hash", "GENESIS")
        }
    }
    
    suspend fun logEvent(
        eventType: LogEventType,
        severity: Severity,
        metadata: Map<String, Any>,
        riskScore: Int
    ): ForensicLogEntry = withContext(Dispatchers.IO) {
        val eventId = UUID.randomUUID().toString()
        val timestamp = System.currentTimeMillis()
        
        // Create hash chain entry
        val entryData = buildString {
            append(eventId)
            append(timestamp)
            append(eventType.name)
            append(severity.name)
            append(metadata.toString())
            append(riskScore)
            append(previousHash ?: "GENESIS")
        }
        
        val currentHash = sha256(entryData)
        
        // Sign the entry
        val signature = signEntry(currentHash)
        
        // Create log entry
        val entry = ForensicLogEntry(
            eventId = eventId,
            timestamp = timestamp,
            eventType = eventType,
            severity = severity,
            metadata = metadata,
            riskScore = riskScore,
            previousHash = previousHash ?: "GENESIS",
            currentHash = currentHash,
            signature = signature,
            integrityVerified = verifyChainIntegrity()
        )
        
        // Store entry
        storeLogEntry(entry)
        
        // Update chain state
        previousHash = currentHash
        updateChainState()
        
        entry
    }
    
    private fun sha256(input: String): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(input.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }
    
    private fun signEntry(hash: String): String {
        val signingKey = keystore.getEntry("aegis_log_signing_key", null) as KeyStore.PrivateKeyEntry
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(signingKey.privateKey)
        signature.update(hash.toByteArray())
        val signedBytes = signature.sign()
        return signedBytes.joinToString("") { "%02x".format(it) }
    }
    
    private fun verifyEntrySignature(hash: String, signature: String): Boolean {
        return try {
            val signingKey = keystore.getEntry("aegis_log_signing_key", null) as KeyStore.PrivateKeyEntry
            val sig = Signature.getInstance("SHA256withECDSA")
            sig.initVerify(signingKey.certificate)
            sig.update(hash.toByteArray())
            sig.verify(signature.hexToBytes())
        } catch (e: Exception) {
            false
        }
    }
    
    private fun String.hexToBytes(): ByteArray {
        return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
    
    private fun storeLogEntry(entry: ForensicLogEntry) {
        val entryJson = serializeEntry(entry)
        encryptedPrefs.edit()
            .putString("entry_${entry.eventId}", entryJson)
            .apply()
    }
    
    private fun serializeEntry(entry: ForensicLogEntry): String {
        return buildString {
            append(entry.eventId).append("|")
            append(entry.timestamp).append("|")
            append(entry.eventType.name).append("|")
            append(entry.severity.name).append("|")
            append(entry.metadata.toString()).append("|")
            append(entry.riskScore).append("|")
            append(entry.previousHash).append("|")
            append(entry.currentHash).append("|")
            append(entry.signature).append("|")
            append(entry.integrityVerified)
        }
    }
    
    private fun updateChainState() {
        val count = chainPrefs.getInt("${currentChainId}_count", 0) + 1
        chainPrefs.edit()
            .putString("${currentChainId}_last_hash", previousHash)
            .putInt("${currentChainId}_count", count)
            .apply()
    }
    
    suspend fun verifyChainIntegrity(): Boolean = withContext(Dispatchers.IO) {
        try {
            val chainId = currentChainId ?: return@withContext false
            val entryCount = chainPrefs.getInt("${chainId}_count", 0)
            
            if (entryCount == 0) return@withContext true
            
            // Get all entries and verify chain
            val allEntries = getAllEntries()
            var lastHash = "GENESIS"
            
            for (entry in allEntries.sortedBy { it.timestamp }) {
                // Verify hash chain
                if (entry.previousHash != lastHash) {
                    markChainTampered()
                    return@withContext false
                }
                
                // Verify signature
                if (!verifyEntrySignature(entry.currentHash, entry.signature)) {
                    markChainTampered()
                    return@withContext false
                }
                
                lastHash = entry.currentHash
            }
            
            // Update last verified timestamp
            chainPrefs.edit()
                .putLong("${chainId}_last_verified", System.currentTimeMillis())
                .apply()
            
            true
        } catch (e: Exception) {
            markChainTampered()
            false
        }
    }
    
    private fun markChainTampered() {
        chainPrefs.edit()
            .putBoolean("${currentChainId}_tamper_detected", true)
            .apply()
    }
    
    suspend fun getAllEntries(): List<ForensicLogEntry> = withContext(Dispatchers.IO) {
        val entries = mutableListOf<ForensicLogEntry>()
        val allKeys = encryptedPrefs.all.keys.filter { it.startsWith("entry_") }
        
        for (key in allKeys) {
            val entryJson = encryptedPrefs.getString(key, null) ?: continue
            val entry = deserializeEntry(entryJson)
            entries.add(entry)
        }
        
        entries
    }
    
    private fun deserializeEntry(json: String): ForensicLogEntry {
        val parts = json.split("|")
        return ForensicLogEntry(
            eventId = parts[0],
            timestamp = parts[1].toLong(),
            eventType = LogEventType.valueOf(parts[2]),
            severity = Severity.valueOf(parts[3]),
            metadata = parseMetadata(parts[4]),
            riskScore = parts[5].toInt(),
            previousHash = parts[6],
            currentHash = parts[7],
            signature = parts[8],
            integrityVerified = parts[9].toBoolean()
        )
    }
    
    private fun parseMetadata(metadataString: String): Map<String, Any> {
        // Simple parsing - in production, use proper JSON parser
        return try {
            val cleanString = metadataString.removeSurrounding("{", "}")
            if (cleanString.isEmpty()) return emptyMap()
            
            cleanString.split(", ").mapNotNull { pair ->
                val keyValue = pair.split("=")
                if (keyValue.size == 2) {
                    keyValue[0].trim() to keyValue[1].trim()
                } else null
            }.toMap()
        } catch (e: Exception) {
            emptyMap()
        }
    }
    
    suspend fun getLogChain(): LogChain = withContext(Dispatchers.IO) {
        val chainId = currentChainId ?: return@withContext LogChain(
            chainId = "",
            genesisHash = "",
            currentHead = "",
            entryCount = 0,
            lastVerified = 0,
            tamperDetected = true
        )
        
        LogChain(
            chainId = chainId,
            genesisHash = chainPrefs.getString("${chainId}_genesis", "") ?: "",
            currentHead = chainPrefs.getString("${chainId}_last_hash", "") ?: "",
            entryCount = chainPrefs.getInt("${chainId}_count", 0),
            lastVerified = chainPrefs.getLong("${chainId}_last_verified", 0),
            tamperDetected = chainPrefs.getBoolean("${chainId}_tamper_detected", false)
        )
    }
    
    suspend fun createNewChain(): String = withContext(Dispatchers.IO) {
        val newChainId = UUID.randomUUID().toString()
        
        chainPrefs.edit()
            .putString("current_chain_id", newChainId)
            .putString("${newChainId}_genesis", "GENESIS")
            .putString("${newChainId}_last_hash", "GENESIS")
            .putInt("${newChainId}_count", 0)
            .putLong("${newChainId}_last_verified", System.currentTimeMillis())
            .putBoolean("${newChainId}_tamper_detected", false)
            .apply()
        
        currentChainId = newChainId
        previousHash = "GENESIS"
        
        newChainId
    }
}

// Data classes for forensic logging

data class ForensicLogEntry(
    val eventId: String,
    val timestamp: Long,
    val eventType: LogEventType,
    val severity: Severity,
    val metadata: Map<String, Any>,
    val riskScore: Int,
    val previousHash: String,
    val currentHash: String,
    val signature: String,
    val integrityVerified: Boolean
)

data class LogChain(
    val chainId: String,
    val genesisHash: String,
    val currentHead: String,
    val entryCount: Int,
    val lastVerified: Long,
    val tamperDetected: Boolean
)

enum class LogEventType {
    USB_DEVICE_CONNECTED,
    USB_DEVICE_DISCONNECTED,
    USB_SUSPICIOUS_ACTIVITY,
    NETWORK_CONNECTION,
    DNS_QUERY,
    TLS_HANDSHAKE,
    APP_INSTALL,
    APP_UNINSTALL,
    APP_PERMISSION_CHANGE,
    SYSTEM_INTEGRITY_CHECK,
    INCIDENT_RESPONSE
}

enum class Severity {
    INFO,
    WARNING,
    HIGH,
    CRITICAL
}
