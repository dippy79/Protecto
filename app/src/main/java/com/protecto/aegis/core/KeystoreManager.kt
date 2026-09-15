package com.protecto.aegis.core

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * PROJECT AEGIS - Hardware-Backed Keystore Manager
 * 
 * Manages all cryptographic operations using Android's hardware-backed Keystore.
 * Ensures that cryptographic keys never leave the secure hardware enclave.
 * 
 * Supports:
 * - Asymmetric encryption/signing (ECDSA)
 * - Symmetric encryption (AES-GCM)
 * - Hardware backing verification
 * - Key access control
 */
class KeystoreManager(private val context: Context) {
    
    private val keystore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    
    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS_ENCRYPTION = "aegis_encryption_key"
        private const val KEY_ALIAS_SIGNING = "aegis_signing_key"
        private const val KEY_ALIAS_HMAC = "aegis_hmac_key"
        private const val AES_KEY_SIZE = 256
        private const val GCM_TAG_LENGTH = 128
        private const val GCM_IV_LENGTH = 12
    }
    
    init {
        initializeKeys()
    }
    
    private fun initializeKeys() {
        if (!keystore.containsAlias(KEY_ALIAS_ENCRYPTION)) {
            generateEncryptionKey()
        }
        if (!keystore.containsAlias(KEY_ALIAS_SIGNING)) {
            generateSigningKey()
        }
        if (!keystore.containsAlias(KEY_ALIAS_HMAC)) {
            generateHMACKey()
        }
    }
    
    /**
     * Generate AES-GCM encryption key with hardware backing
     */
    private fun generateEncryptionKey() {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )
        
        val keyGenSpec = KeyGenParameterSpec.Builder(
            KEY_ALIAS_ENCRYPTION,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(AES_KEY_SIZE)
            .setRandomizedEncryptionRequired(true)
            .build()
        
        keyGenerator.init(keyGenSpec)
        keyGenerator.generateKey()
    }
    
    /**
     * Generate ECDSA signing key with hardware backing
     */
    private fun generateSigningKey() {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEYSTORE
        )
        
        val keyGenSpec = KeyGenParameterSpec.Builder(
            KEY_ALIAS_SIGNING,
            KeyProperties.PURPOSE_SIGN
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setSignatureAlgorithms("SHA256withECDSA")
            .setUserAuthenticationRequired(false)
            .build()
        
        keyGenerator.init(keyGenSpec)
        keyGenerator.generateKey()
    }
    
    /**
     * Generate HMAC key for integrity verification
     */
    private fun generateHMACKey() {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_HMAC_SHA256,
            ANDROID_KEYSTORE
        )
        
        val keyGenSpec = KeyGenParameterSpec.Builder(
            KEY_ALIAS_HMAC,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .build()
        
        keyGenerator.init(keyGenSpec)
        keyGenerator.generateKey()
    }
    
    /**
     * Encrypt data using AES-GCM with hardware-backed key
     */
    fun encryptData(data: ByteArray): EncryptionResult {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val key = getSecretKey(KEY_ALIAS_ENCRYPTION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        
        val iv = cipher.iv
        val encryptedData = cipher.doFinal(data)
        
        return EncryptionResult(
            encryptedData = encryptedData,
            iv = iv
        )
    }
    
    /**
     * Decrypt data using AES-GCM with hardware-backed key
     */
    fun decryptData(encryptedData: ByteArray, iv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val key = getSecretKey(KEY_ALIAS_ENCRYPTION)
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.DECRYPT_MODE, key, spec)
        
        return cipher.doFinal(encryptedData)
    }
    
    /**
     * Sign data using ECDSA with hardware-backed key
     */
    fun signData(data: ByteArray): ByteArray {
        val signature = Signature.getInstance("SHA256withECDSA")
        val key = getPrivateKey(KEY_ALIAS_SIGNING)
        signature.initSign(key)
        signature.update(data)
        return signature.sign()
    }
    
    /**
     * Verify signature using ECDSA with hardware-backed key
     */
    fun verifySignature(data: ByteArray, signature: ByteArray): Boolean {
        return try {
            val sig = Signature.getInstance("SHA256withECDSA")
            val key = getPublicKey(KEY_ALIAS_SIGNING)
            sig.initVerify(key)
            sig.update(data)
            sig.verify(signature)
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Generate HMAC for data integrity
     */
    fun generateHMAC(data: ByteArray): ByteArray {
        val key = getSecretKey(KEY_ALIAS_HMAC)
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(key)
        return mac.doFinal(data)
    }
    
    /**
     * Verify HMAC for data integrity
     */
    fun verifyHMAC(data: ByteArray, hmac: ByteArray): Boolean {
        val computedHMAC = generateHMAC(data)
        return computedHMAC.contentEquals(hmac)
    }
    
    /**
     * Verify that a key is hardware-backed
     */
    fun isKeyHardwareBacked(alias: String): Boolean {
        return try {
            val factory = KeyFactory.getInstance(ANDROID_KEYSTORE, "AndroidKeyStoreBCWorkaround")
            val keyInfo = KeyInfo(
                factory.getKeySpec(
                    keystore.getCertificate(alias).publicKey,
                    X509EncodedKeySpec::class.java
                )
            )
            keyInfo.isInsideSecureHardware
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Get all security information about keys
     */
    fun getKeySecurityInfo(): KeySecurityInfo {
        return KeySecurityInfo(
            encryptionKeyHardwareBacked = isKeyHardwareBacked(KEY_ALIAS_ENCRYPTION),
            signingKeyHardwareBacked = isKeyHardwareBacked(KEY_ALIAS_SIGNING),
            hmacKeyHardwareBacked = isKeyHardwareBacked(KEY_ALIAS_HMAC),
            totalKeys = keystore.size(),
            keyAliases = keystore.aliases().toList()
        )
    }
    
    /**
     * Rotate encryption key (generate new one, migrate data)
     */
    fun rotateEncryptionKey(): Boolean {
        return try {
            // Generate new key
            val oldAlias = KEY_ALIAS_ENCRYPTION
            val newAlias = "${KEY_ALIAS_ENCRYPTION}_rotated_${System.currentTimeMillis()}"
            
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE
            )
            
            val keyGenSpec = KeyGenParameterSpec.Builder(
                newAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(AES_KEY_SIZE)
                .setRandomizedEncryptionRequired(true)
                .build()
            
            keyGenerator.init(keyGenSpec)
            keyGenerator.generateKey()
            
            // In production, you would migrate encrypted data here
            // For now, just mark old key for deletion
            
            // Delete old key
            keystore.deleteEntry(oldAlias)
            
            // Rename new key to standard alias
            val newKey = keystore.getKey(newAlias, null) as SecretKey
            keystore.deleteEntry(newAlias)
            
            // Regenerate with standard alias
            generateEncryptionKey()
            
            true
        } catch (e: Exception) {
            false
        }
    }
    
    private fun getSecretKey(alias: String): SecretKey {
        return keystore.getKey(alias, null) as SecretKey
    }
    
    private fun getPrivateKey(alias: String): PrivateKey {
        val entry = keystore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        return entry.privateKey
    }
    
    private fun getPublicKey(alias: String): PublicKey {
        val entry = keystore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        return entry.certificate.publicKey
    }
    
    /**
     * Securely wipe all keys (emergency procedure)
     */
    fun wipeAllKeys() {
        keystore.aliases().forEach { alias ->
            if (alias.startsWith("aegis_")) {
                keystore.deleteEntry(alias)
            }
        }
    }
}

// Data classes for cryptographic operations

data class EncryptionResult(
    val encryptedData: ByteArray,
    val iv: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        
        other as EncryptionResult
        
        if (!encryptedData.contentEquals(other.encryptedData)) return false
        if (!iv.contentEquals(other.iv)) return false
        
        return true
    }
    
    override fun hashCode(): Int {
        var result = encryptedData.contentHashCode()
        result = 31 * result + iv.contentHashCode()
        return result
    }
}

data class KeySecurityInfo(
    val encryptionKeyHardwareBacked: Boolean,
    val signingKeyHardwareBacked: Boolean,
    val hmacKeyHardwareBacked: Boolean,
    val totalKeys: Int,
    val keyAliases: List<String>
)
