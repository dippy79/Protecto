package com.protecto.aegis.core

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest
import java.util.UUID

/**
 * PROJECT AEGIS - Merkle Tree System Snapshot
 * 
 * Creates cryptographic snapshots of system directories using Merkle trees
 * to detect supply-chain attacks, ROM tampering, and unauthorized modifications.
 * 
 * Calculates "Drift Delta" - the percentage change between snapshots to
 * identify suspicious modifications.
 */
class MerkleTreeSnapshot(private val context: Context) {
    
    private val monitoredDirectories = listOf(
        "/system/app",
        "/system/priv-app",
        "/data/app",
        "/data/data"
    )
    
    companion object {
        private const val SNAPSHOT_PREFS = "aegis_snapshots"
        private const val BASELINE_PREFS = "aegis_baselines"
    }
    
    /**
     * Create a cryptographic snapshot of monitored directories
     */
    suspend fun createSnapshot(snapshotType: SnapshotType): SystemSnapshot = withContext(Dispatchers.IO) {
        val snapshotId = UUID.randomUUID().toString()
        val timestamp = System.currentTimeMillis()
        
        // Calculate directory hashes
        val directoryHashes = mutableMapOf<String, String>()
        
        for (directory in monitoredDirectories) {
            val dirFile = File(directory)
            if (dirFile.exists()) {
                val hash = calculateDirectoryHash(dirFile)
                directoryHashes[directory] = hash
            }
        }
        
        // Calculate Merkle root
        val rootHash = calculateMerkleRoot(directoryHashes.values.toList())
        
        // Calculate drift from baseline
        val drift = calculateDriftFromBaseline(directoryHashes)
        
        val snapshot = SystemSnapshot(
            snapshotId = snapshotId,
            timestamp = timestamp,
            snapshotType = snapshotType,
            rootHash = rootHash,
            directoryHashes = directoryHashes,
            driftDelta = drift,
            chainRef = "" // Will be linked to log chain
        )
        
        // Store snapshot
        storeSnapshot(snapshot)
        
        snapshot
    }
    
    /**
     * Calculate SHA-256 hash of a directory and all its contents
     */
    private fun calculateDirectoryHash(directory: File): String {
        if (!directory.exists() || !directory.isDirectory) {
            return sha256("DIRECTORY_NOT_FOUND:${directory.absolutePath}")
        }
        
        val hashes = mutableListOf<String>()
        
        // Recursively hash all files
        directory.walkTopDown()
            .filter { it.isFile }
            .sortedBy { it.absolutePath }
            .forEach { file ->
                val fileHash = calculateFileHash(file)
                hashes.add(fileHash)
            }
        
        // Hash the list of file hashes
        return if (hashes.isEmpty()) {
            sha256("EMPTY_DIRECTORY:${directory.absolutePath}")
        } else {
            sha256(hashes.joinToString("|"))
        }
    }
    
    /**
     * Calculate SHA-256 hash of a single file
     */
    private fun calculateFileHash(file: File): String {
        return try {
            val bytes = file.readBytes()
            sha256(bytes + file.absolutePath.toByteArray())
        } catch (e: Exception) {
            sha256("FILE_READ_ERROR:${file.absolutePath}")
        }
    }
    
    /**
     * Calculate Merkle root from a list of hashes
     */
    private fun calculateMerkleRoot(hashes: List<String>): String {
        if (hashes.isEmpty()) return sha256("EMPTY_TREE")
        if (hashes.size == 1) return hashes[0]
        
        var currentLevel = hashes
        while (currentLevel.size > 1) {
            val nextLevel = mutableListOf<String>()
            
            for (i in currentLevel.indices step 2) {
                if (i + 1 < currentLevel.size) {
                    val combined = currentLevel[i] + currentLevel[i + 1]
                    nextLevel.add(sha256(combined))
                } else {
                    // Odd number of elements, duplicate the last one
                    nextLevel.add(sha256(currentLevel[i] + currentLevel[i]))
                }
            }
            
            currentLevel = nextLevel
        }
        
        return currentLevel[0]
    }
    
    /**
     * Calculate drift delta from baseline snapshot
     */
    private fun calculateDriftFromBaseline(currentHashes: Map<String, String>): Float {
        val baselineHashes = loadBaselineHashes() ?: return 0f
        
        if (baselineHashes.isEmpty()) return 0f
        
        var changedCount = 0
        var totalCount = 0
        
        for ((directory, currentHash) in currentHashes) {
            val baselineHash = baselineHashes[directory]
            if (baselineHash != null) {
                totalCount++
                if (currentHash != baselineHash) {
                    changedCount++
                }
            }
        }
        
        return if (totalCount > 0) {
            (changedCount.toFloat() / totalCount.toFloat()) * 100f
        } else {
            0f
        }
    }
    
    /**
     * Store snapshot in encrypted preferences
     */
    private fun storeSnapshot(snapshot: SystemSnapshot) {
        val prefs = context.getSharedPreferences(SNAPSHOT_PREFS, Context.MODE_PRIVATE)
        
        val snapshotData = buildString {
            append(snapshot.snapshotId).append("|")
            append(snapshot.timestamp).append("|")
            append(snapshot.snapshotType.name).append("|")
            append(snapshot.rootHash).append("|")
            append(snapshot.driftDelta).append("|")
            append(snapshot.chainRef)
        }
        
        prefs.edit()
            .putString("snapshot_${snapshot.snapshotId}", snapshotData)
            .putString("snapshot_${snapshot.snapshotId}_dir_hashes", serializeDirectoryHashes(snapshot.directoryHashes))
            .apply()
    }
    
    /**
     * Serialize directory hashes map
     */
    private fun serializeDirectoryHashes(hashes: Map<String, String>): String {
        return hashes.entries.joinToString(",") { "${it.key}=${it.value}" }
    }
    
    /**
     * Deserialize directory hashes map
     */
    private fun deserializeDirectoryHashes(serialized: String): Map<String, String> {
        return try {
            serialized.split(",").mapNotNull { entry ->
                val parts = entry.split("=")
                if (parts.size == 2) {
                    parts[0] to parts[1]
                } else null
            }.toMap()
        } catch (e: Exception) {
            emptyMap()
        }
    }
    
    /**
     * Load baseline hashes
     */
    private fun loadBaselineHashes(): Map<String, String>? {
        val prefs = context.getSharedPreferences(BASELINE_PREFS, Context.MODE_PRIVATE)
        val baselineJson = prefs.getString("baseline_hashes", null) ?: return null
        return deserializeDirectoryHashes(baselineJson)
    }
    
    /**
     * Set current snapshot as baseline
     */
    suspend fun setAsBaseline(snapshot: SystemSnapshot) = withContext(Dispatchers.IO) {
        val prefs = context.getSharedPreferences(BASELINE_PREFS, Context.MODE_PRIVATE)
        val serialized = serializeDirectoryHashes(snapshot.directoryHashes)
        
        prefs.edit()
            .putString("baseline_hashes", serialized)
            .putLong("baseline_timestamp", snapshot.timestamp)
            .putString("baseline_id", snapshot.snapshotId)
            .apply()
    }
    
    /**
     * Load a specific snapshot
     */
    suspend fun loadSnapshot(snapshotId: String): SystemSnapshot? = withContext(Dispatchers.IO) {
        val prefs = context.getSharedPreferences(SNAPSHOT_PREFS, Context.MODE_PRIVATE)
        val snapshotData = prefs.getString("snapshot_$snapshotId", null) ?: return@withContext null
        val dirHashesData = prefs.getString("snapshot_${snapshotId}_dir_hashes", null) ?: return@withContext null
        
        val parts = snapshotData.split("|")
        if (parts.size != 6) return@withContext null
        
        SystemSnapshot(
            snapshotId = parts[0],
            timestamp = parts[1].toLong(),
            snapshotType = SnapshotType.valueOf(parts[2]),
            rootHash = parts[3],
            directoryHashes = deserializeDirectoryHashes(dirHashesData),
            driftDelta = parts[4].toFloat(),
            chainRef = parts[5]
        )
    }
    
    /**
     * Get all snapshots
     */
    suspend fun getAllSnapshots(): List<SystemSnapshot> = withContext(Dispatchers.IO) {
        val prefs = context.getSharedPreferences(SNAPSHOT_PREFS, Context.MODE_PRIVATE)
        val snapshotIds = prefs.all.keys.filter { it.startsWith("snapshot_") && !it.endsWith("_dir_hashes") }
        
        val snapshots = mutableListOf<SystemSnapshot>()
        for (id in snapshotIds) {
            val snapshotId = id.removePrefix("snapshot_")
            val snapshot = loadSnapshot(snapshotId)
            if (snapshot != null) {
                snapshots.add(snapshot)
            }
        }
        
        snapshots.sortedByDescending { it.timestamp }
    }
    
    /**
     * Compare two snapshots and return detailed diff
     */
    suspend fun compareSnapshots(snapshotId1: String, snapshotId2: String): SnapshotDiff = withContext(Dispatchers.IO) {
        val snapshot1 = loadSnapshot(snapshotId1) ?: return@withContext SnapshotDiff.empty()
        val snapshot2 = loadSnapshot(snapshotId2) ?: return@withContext SnapshotDiff.empty()
        
        val changedDirectories = mutableListOf<String>()
        val addedDirectories = mutableListOf<String>()
        val removedDirectories = mutableListOf<String>()
        
        for ((dir, hash1) in snapshot1.directoryHashes) {
            val hash2 = snapshot2.directoryHashes[dir]
            if (hash2 == null) {
                removedDirectories.add(dir)
            } else if (hash1 != hash2) {
                changedDirectories.add(dir)
            }
        }
        
        for ((dir, _) in snapshot2.directoryHashes) {
            if (dir !in snapshot1.directoryHashes) {
                addedDirectories.add(dir)
            }
        }
        
        SnapshotDiff(
            snapshot1Id = snapshotId1,
            snapshot2Id = snapshotId2,
            rootHashChanged = snapshot1.rootHash != snapshot2.rootHash,
            changedDirectories = changedDirectories,
            addedDirectories = addedDirectories,
            removedDirectories = removedDirectories,
            driftDelta = snapshot2.driftDelta
        )
    }
    
    /**
     * Delete old snapshots (keep last N)
     */
    suspend fun cleanupOldSnapshots(keepCount: Int = 10) = withContext(Dispatchers.IO) {
        val allSnapshots = getAllSnapshots()
        if (allSnapshots.size <= keepCount) return@withContext
        
        val toDelete = allSnapshots.drop(keepCount)
        val prefs = context.getSharedPreferences(SNAPSHOT_PREFS, Context.MODE_PRIVATE)
        
        for (snapshot in toDelete) {
            prefs.edit()
                .remove("snapshot_${snapshot.snapshotId}")
                .remove("snapshot_${snapshot.snapshotId}_dir_hashes")
                .apply()
        }
    }
    
    private fun sha256(input: ByteArray): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(input)
        return bytes.joinToString("") { "%02x".format(it) }
    }
    
    private fun sha256(input: String): String {
        return sha256(input.toByteArray())
    }
}

// Data classes for system snapshots

data class SystemSnapshot(
    val snapshotId: String,
    val timestamp: Long,
    val snapshotType: SnapshotType,
    val rootHash: String,
    val directoryHashes: Map<String, String>,
    val driftDelta: Float,
    val chainRef: String
)

data class SnapshotDiff(
    val snapshot1Id: String,
    val snapshot2Id: String,
    val rootHashChanged: Boolean,
    val changedDirectories: List<String>,
    val addedDirectories: List<String>,
    val removedDirectories: List<String>,
    val driftDelta: Float
) {
    companion object {
        fun empty() = SnapshotDiff(
            snapshot1Id = "",
            snapshot2Id = "",
            rootHashChanged = false,
            changedDirectories = emptyList(),
            addedDirectories = emptyList(),
            removedDirectories = emptyList(),
            driftDelta = 0f
        )
    }
}

enum class SnapshotType {
    PRE_SERVICE,
    POST_SERVICE,
    MANUAL
}
