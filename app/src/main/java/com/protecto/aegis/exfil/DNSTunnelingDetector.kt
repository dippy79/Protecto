package com.protecto.aegis.exfil

import android.content.Context
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
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * PROJECT AEGIS - DNS Tunneling Detector
 * 
 * Detects DNS tunneling used for data exfiltration and covert channels.
 * DNS tunneling encodes data in DNS queries to bypass network security controls.
 * 
 * Detection methods:
 * - High entropy DNS queries (random-looking subdomains)
 * - Abnormal query frequency
 * - Unusually long DNS queries
 * - Suspicious domain patterns
 * - Query length analysis
 * 
 * Core Philosophy: DETECT → BLOCK → ISOLATE → RECORD → ANALYZE → ALERT → RECOVER
 */
class DNSTunnelingDetector(
    private val context: Context,
    private val forensicLogger: ForensicLogger
) {
    
    private val _isMonitoring = MutableStateFlow(false)
    val isMonitoring: StateFlow<Boolean> = _isMonitoring.asStateFlow()
    
    private val _detectedTunnels = MutableStateFlow<List<DNSTunnelAlert>>(emptyList())
    val detectedTunnels: StateFlow<List<DNSTunnelAlert>> = _detectedTunnels.asStateFlow()
    
    private val _dnsQueryStats = MutableStateFlow(DNSQueryStats())
    val dnsQueryStats: StateFlow<DNSQueryStats> = _dnsQueryStats.asStateFlow()
    
    // DNS query history (circular buffer)
    private val queryHistory = ConcurrentLinkedQueue<DNSQuery>()
    private val maxHistorySize = 1000
    
    // Domain frequency tracking
    private val domainFrequency = mutableMapOf<String, Int>()
    
    // Known safe domains
    private val knownSafeDomains = setOf(
        "google.com",
        "facebook.com",
        "apple.com",
        "microsoft.com",
        "amazon.com",
        "netflix.com",
        "twitter.com",
        "instagram.com",
        "linkedin.com",
        "github.com",
        "stackoverflow.com",
        "cloudflare.com",
        "akamai.net",
        "cloudfront.net",
        "amazonaws.com"
    )
    
    // Suspicious domain patterns
    private val suspiciousPatterns = listOf(
        Regex("^[a-f0-9]{32,}\\..*"), // Long hex strings
        Regex("^[a-z0-9]{20,}\\..*"), // Long alphanumeric strings
        Regex("^[a-z]{30,}\\..*"), // Long alphabetical strings
        Regex("^.*\\.[a-f0-9]{16,}$"), // Hex TLDs
        Regex("^.*\\.[a-z0-9]{20,}$") // Long alphanumeric TLDs
    )
    
    /**
     * Start DNS tunneling monitoring
     */
    fun startMonitoring(): Flow<ThreatAlert> = callbackFlow {
        _isMonitoring.value = true
        
        // In a real implementation, you would hook into DNS queries
        // For now, simulate monitoring with periodic analysis
        val analysisJob = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Default).launch {
            while (_isMonitoring.value) {
                delay(5000) // Analyze every 5 seconds
                performDNSAnalysis()
            }
        }
        
        awaitClose {
            analysisJob.cancel()
            _isMonitoring.value = false
        }
    }
    
    /**
     * Stop DNS tunneling monitoring
     */
    fun stopMonitoring() {
        _isMonitoring.value = false
    }
    
    /**
     * Record DNS query (simulated - in real implementation, hook into DNS)
     */
    fun recordDNSQuery(domain: String, queryType: String = "A", responseSize: Int = 0) {
        if (!_isMonitoring.value) return
        
        val query = DNSQuery(
            domain = domain,
            queryType = queryType,
            responseSize = responseSize,
            timestamp = System.currentTimeMillis()
        )
        
        queryHistory.offer(query)
        
        // Maintain history size
        while (queryHistory.size > maxHistorySize) {
            queryHistory.poll()
        }
        
        // Update domain frequency
        val baseDomain = extractBaseDomain(domain)
        domainFrequency[baseDomain] = domainFrequency.getOrDefault(baseDomain, 0) + 1
        
        // Update stats
        val currentStats = _dnsQueryStats.value
        val newStats = currentStats.copy(
            totalQueries = currentStats.totalQueries + 1,
            uniqueDomains = domainFrequency.size,
            lastUpdated = System.currentTimeMillis()
        )
        _dnsQueryStats.value = newStats
    }
    
    /**
     * Perform DNS analysis
     */
    private fun performDNSAnalysis() {
        if (queryHistory.size < 10) return
        
        val recentQueries = queryHistory.toList().takeLast(100)
        
        // Analyze for tunneling indicators
        val entropyAnalysis = analyzeQueryEntropy(recentQueries)
        val frequencyAnalysis = analyzeQueryFrequency(recentQueries)
        val lengthAnalysis = analyzeQueryLength(recentQueries)
        val patternAnalysis = analyzeSuspiciousPatterns(recentQueries)
        
        // Calculate overall tunneling probability
        val tunnelingProbability = calculateTunnelingProbability(
            entropyAnalysis,
            frequencyAnalysis,
            lengthAnalysis,
            patternAnalysis
        )
        
        if (tunnelingProbability > 0.7) { // 70% threshold
            val alert = DNSTunnelAlert(
                tunnelingProbability = tunnelingProbability,
                highEntropyQueries = entropyAnalysis.highEntropyCount,
                highFrequencyQueries = frequencyAnalysis.highFrequencyCount,
                longQueries = lengthAnalysis.longQueryCount,
                suspiciousPatterns = patternAnalysis.suspiciousPatternCount,
                sampleQueries = recentQueries.take(5).map { it.domain },
                timestamp = System.currentTimeMillis()
            )
            
            _detectedTunnels.value = _detectedTunnels.value + alert
            
            val threat = ThreatAlert(
                id = java.util.UUID.randomUUID().toString(),
                type = LogEventType.DNS_QUERY,
                category = ThreatCategory.DATA,
                severity = Severity.HIGH,
                riskScore = (tunnelingProbability * 100).toInt(),
                metadata = mapOf(
                    "event_type" to "dns_tunneling_detected",
                    "probability" to tunnelingProbability.toString(),
                    "high_entropy_count" to entropyAnalysis.highEntropyCount.toString(),
                    "high_frequency_count" to frequencyAnalysis.highFrequencyCount.toString(),
                    "long_query_count" to lengthAnalysis.longQueryCount.toString(),
                    "suspicious_pattern_count" to patternAnalysis.suspiciousPatternCount.toString()
                )
            )
            
            trySend(threat)
            
            forensicLogger.logEvent(
                eventType = LogEventType.DNS_QUERY,
                severity = Severity.HIGH,
                metadata = mapOf(
                    "event_type" to "dns_tunneling_detected",
                    "probability" to tunnelingProbability.toString(),
                    "high_entropy_count" to entropyAnalysis.highEntropyCount.toString(),
                    "high_frequency_count" to frequencyAnalysis.highFrequencyCount.toString(),
                    "long_query_count" to lengthAnalysis.longQueryCount.toString(),
                    "suspicious_pattern_count" to patternAnalysis.suspiciousPatternCount.toString()
                ),
                riskScore = (tunnelingProbability * 100).toInt()
            )
        }
    }
    
    /**
     * Analyze query entropy
     */
    private fun analyzeQueryEntropy(queries: List<DNSQuery>): EntropyAnalysis {
        var highEntropyCount = 0
        
        for (query in queries) {
            val subdomain = extractSubdomain(query.domain)
            val entropy = calculateShannonEntropy(subdomain)
            
            if (entropy > 3.5) { // High entropy threshold
                highEntropyCount++
            }
        }
        
        return EntropyAnalysis(
            highEntropyCount = highEntropyCount,
            averageEntropy = queries.map { calculateShannonEntropy(extractSubdomain(it.domain)) }.average()
        )
    }
    
    /**
     * Analyze query frequency
     */
    private fun analyzeQueryFrequency(queries: List<DNSQuery>): FrequencyAnalysis {
        val queryCount = queries.size
        val timeWindow = 5000 // 5 seconds
        val queriesPerSecond = queryCount.toDouble() / (timeWindow / 1000.0)
        
        val highFrequencyCount = if (queriesPerSecond > 10) queryCount else 0
        
        return FrequencyAnalysis(
            highFrequencyCount = highFrequencyCount,
            queriesPerSecond = queriesPerSecond
        )
    }
    
    /**
     * Analyze query length
     */
    private fun analyzeQueryLength(queries: List<DNSQuery>): LengthAnalysis {
        var longQueryCount = 0
        
        for (query in queries) {
            if (query.domain.length > 50) { // Long query threshold
                longQueryCount++
            }
        }
        
        return LengthAnalysis(
            longQueryCount = longQueryCount,
            averageLength = queries.map { it.domain.length }.average()
        )
    }
    
    /**
     * Analyze suspicious patterns
     */
    private fun analyzeSuspiciousPatterns(queries: List<DNSQuery>): PatternAnalysis {
        var suspiciousPatternCount = 0
        
        for (query in queries) {
            for (pattern in suspiciousPatterns) {
                if (pattern.matches(query.domain)) {
                    suspiciousPatternCount++
                    break
                }
            }
        }
        
        return PatternAnalysis(
            suspiciousPatternCount = suspiciousPatternCount
        )
    }
    
    /**
     * Calculate tunneling probability
     */
    private fun calculateTunnelingProbability(
        entropyAnalysis: EntropyAnalysis,
        frequencyAnalysis: FrequencyAnalysis,
        lengthAnalysis: LengthAnalysis,
        patternAnalysis: PatternAnalysis
    ): Double {
        var probability = 0.0
        
        // Entropy score (40% weight)
        val entropyScore = (entropyAnalysis.highEntropyCount / 100.0).coerceIn(0.0, 1.0)
        probability += entropyScore * 0.4
        
        // Frequency score (25% weight)
        val frequencyScore = if (frequencyAnalysis.queriesPerSecond > 10) {
            (frequencyAnalysis.queriesPerSecond / 50.0).coerceIn(0.0, 1.0)
        } else {
            0.0
        }
        probability += frequencyScore * 0.25
        
        // Length score (20% weight)
        val lengthScore = (lengthAnalysis.longQueryCount / 50.0).coerceIn(0.0, 1.0)
        probability += lengthScore * 0.2
        
        // Pattern score (15% weight)
        val patternScore = (patternAnalysis.suspiciousPatternCount / 20.0).coerceIn(0.0, 1.0)
        probability += patternScore * 0.15
        
        return probability.coerceIn(0.0, 1.0)
    }
    
    /**
     * Calculate Shannon entropy
     */
    private fun calculateShannonEntropy(input: String): Double {
        if (input.isEmpty()) return 0.0
        
        val frequency = mutableMapOf<Char, Int>()
        for (char in input) {
            frequency[char] = frequency.getOrDefault(char, 0) + 1
        }
        
        val length = input.length.toDouble()
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
     * Extract subdomain from domain
     */
    private fun extractSubdomain(domain: String): String {
        val parts = domain.split(".")
        return if (parts.size > 2) {
            parts.dropLast(2).joinToString(".")
        } else {
            ""
        }
    }
    
    /**
     * Extract base domain from domain
     */
    private fun extractBaseDomain(domain: String): String {
        val parts = domain.split(".")
        return if (parts.size >= 2) {
            parts.takeLast(2).joinToString(".")
        } else {
            domain
        }
    }
    
    /**
     * Check if domain is known safe
     */
    private fun isKnownSafeDomain(domain: String): Boolean {
        val baseDomain = extractBaseDomain(domain)
        return baseDomain in knownSafeDomains
    }
    
    /**
     * Get DNS query history
     */
    fun getQueryHistory(): List<DNSQuery> {
        return queryHistory.toList()
    }
    
    /**
     * Get domain frequency
     */
    fun getDomainFrequency(): Map<String, Int> {
        return domainFrequency.toMap()
    }
    
    /**
     * Clear history
     */
    fun clearHistory() {
        queryHistory.clear()
        domainFrequency.clear()
        _detectedTunnels.value = emptyList()
    }
}

// Data classes for DNS tunneling detection

data class DNSQuery(
    val domain: String,
    val queryType: String,
    val responseSize: Int,
    val timestamp: Long
)

data class DNSQueryStats(
    val totalQueries: Int = 0,
    val uniqueDomains: Int = 0,
    val lastUpdated: Long = System.currentTimeMillis()
)

data class DNSTunnelAlert(
    val tunnelingProbability: Double,
    val highEntropyQueries: Int,
    val highFrequencyQueries: Int,
    val longQueries: Int,
    val suspiciousPatterns: Int,
    val sampleQueries: List<String>,
    val timestamp: Long
)

data class EntropyAnalysis(
    val highEntropyCount: Int,
    val averageEntropy: Double
)

data class FrequencyAnalysis(
    val highFrequencyCount: Int,
    val queriesPerSecond: Double
)

data class LengthAnalysis(
    val longQueryCount: Int,
    val averageLength: Double
)

data class PatternAnalysis(
    val suspiciousPatternCount: Int
)
