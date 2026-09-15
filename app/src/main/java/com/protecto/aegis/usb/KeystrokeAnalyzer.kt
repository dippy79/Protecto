package com.protecto.aegis.usb

import android.hardware.usb.UsbDevice
import com.protecto.aegis.core.ForensicLogger
import com.protecto.aegis.core.LogEventType
import com.protecto.aegis.core.Severity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentLinkedQueue
import kotlin.math.abs
import kotlin.math.sqrt

/**
 * PROJECT AEGIS - Keystroke Microsecond Dynamics Analyzer
 * 
 * Advanced keystroke timing analysis to detect inhuman typing patterns
 * characteristic of BadUSB attacks and automated input devices.
 * 
 * Detection metrics:
 * - Jitter: Standard deviation of inter-key intervals (human: 5-20%, inhuman: <5%)
 * - Cadence: Words per minute burst detection (human: 40-80 WPM, inhuman: >200 WPM)
 * - Entropy: Randomness in key sequences (human: moderate, inhuman: zero/low)
 * 
 * Core Philosophy: DETECT → BLOCK → ISOLATE → RECORD → ANALYZE → ALERT → RECOVER
 */
class KeystrokeAnalyzer(private val forensicLogger: ForensicLogger) {
    
    // Circular buffer for keystroke events (keeps last 100 events)
    private val keystrokeBuffer = ConcurrentLinkedQueue<KeystrokeEvent>()
    private val maxBufferSize = 100
    
    private val _isMonitoring = MutableStateFlow(false)
    val isMonitoring: StateFlow<Boolean> = _isMonitoring.asStateFlow()
    
    private val _analysisResult = MutableStateFlow(KeystrokeAnalysisResult())
    val analysisResult: StateFlow<KeystrokeAnalysisResult> = _analysisResult.asStateFlow()
    
    private var currentDevice: UsbDevice? = null
    private var monitoringLevel = MonitoringLevel.STANDARD
    private var monitoringJob: kotlinx.coroutines.Job? = null
    
    // Analysis thresholds
    private val jitterThreshold = 0.05 // 5% jitter threshold
    private val wpmThreshold = 200 // WPM threshold for inhuman detection
    private val entropyThreshold = 0.1 // Minimum entropy threshold
    
    /**
     * Start standard keystroke monitoring
     */
    fun startMonitoring(device: UsbDevice) {
        if (_isMonitoring.value) return
        
        currentDevice = device
        monitoringLevel = MonitoringLevel.STANDARD
        _isMonitoring.value = true
        
        startAnalysisLoop()
    }
    
    /**
     * Start enhanced keystroke monitoring (for suspicious devices)
     */
    fun startEnhancedMonitoring(device: UsbDevice) {
        if (_isMonitoring.value) return
        
        currentDevice = device
        monitoringLevel = MonitoringLevel.ENHANCED
        _isMonitoring.value = true
        
        startAnalysisLoop()
    }
    
    /**
     * Stop keystroke monitoring
     */
    fun stopMonitoring() {
        _isMonitoring.value = false
        monitoringJob?.cancel()
        monitoringJob = null
        currentDevice = null
        keystrokeBuffer.clear()
        
        _analysisResult.value = KeystrokeAnalysisResult()
    }
    
    /**
     * Simulate keystroke event (in real implementation, this would come from InputManager)
     */
    fun recordKeystroke(keyCode: Int, timestamp: Long = System.nanoTime()) {
        if (!_isMonitoring.value) return
        
        val event = KeystrokeEvent(
            keyCode = keyCode,
            timestamp = timestamp,
            deviceId = currentDevice?.deviceId ?: 0
        )
        
        // Add to buffer
        keystrokeBuffer.offer(event)
        
        // Maintain buffer size
        while (keystrokeBuffer.size > maxBufferSize) {
            keystrokeBuffer.poll()
        }
    }
    
    /**
     * Start periodic analysis loop
     */
    private fun startAnalysisLoop() {
        monitoringJob = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Default).launch {
            while (_isMonitoring.value) {
                delay(1000) // Analyze every second
                
                if (keystrokeBuffer.size >= 10) { // Need minimum events for analysis
                    val result = performAnalysis()
                    _analysisResult.value = result
                    
                    // Check for threats
                    if (result.isSuspicious) {
                        handleSuspiciousActivity(result)
                    }
                }
            }
        }
    }
    
    /**
     * Perform comprehensive keystroke analysis
     */
    private fun performAnalysis(): KeystrokeAnalysisResult {
        val events = keystrokeBuffer.toList()
        if (events.size < 2) return KeystrokeAnalysisResult()
        
        // Calculate inter-key intervals
        val intervals = mutableListOf<Long>()
        for (i in 1 until events.size) {
            val interval = events[i].timestamp - events[i - 1].timestamp
            intervals.add(interval)
        }
        
        // Calculate jitter (standard deviation as percentage of mean)
        val jitter = calculateJitter(intervals)
        
        // Calculate typing cadence (WPM)
        val wpm = calculateWPM(events)
        
        // Calculate entropy
        val entropy = calculateEntropy(events)
        
        // Determine if suspicious
        val isSuspicious = when (monitoringLevel) {
            MonitoringLevel.STANDARD -> {
                jitter < jitterThreshold && wpm > wpmThreshold
            }
            MonitoringLevel.ENHANCED -> {
                jitter < jitterThreshold || wpm > wpmThreshold || entropy < entropyThreshold
            }
        }
        
        // Calculate overall risk score
        val riskScore = calculateRiskScore(jitter, wpm, entropy)
        
        return KeystrokeAnalysisResult(
            isSuspicious = isSuspicious,
            jitter = jitter,
            wpm = wpm,
            entropy = entropy,
            riskScore = riskScore,
            sampleSize = events.size,
            monitoringLevel = monitoringLevel,
            timestamp = System.currentTimeMillis()
        )
    }
    
    /**
     * Calculate jitter (coefficient of variation)
     */
    private fun calculateJitter(intervals: List<Long>): Double {
        if (intervals.isEmpty()) return 0.0
        
        val mean = intervals.average()
        if (mean == 0.0) return 0.0
        
        val variance = intervals.map { (it - mean).pow(2) }.average()
        val stdDev = sqrt(variance)
        
        return (stdDev / mean) // Coefficient of variation
    }
    
    /**
     * Calculate words per minute
     */
    private fun calculateWPM(events: List<KeystrokeEvent>): Double {
        if (events.size < 2) return 0.0
        
        val duration = (events.last().timestamp - events.first().timestamp) / 1_000_000_000.0 // Convert to seconds
        if (duration == 0.0) return 0.0
        
        val keystrokesPerSecond = events.size / duration
        val wordsPerMinute = (keystrokesPerSecond * 60) / 5.0 // Average 5 keystrokes per word
        
        return wordsPerMinute
    }
    
    /**
     * Calculate entropy of key sequence
     */
    private fun calculateEntropy(events: List<KeystrokeEvent>): Double {
        if (events.isEmpty()) return 0.0
        
        // Count frequency of each key
        val frequency = mutableMapOf<Int, Int>()
        for (event in events) {
            frequency[event.keyCode] = frequency.getOrDefault(event.keyCode, 0) + 1
        }
        
        // Calculate Shannon entropy
        val total = events.size.toDouble()
        var entropy = 0.0
        
        for (count in frequency.values) {
            val probability = count / total
            if (probability > 0) {
                entropy -= probability * kotlin.math.ln(probability) / kotlin.math.ln(2.0)
            }
        }
        
        // Normalize to 0-1 range
        val maxEntropy = kotlin.math.ln(frequency.size.toDouble()) / kotlin.math.ln(2.0)
        return if (maxEntropy > 0) entropy / maxEntropy else 0.0
    }
    
    /**
     * Calculate overall risk score based on metrics
     */
    private fun calculateRiskScore(jitter: Double, wpm: Double, entropy: Double): Int {
        var score = 0
        
        // Jitter score (lower jitter = higher risk)
        if (jitter < 0.02) score += 40
        else if (jitter < 0.05) score += 30
        else if (jitter < 0.10) score += 10
        
        // WPM score (higher WPM = higher risk)
        if (wpm > 300) score += 40
        else if (wpm > 200) score += 30
        else if (wpm > 150) score += 15
        
        // Entropy score (lower entropy = higher risk)
        if (entropy < 0.05) score += 20
        else if (entropy < 0.10) score += 10
        
        return score.coerceIn(0, 100)
    }
    
    /**
     * Handle suspicious keystroke activity
     */
    private fun handleSuspiciousActivity(result: KeystrokeAnalysisResult) {
        forensicLogger.logEvent(
            eventType = LogEventType.USB_SUSPICIOUS_ACTIVITY,
            severity = if (result.riskScore >= 70) Severity.HIGH else Severity.WARNING,
            metadata = mapOf(
                "device_id" to (currentDevice?.deviceId ?: 0),
                "device_name" to (currentDevice?.deviceName ?: "unknown"),
                "jitter" to result.jitter,
                "wpm" to result.wpm,
                "entropy" to result.entropy,
                "risk_score" to result.riskScore,
                "monitoring_level" to result.monitoringLevel.name
            ),
            riskScore = result.riskScore
        )
    }
    
    /**
     * Get current analysis result
     */
    fun getAnalysisResult(): KeystrokeAnalysisResult {
        return _analysisResult.value
    }
    
    /**
     * Clear keystroke buffer
     */
    fun clearBuffer() {
        keystrokeBuffer.clear()
    }
    
    /**
     * Get buffer statistics
     */
    fun getBufferStats(): BufferStats {
        return BufferStats(
            size = keystrokeBuffer.size,
            maxSize = maxBufferSize,
            utilization = keystrokeBuffer.size.toDouble() / maxBufferSize
        )
    }
    
    private fun Double.pow(exponent: Int): Double {
        return this.toDouble().let { base ->
            var result = 1.0
            repeat(exponent) { result *= base }
            result
        }
    }
}

// Data classes for keystroke analysis

data class KeystrokeEvent(
    val keyCode: Int,
    val timestamp: Long, // Nanosecond precision
    val deviceId: Int
)

data class KeystrokeAnalysisResult(
    val isSuspicious: Boolean = false,
    val jitter: Double = 0.0, // Coefficient of variation (0-1)
    val wpm: Double = 0.0, // Words per minute
    val entropy: Double = 0.0, // Normalized entropy (0-1)
    val riskScore: Int = 0, // 0-100
    val sampleSize: Int = 0,
    val monitoringLevel: MonitoringLevel = MonitoringLevel.STANDARD,
    val timestamp: Long = System.currentTimeMillis()
)

data class BufferStats(
    val size: Int,
    val maxSize: Int,
    val utilization: Double
)

enum class MonitoringLevel {
    STANDARD,
    ENHANCED
}
