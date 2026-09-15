package com.protecto.aegis.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * PROJECT AEGIS - Risk Score Card Component
 * 
 * Displays the overall security risk score with visual indicators
 * and color-coded severity levels.
 * 
 * Core Philosophy: DETECT → BLOCK → ISOLATE → RECORD → ANALYZE → ALERT → RECOVER
 */
@Composable
fun RiskScoreCard(
    riskScore: Int,
    modifier: Modifier = Modifier,
    showTrend: Boolean = false,
    trend: Int = 0 // Positive = increasing risk, Negative = decreasing
) {
    val (scoreColor, statusText, statusColor) = when {
        riskScore >= 80 -> Triple(
            Color(0xFFFF5252),
            "CRITICAL",
            Color(0xFFFFCDD2)
        )
        riskScore >= 60 -> Triple(
            Color(0xFFFF9800),
            "HIGH",
            Color(0xFFFFE0B2)
        )
        riskScore >= 40 -> Triple(
            Color(0xFFFFEB3B),
            "MEDIUM",
            Color(0xFFFFF9C4)
        )
        riskScore >= 20 -> Triple(
            Color(0xFF8BC34A),
            "LOW",
            Color(0xFFDCEDC8)
        )
        else -> Triple(
            Color(0xFF4CAF50),
            "SAFE",
            Color(0xFFC8E6C9)
        )
    }
    
    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = statusColor
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        "Security Risk Score",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    
                    if (showTrend) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.padding(top = 4.dp)
                        ) {
                            val trendColor = if (trend > 0) Color.Red else Color(0xFF4CAF50)
                            val trendIcon = if (trend > 0) "↑" else "↓"
                            Text(
                                "$trendIcon ${kotlin.math.abs(trend)}%",
                                style = MaterialTheme.typography.bodySmall,
                                color = trendColor,
                                fontWeight = FontWeight.Medium
                            )
                            Text(
                                " from last scan",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
                
                Box(
                    modifier = Modifier
                        .size(100.dp)
                        .background(
                            color = scoreColor,
                            shape = RoundedCornerShape(50.dp)
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            text = "$riskScore",
                            style = MaterialTheme.typography.headlineMedium,
                            fontWeight = FontWeight.Bold,
                            color = Color.White,
                            fontSize = 36.sp
                        )
                        Text(
                            "/100",
                            style = MaterialTheme.typography.bodySmall,
                            color = Color.White.copy(alpha = 0.8f)
                        )
                    }
                }
            }
            
            Spacer(modifier = Modifier.height(16.dp))
            
            LinearProgressIndicator(
                progress = riskScore / 100f,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(8.dp),
                color = scoreColor,
                trackColor = MaterialTheme.colorScheme.surface
            )
            
            Spacer(modifier = Modifier.height(12.dp))
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    statusText,
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                    color = scoreColor
                )
                
                Text(
                    getRiskDescription(riskScore),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
fun MiniRiskScoreCard(
    riskScore: Int,
    modifier: Modifier = Modifier
) {
    val scoreColor = when {
        riskScore >= 80 -> Color(0xFFFF5252)
        riskScore >= 60 -> Color(0xFFFF9800)
        riskScore >= 40 -> Color(0xFFFFEB3B)
        riskScore >= 20 -> Color(0xFF8BC34A)
        else -> Color(0xFF4CAF50)
    }
    
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .background(
                        color = scoreColor,
                        shape = RoundedCornerShape(20.dp)
                    ),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = "$riskScore",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = Color.White
                )
            }
            
            Spacer(modifier = Modifier.width(12.dp))
            
            Column {
                Text(
                    "Risk Score",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    getRiskDescription(riskScore),
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium
                )
            }
        }
    }
}

private fun getRiskDescription(riskScore: Int): String {
    return when {
        riskScore >= 80 -> "Immediate action required"
        riskScore >= 60 -> "High risk - review threats"
        riskScore >= 40 -> "Moderate risk - monitor closely"
        riskScore >= 20 -> "Low risk - normal monitoring"
        else -> "System secure - no threats detected"
    }
}
