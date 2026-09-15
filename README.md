# PROJECT AEGIS

**Advanced Android Defensive Security Platform**

## 🛡️ Core Philosophy
**DETECT → BLOCK → ISOLATE → RECORD → ANALYZE → ALERT → RECOVER**

- NO offensive operations
- NO hacking back
- NO attacking the attacker
- Purely defensive: detection, blocking, isolation, forensic analysis

## 🏗️ Architecture

PROJECT AEGIS is designed in 4 layers:

### Layer 1: Application Layer
- Security Dashboard with real-time monitoring
- Zero-Trust UI Obscuration
- Alerts and Incident History
- Quick action controls

### Layer 2: Service Layer
- AegisSecurityService (Privileged system service)
- USBGuardian 2.0 (Physical & Hardware Defense)
- WirelessGuardian 2.0 (Spectrum Defense)
- ExfilGuard 2.0 (Data & Covert Channel Defense)
- AppRiskEngine 2.0 (App Forensics)

### Layer 3: Framework Layer
- Hooks into UsbManager, ConnectivityManager, DevicePolicyManager
- ActivityManager and PackageManager monitoring
- Accessibility service abuse detection

### Layer 4: Kernel/OS Layer
- eBPF integration for system call monitoring
- Binder IPC monitoring for lateral movement detection
- Hardware-backed Keystore for cryptographic operations
- Merkle Tree snapshots for integrity verification

## 🎯 Threat Detection Engines

### USBGuardian 2.0
- **Standard Detection**: Unknown HID, BadUSB, unauthorized ADB/MTP
- **Advanced Detection**: 
  - Keystroke Microsecond Dynamics (jitter < 5%, WPM > 200)
  - USB-C Power Delivery attack detection
  - Composite interface fuzzing detection

### WirelessGuardian 2.0
- **Standard Detection**: Evil twins, rogue Bluetooth, unauthorized VPNs
- **Advanced Detection**:
  - Cellular downgrade detection (5G/4G → 2G = IMSI catchers)
  - BSSID Historical Profiling (WiFi spoofing detection)
  - Spectrum anomaly detection

### ExfilGuard 2.0
- **Standard Detection**: Volume spikes, suspicious IP routing
- **Advanced Detection**:
  - DNS Tunneling detection (entropy/frequency analysis)
  - JA3/JA3S TLS Fingerprinting (malware HTTP libraries)
  - Covert channel detection

### AppRiskEngine 2.0
- **Standard Detection**: APK metadata, accessibility abuse, device-admin abuse
- **Advanced Detection**:
  - TFLite memory-map analysis
  - Packer/obfuscator entropy detection
  - Fileless malware indicators (memfd/ptrace abuse)

## 🚨 Incident Response

### Dead Man's Switch (Lockdown Mode)
- Trigger: CRITICAL physical risk
- Actions:
  - Zero-Trust UI Obscuration (dim screen)
  - Disable biometrics
  - Force alphanumeric PIN
  - Block all USB devices
  - Lock device admin functions

### Faraday Mode
- Trigger: CRITICAL wireless risk
- Actions:
  - Deploy null-routed local VPN
  - Blackhole all outbound traffic
  - Disable WiFi/Bluetooth
  - Force cellular only
  - Block network changes

### Clean Room Baselines
- Pre-service cryptographic snapshot
- Post-service cryptographic snapshot
- Merkle tree comparison
- Drift delta calculation (supply-chain tampering detection)

## 🔐 Security Features

### Hash-Chained Forensic Logging
- Each log entry includes previous hash (tamper-evident chain)
- Hardware-backed Keystore signing
- Cryptographic log sealing
- Immutable timeline with event IDs, timestamps, metadata

### Merkle Tree System Snapshots
- Cryptographic snapshots of system directories
- Root hash calculation for integrity verification
- Drift delta calculation for tampering detection
- Supply-chain attack identification

### Hardware-Backed Cryptography
- AES-GCM encryption (256-bit keys)
- ECDSA digital signatures
- Hardware security verification
- Key access control

## 📱 Requirements

- **Minimum**: Android 7.0 (API 24)
- **Recommended**: Android 14 (API 34)
- **Root**: Optional (for eBPF hooks)
- **Hardware**: Hardware-backed Keystore recommended

## 🚀 Building

```bash
# Clone the repository
git clone <repository-url>
cd Protecto

# Build the project
./gradlew assembleDebug

# Install on device
./gradlew installDebug
```

## 📁 Project Structure

```
app/src/main/java/com/protecto/aegis/
├── core/                          # Core security components
│   ├── AegisSecurityService.kt   # Main security service
│   ├── ForensicLogger.kt         # Hash-chained logging
│   ├── KeystoreManager.kt        # Hardware-backed crypto
│   └── MerkleTreeSnapshot.kt     # System integrity
├── usb/                           # USB security
│   ├── USBGuardian.kt            # USB monitoring
│   ├── KeystrokeAnalyzer.kt      # Microsecond dynamics
│   └── USBDeviceManager.kt       # Device enumeration
├── wireless/                      # Wireless security
│   ├── WirelessGuardian.kt       # Network monitoring
│   ├── CellularDowngradeDetector.kt  # IMSI catcher detection
│   └── BSSIDProfiler.kt          # WiFi profiling
├── exfil/                         # Data exfiltration
│   ├── ExfilGuard.kt             # Exfiltration detection
│   ├── DNSTunnelingDetector.kt   # DNS tunneling
│   └── TLSFingerprinter.kt       # TLS fingerprinting
├── app/                           # App security
│   ├── AppRiskEngine.kt          # App forensics
│   ├── APKAnalyzer.kt            # APK analysis
│   └── AccessibilityAbuseDetector.kt  # Accessibility abuse
├── response/                      # Incident response
│   ├── DeadMansSwitch.kt         # Lockdown mode
│   ├── FaradayMode.kt            # Network isolation
│   ├── IncidentResponder.kt      # Response automation
│   └── DeviceAdminReceiver.kt    # Device admin
└── ui/                            # User interface
    ├── dashboard/                 # Main dashboard
    │   └── DashboardScreen.kt
    └── components/               # UI components
        ├── RiskScoreCard.kt
        └── QuickActions.kt
```

## 🔧 Configuration

### Required Permissions
The app requires the following permissions (see AndroidManifest.xml):
- USB monitoring (USB_HOST, USB_DEVICE)
- Network monitoring (ACCESS_NETWORK_STATE, CHANGE_NETWORK_STATE)
- Cellular monitoring (READ_PHONE_STATE, ACCESS_FINE_LOCATION)
- App analysis (PACKAGE_USAGE_STATS, GET_PACKAGE_SIZE)
- Accessibility monitoring (BIND_ACCESSIBILITY_SERVICE)
- Device admin (BIND_DEVICE_ADMIN)
- And more...

### Service Configuration
- Foreground service for continuous monitoring
- VPN service for Faraday Mode
- Accessibility service for abuse detection
- Device admin receiver for incident response

## 🎨 UI Features

### Dashboard
- Real-time risk score display
- Threat engine status cards
- Recent incidents list
- Quick action buttons
- System integrity indicators

### Material Design 3
- Dark theme optimized for security
- Color-coded severity levels
- Responsive layouts
- Accessible components

## 🔬 Advanced Detection Algorithms

### Keystroke Microsecond Dynamics
- Jitter calculation (coefficient of variation)
- Typing cadence analysis (WPM burst detection)
- Entropy calculation (sequential vs random patterns)
- Risk scoring based on inhuman characteristics

### DNS Tunneling Detection
- Shannon entropy analysis of DNS queries
- Query frequency monitoring
- Suspicious pattern matching
- Domain length analysis

### TLS Fingerprinting
- JA3 fingerprint calculation
- JA3S fingerprint calculation
- Malware signature matching
- Cipher suite analysis

## 📊 Forensic Logging

### Log Entry Structure
```kotlin
data class ForensicLogEntry(
    val eventId: String,              // UUID v4
    val timestamp: Long,               // Unix epoch milliseconds
    val eventType: LogEventType,       // Event type
    val severity: Severity,            // INFO, WARNING, HIGH, CRITICAL
    val metadata: Map<String, Any>,    // Event-specific data
    val riskScore: Int,                // 0-100
    val previousHash: String,          // Previous entry's SHA-256
    val currentHash: String,           // Current entry's SHA-256
    val signature: String,            // Hardware-backed signature
    val integrityVerified: Boolean    // Chain integrity check
)
```

### Chain Integrity
- Each entry contains hash of previous entry
- Creates tamper-evident chain
- Verified using hardware-backed signatures
- Detects any log tampering

## 🛡️ Security Best Practices

1. **Hardware-Backed Crypto**: All cryptographic operations use Android Keystore
2. **Hash-Chained Logs**: Tamper-evident forensic logging
3. **Merkle Tree Snapshots**: System integrity verification
4. **Zero-Trust Architecture**: No implicit trust, continuous verification
5. **Defense in Depth**: Multiple detection layers
6. **Privacy Preservation**: Local processing only
7. **Anti-Tampering**: Code obfuscation, integrity checks

## 🚦 System States

- **IDLE**: Not monitoring
- **MONITORING**: Active threat detection
- **LOCKDOWN**: Dead Man's Switch active
- **FARADAY**: Faraday Mode active
- **SCANNING**: Full system scan in progress

## 📈 Risk Scoring

- **0-20**: SAFE - System secure
- **20-40**: LOW - Normal monitoring
- **40-60**: MEDIUM - Monitor closely
- **60-80**: HIGH - Review threats
- **80-100**: CRITICAL - Immediate action required

## 🔍 Detection Engines Status

Each engine reports:
- State (ACTIVE, IDLE, ERROR)
- Active threats count
- Last scan timestamp
- Performance metrics

## 📝 Logging Levels

- **INFO**: Normal operations
- **WARNING**: Suspicious activity
- **HIGH**: Significant threat detected
- **CRITICAL**: Emergency response triggered

## 🔄 Response Matrix

| Category | Severity | Response |
|----------|----------|----------|
| PHYSICAL | CRITICAL | Dead Man's Switch |
| WIRELESS | CRITICAL | Faraday Mode |
| DATA | HIGH | Traffic blocking |
| DATA | CRITICAL | Faraday Mode |
| APP | HIGH | App quarantine |
| APP | CRITICAL | Dead Man's Switch |
| SYSTEM | HIGH | Partial lockdown |
| SYSTEM | CRITICAL | Full lockdown |

## 🛠️ Dependencies

- AndroidX Compose (UI)
- Room (Database)
- Kotlin Coroutines (Async)
- TensorFlow Lite (ML detection)
- Android Biometric (Biometrics)
- Android Security Crypto (Encryption)
- Material Design 3 (UI components)

## 📄 License

This project is for educational and defensive security research purposes only.

## ⚠️ Disclaimer

PROJECT AEGIS is designed for defensive security purposes only. It should not be used for any offensive operations. The developers are not responsible for misuse of this software.

## 🤝 Contributing

This is a defensive security research project. Contributions should focus on improving detection capabilities and defensive measures.

## 📧 Contact

For security research collaboration, please use the project issue tracker.

---

**PROJECT AEGIS - Advanced Android Defensive Security Platform**

*Core Philosophy: DETECT → BLOCK → ISOLATE → RECORD → ANALYZE → ALERT → RECOVER*
