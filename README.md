# Dexel-Network-Scanner


# DNMAP - Dexel Network Scanner

[![Version](https://img.shields.io/badge/version-1.0-blue.svg)](https://github.com/yourusername/dnmap)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Termux-orange.svg)](https://termux.com/)
[![Bash](https://img.shields.io/badge/bash-4.0%2B-red.svg)](https://www.gnu.org/software/bash/)

**DNMAP** adalah tool scanner jaringan canggih yang dirancang khusus untuk Termux. Tool ini menyediakan berbagai fitur untuk analisis keamanan jaringan, pemantauan, dan penilaian infrastruktur network.

## 🚀 Fitur Utama

### 🔍 Network Discovery & Scanning
- **Network Scan**: Deteksi perangkat aktif dalam jaringan
- **Ping Host**: Test konektivitas ke host tertentu
- **Port Scan**: Scanning port dengan berbagai metode
- **Advanced Scan**: Deteksi OS dan enumerasi service
- **Vulnerability Scan**: Assessment keamanan dasar

### 🔬 Network Analysis
- **DNS Lookup**: Resolusi domain dan record DNS
- **Network Monitor**: Monitoring host secara real-time
- **MAC Lookup**: Identifikasi vendor dari MAC address
- **Traceroute**: Pelacakan jalur network ke destination

### 💻 System & Information
- **Interface Info**: Informasi detail interface jaringan
- **Port Listener**: Testing konektivitas port
- **WiFi Scan**: Scanning jaringan wireless
- **System Info**: Informasi sistem dan konfigurasi

### 📊 Logging & Monitoring
- **Advanced Logging**: Sistem logging komprehensif
- **Scan Results**: Penyimpanan hasil scan otomatis
- **Log Viewer**: Interface untuk viewing log files
- **Configuration Management**: Manajemen konfigurasi otomatis

## 📋 Persyaratan

### Sistem Minimum
- **Platform**: Android dengan Termux
- **Bash**: Version 4.0 atau lebih tinggi
- **Storage**: Minimal 100MB free space
- **Network**: Koneksi internet untuk instalasi tools

### Dependencies
Tool ini akan otomatis menginstal dependencies berikut:
- `nmap` - Network discovery dan port scanning
- `ping` - Network connectivity testing
- `curl` - HTTP client untuk lookups
- `wget` - File download utility
- `netcat` - Network utility
- `dig` - DNS lookup tool
- `traceroute` - Network path tracing

## 🛠️ Instalasi

### 1. Persiapan Termux
```bash
# Update package list
pkg update && pkg upgrade

# Install git (jika belum ada)
pkg install git

# Clone repository
git clone https://github.com/yourusername/dnmap.git
cd dnmap

# Berikan permission execute
chmod +x dnmap.sh
```

### 2. Menjalankan DNMAP
```bash
# Jalankan script
./dnmap.sh
```

### 3. Instalasi Otomatis
Pada first run, DNMAP akan:
- Mengecek dan menginstal semua dependencies
- Mendeteksi konfigurasi jaringan
- Membuat direktori log dan konfigurasi
- Menyiapkan environment yang diperlukan

## 📖 Panduan Penggunaan

### Main Menu Options

#### 1. Network Scan
Melakukan discovery perangkat aktif dalam jaringan:
```
Target: 192.168.1.0/24
Output: Daftar IP, hostname, MAC address, dan vendor
```

#### 2. Ping Host
Test konektivitas ke host tertentu:
```
Input: IP address atau hostname
Options: Jumlah ping packets
Output: Response time dan packet loss
```

#### 3. Port Scan
Scanning port dengan berbagai metode:
- **Quick Scan**: Top 100 ports
- **Common Ports**: Top 1000 ports
- **Full Scan**: All ports (1-65535)
- **Custom Range**: Port range kustom
- **Service Detection**: Deteksi service version

#### 4. Advanced Scan
Scanning lanjutan dengan fitur:
- **OS Detection**: Identifikasi operating system
- **Service Version**: Deteksi versi service
- **Aggressive Scan**: Comprehensive scanning
- **Stealth Scan**: Low-profile scanning

#### 5. Vulnerability Scan
Assessment keamanan dasar menggunakan NSE scripts

#### 6. DNS Lookup
Resolusi DNS dengan berbagai record types:
- A Record (IPv4)
- AAAA Record (IPv6)
- MX Record (Mail Exchange)
- NS Record (Name Server)
- TXT Record
- All Records

#### 7. Network Monitor
Monitoring host secara real-time:
- Continuous ping monitoring
- Uptime/downtime tracking
- Alert system untuk consecutive failures
- Logging otomatis

#### 8. MAC Lookup
Identifikasi vendor dari MAC address:
- OUI (Organizationally Unique Identifier) lookup
- Vendor information
- Address type analysis

#### 9. Traceroute
Pelacakan jalur network:
- ICMP traceroute
- UDP traceroute
- TCP traceroute
- Hop-by-hop analysis

#### 10. Interface Info
Informasi detail interface jaringan:
- Network interfaces
- IP addresses
- Routing table
- Network statistics

#### 11. Port Listener
Testing konektivitas port:
- Port connectivity check
- Local port listener
- Banner grabbing

#### 12. WiFi Scan
Scanning jaringan wireless (jika mendukung):
- Available networks
- Signal strength
- Security information

#### 13. View Logs
Interface untuk viewing log files:
- Recent logs
- Scan results
- Monitoring logs
- Log search

#### 14. System Info
Informasi sistem dan konfigurasi:
- System details
- Network configuration
- Resource usage
- DNMAP information

## 📁 Struktur Direktori

```
/data/data/com.termux/files/home/
├── dnmap_logs/                 # Log directory
│   ├── dnmap_YYYYMMDD.log     # Daily logs
│   ├── scans/                 # Scan results
│   ├── port_scans/            # Port scan results
│   ├── advanced_scans/        # Advanced scan results
│   ├── vuln_scans/            # Vulnerability scan results
│   ├── monitoring/            # Monitoring logs
│   └── traceroute/            # Traceroute results
├── .dnmap_config              # Configuration file
└── /tmp/                      # Temporary files
```

## ⚙️ Konfigurasi

### Configuration File
DNMAP menyimpan konfigurasi di `~/.dnmap_config`:
```bash
# Network Settings
DEFAULT_NETWORK="192.168.1.0/24"
DEFAULT_IP="192.168.1.100"

# Scan Settings
DEFAULT_SCAN_TIMEOUT=30
DEFAULT_PING_COUNT=4
DEFAULT_PORT_RANGE="1-1000"

# Logging
LOG_LEVEL="INFO"
MAX_LOG_SIZE=10485760
```

### Customization
Anda dapat memodifikasi konfigurasi dengan:
1. Edit file konfigurasi langsung
2. Gunakan menu system untuk setting
3. Modify variable dalam script

## 🔧 Troubleshooting

### Common Issues

#### 1. Permission Denied
```bash
# Solution
chmod +x dnmap.sh
```

#### 2. Tools Not Found
```bash
# Manual installation
pkg install nmap curl wget netcat-openbsd dnsutils
```

#### 3. Network Detection Failed
```bash
# Manual IP configuration
export LOCAL_IP="192.168.1.100"
export NETWORK="192.168.1.0/24"
```

#### 4. Log Directory Issues
```bash
# Create log directory manually
mkdir -p /data/data/com.termux/files/home/dnmap_logs
```

## 📊 Stats

- **Lines of Code**: 1000+
- **Functions**: 20+
- **Scan Types**: 10+
- **Log Categories**: 5+
- **Supported Platforms**: Termux/Android

---

**DNMAP** - *Advanced Network Scanner Tool for Termux*

Made with ❤️ by Dexel Network Scanner Team

*"Empowering network security professionals with advanced scanning capabilities"*
