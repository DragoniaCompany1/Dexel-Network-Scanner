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
# Jalankan script bash dnmap.sh
```

### 3. Instalasi Otomatis
Pada first run, DNMAP akan:
- Mengecek dan menginstal semua dependencies
- Mendeteksi konfigurasi jaringan
- Membuat direktori log dan konfigurasi
- Menyiapkan environment yang diperlukan

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
