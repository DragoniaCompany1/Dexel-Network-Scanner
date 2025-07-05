#!/bin/bash

# DNMAP - Dexel Network Scanner
# Advanced Network Scanner Tool for Termux
# Author: Dexel Network Scanner
# Version: 1.0
# Release Date: 2025-07-05

# Script configuration
SCRIPT_NAME="DNMAP"
SCRIPT_VERSION="1.0"
SCRIPT_AUTHOR="Dexel Network Scanner"
SCRIPT_DESC="Advanced Network Scanner Tool for Termux"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m' # No Color

# Global variables
LOCAL_IP=""
NETWORK=""
LOG_DIR="/data/data/com.termux/files/home/dnmap_logs"
CONFIG_FILE="/data/data/com.termux/files/home/.dnmap_config"
TEMP_DIR="/data/data/com.termux/files/tmp"

set -e
trap 'error_handler $? $LINENO' ERR

error_handler() {
    local exit_code=$1
    local line_number=$2
    echo -e "${RED}[ERROR] Script failed at line $line_number with exit code $exit_code${NC}"
    echo -e "${YELLOW}[INFO] Please check the error and try again${NC}"
    exit $exit_code
}

log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    mkdir -p "$LOG_DIR"
    
    # Log file
    echo "[$timestamp] [$level] $message" >> "$LOG_DIR/dnmap_$(date +%Y%m%d).log"
    
    case $level in
        "INFO")
            echo -e "${BLUE}[INFO] $message${NC}"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[SUCCESS] $message${NC}"
            ;;
        "WARNING")
            echo -e "${YELLOW}[WARNING] $message${NC}"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR] $message${NC}"
            ;;
        "DEBUG")
            echo -e "${PURPLE}[DEBUG] $message${NC}"
            ;;
        *)
            echo -e "${WHITE}[$level] $message${NC}"
            ;;
    esac
}

# Banner
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                    DNMAP - DEXEL NETWORK SCANNER             ║"
    echo "║                      Advanced Network Tool                   ║"
    echo "║                        for Termux v1.0                      ║"
    echo "║                                                             ║"
    echo "║  Professional Network Scanning & Security Assessment Tool   ║"
    echo "║                                                             ║"
    echo "║  Author: $SCRIPT_AUTHOR                        ║"
    echo "║  Version: $SCRIPT_VERSION                                           ║"
    echo "║  Release: $(date +%Y-%m-%d)                                    ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
        log_message "INFO" "Configuration loaded from $CONFIG_FILE"
    else
        log_message "INFO" "No configuration file found, using defaults"
    fi
}

save_config() {
    cat > "$CONFIG_FILE" << EOF
# DNMAP Configuration File
# Generated on $(date)

# Network Settings
DEFAULT_NETWORK="$NETWORK"
DEFAULT_IP="$LOCAL_IP"

# Scan Settings
DEFAULT_SCAN_TIMEOUT=30
DEFAULT_PING_COUNT=4
DEFAULT_PORT_RANGE="1-1000"

# Logging
LOG_LEVEL="INFO"
MAX_LOG_SIZE=10485760  # 10MB
EOF
    log_message "SUCCESS" "Configuration saved to $CONFIG_FILE"
}

check_tools() {
    log_message "INFO" "Checking system requirements and tools..."
    
    log_message "INFO" "Updating package list..."
    if pkg update -y &>/dev/null; then
        log_message "SUCCESS" "Package list updated successfully"
    else
        log_message "WARNING" "Package list update failed"
    fi
    
    log_message "INFO" "Upgrading system packages..."
    if pkg upgrade -y &>/dev/null; then
        log_message "SUCCESS" "System packages upgraded successfully"
    else
        log_message "WARNING" "System upgrade failed"
    fi
    
    local tools=("nmap" "ping" "curl" "wget" "nc" "dig" "traceroute")
    local packages=("nmap" "iputils" "curl" "wget" "netcat-openbsd" "dnsutils" "traceroute")
    
    for i in "${!tools[@]}"; do
        local tool="${tools[$i]}"
        local package="${packages[$i]}"
        
        if ! command -v "$tool" &>/dev/null; then
            log_message "WARNING" "$tool not found. Installing $package..."
            if pkg install "$package" -y &>/dev/null; then
                log_message "SUCCESS" "$package installed successfully"
            else
                log_message "ERROR" "Failed to install $package"
            fi
        else
            log_message "SUCCESS" "$tool is already installed"
        fi
    done
    
    log_message "INFO" "Installing additional network tools..."
    local additional_tools=("net-tools" "procps" "grep" "sed" "awk")
    
    for tool in "${additional_tools[@]}"; do
        if pkg install "$tool" -y &>/dev/null; then
            log_message "SUCCESS" "$tool installed/updated"
        else
            log_message "WARNING" "Failed to install $tool"
        fi
    done
    
    log_message "SUCCESS" "All required tools are ready!"
}

get_network_info() {
    log_message "INFO" "Detecting network configuration..."
    
    if command -v ip &>/dev/null; then
        LOCAL_IP=$(ip route get 8.8.8.8 2>/dev/null | grep -oE 'src [0-9.]+' | cut -d' ' -f2)
        if [ -n "$LOCAL_IP" ]; then
            log_message "SUCCESS" "IP detected using 'ip route': $LOCAL_IP"
        fi
    fi
    
    if [ -z "$LOCAL_IP" ] && command -v ifconfig &>/dev/null; then
        LOCAL_IP=$(ifconfig 2>/dev/null | grep -E 'inet.*192\.168\.|inet.*10\.|inet.*172\.' | head -1 | awk '{print $2}' | cut -d':' -f2)
        if [ -n "$LOCAL_IP" ]; then
            log_message "SUCCESS" "IP detected using 'ifconfig': $LOCAL_IP"
        fi
    fi
    
    if [ -z "$LOCAL_IP" ] && command -v hostname &>/dev/null; then
        LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
        if [ -n "$LOCAL_IP" ]; then
            log_message "SUCCESS" "IP detected using 'hostname': $LOCAL_IP"
        fi
    fi
    
    if [ -z "$LOCAL_IP" ] && command -v curl &>/dev/null; then
        LOCAL_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s icanhazip.com 2>/dev/null)
        if [ -n "$LOCAL_IP" ]; then
            log_message "WARNING" "Using external IP (no local IP found): $LOCAL_IP"
        fi
    fi
    
    if [ -z "$LOCAL_IP" ]; then
        LOCAL_IP="192.168.1.100"
        log_message "WARNING" "Could not detect IP, using default: $LOCAL_IP"
    fi
    
    NETWORK=$(echo "$LOCAL_IP" | cut -d'.' -f1-3).0/24
    
    log_message "SUCCESS" "Network configuration detected:"
    echo -e "${GREEN}    Local IP: $LOCAL_IP${NC}"
    echo -e "${GREEN}    Network Range: $NETWORK${NC}"
    echo ""
}

validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}

validate_port_range() {
    local range=$1
    if [[ $range =~ ^[0-9]+-[0-9]+$ ]] || [[ $range =~ ^[0-9]+$ ]]; then
        return 0
    else
        return 1
    fi
}

scan_network() {
    log_message "INFO" "Starting network discovery scan..."
    echo -e "${CYAN}[SCAN] Scanning network for active devices...${NC}"
    echo -e "${YELLOW}Target network: $NETWORK${NC}"
    echo "This may take a few minutes..."
    echo ""
    
    if ! command -v nmap &>/dev/null; then
        log_message "ERROR" "nmap not found. Please install it first."
        return 1
    fi
    
    local results_dir="$LOG_DIR/scans"
    mkdir -p "$results_dir"
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local scan_file="$results_dir/network_scan_$timestamp.txt"
    
    log_message "INFO" "Scanning $NETWORK for active hosts..."
    echo -e "${YELLOW}[PROGRESS] Scanning in progress...${NC}"
    
    if nmap -sn -T4 --min-rate 1000 "$NETWORK" 2>/dev/null > "$scan_file"; then
        log_message "SUCCESS" "Network scan completed successfully"
    else
        log_message "ERROR" "Network scan failed"
        return 1
    fi
    
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}                    ACTIVE DEVICES FOUND                    ${NC}"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════${NC}"
    
    local device_count=0
    local scan_results=""
    
    while IFS= read -r line; do
        if [[ $line == *"Nmap scan report"* ]]; then
            if [[ $line == *"("* ]] && [[ $line == *")"* ]]; then
                
                local hostname=$(echo "$line" | sed 's/Nmap scan report for //' | sed 's/ (.*//')
                local ip=$(echo "$line" | grep -oE '\([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\)' | tr -d '()')
                echo -e "${GREEN}[+] Device: $hostname ($ip)${NC}"
                scan_results+="$hostname ($ip)\n"
            else
                
                local ip=$(echo "$line" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
                echo -e "${GREEN}[+] Device: $ip${NC}"
                scan_results+="$ip\n"
            fi
            ((device_count++))
        elif [[ $line == *"MAC Address"* ]]; then
            
            local mac=$(echo "$line" | grep -oE '([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})')
            local vendor=$(echo "$line" | sed 's/.*(//' | sed 's/).*//')
            echo -e "${BLUE}    MAC: $mac${NC}"
            if [ -n "$vendor" ]; then
                echo -e "${BLUE}    Vendor: $vendor${NC}"
            fi
            echo ""
        fi
    done < "$scan_file"
    
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}[SUMMARY] Total devices found: $device_count${NC}"
    echo -e "${CYAN}[INFO] Scan results saved to: $scan_file${NC}"
    
    echo -e "Network Scan Summary - $(date)\n" > "$results_dir/scan_summary_$timestamp.txt"
    echo -e "Network: $NETWORK" >> "$results_dir/scan_summary_$timestamp.txt"
    echo -e "Total devices found: $device_count\n" >> "$results_dir/scan_summary_$timestamp.txt"
    echo -e "Active devices:\n$scan_results" >> "$results_dir/scan_summary_$timestamp.txt"
    
    log_message "SUCCESS" "Network scan completed. Found $device_count active devices."
    echo ""
}

ping_host() {
    echo -e "${YELLOW}Enter IP address or hostname to ping:${NC}"
    read -p "Target: " target
    
    if [ -z "$target" ]; then
        log_message "ERROR" "Please enter a valid target"
        return 1
    fi
    
    echo -e "${YELLOW}Enter number of pings (default: 4):${NC}"
    read -p "Count: " ping_count
    ping_count=${ping_count:-4}
    
    if ! [[ "$ping_count" =~ ^[0-9]+$ ]]; then
        log_message "ERROR" "Invalid ping count. Using default: 4"
        ping_count=4
    fi
    
    log_message "INFO" "Pinging $target with $ping_count packets..."
    echo -e "${CYAN}[PING] Pinging $target...${NC}"
    echo "Press Ctrl+C to stop"
    echo ""
    
    local ping_results
    if ping_results=$(ping -c "$ping_count" "$target" 2>&1); then
        echo "$ping_results"
        
        local packet_loss=$(echo "$ping_results" | grep -oE '[0-9]+% packet loss' | cut -d'%' -f1)
        local avg_time=$(echo "$ping_results" | grep -oE 'avg = [0-9.]+' | cut -d'=' -f2 | tr -d ' ')
        
        if [ -n "$packet_loss" ]; then
            if [ "$packet_loss" -eq 0 ]; then
                log_message "SUCCESS" "Host $target is reachable (0% packet loss)"
            else
                log_message "WARNING" "Host $target has $packet_loss% packet loss"
            fi
        fi
        
        if [ -n "$avg_time" ]; then
            log_message "INFO" "Average response time: ${avg_time}ms"
        fi
    else
        log_message "ERROR" "Failed to ping $target"
        echo "$ping_results"
    fi
}

port_scan() {
    echo -e "${YELLOW}Enter IP address to scan ports:${NC}"
    read -p "IP: " target_ip
    
    if ! validate_ip "$target_ip"; then
        log_message "ERROR" "Invalid IP address format"
        return 1
    fi
    
    echo -e "${YELLOW}Select scan type:${NC}"
    echo "1. Quick scan (top 100 ports)"
    echo "2. Common ports scan (top 1000 ports)"
    echo "3. Full scan (1-65535) - WARNING: Very slow!"
    echo "4. Custom port range"
    echo "5. Service detection scan"
    read -p "Choice [1-5]: " scan_type
    
    local nmap_options="-T4 --min-rate 1000"
    local port_range=""
    local scan_name=""
    
    case $scan_type in
        1)
            nmap_options+=" --top-ports 100"
            scan_name="Quick Port Scan"
            ;;
        2)
            nmap_options+=" --top-ports 1000"
            scan_name="Common Ports Scan"
            ;;
        3)
            nmap_options+=" -p-"
            scan_name="Full Port Scan"
            echo -e "${RED}[WARNING] This will take a very long time!${NC}"
            echo -e "${YELLOW}Are you sure you want to continue? (y/N):${NC}"
            read -p "Confirm: " confirm
            if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
                log_message "INFO" "Full port scan cancelled"
                return 0
            fi
            ;;
        4)
            echo -e "${YELLOW}Enter port range (e.g., 1-1000, 80,443,8080):${NC}"
            read -p "Range: " port_range
            if ! validate_port_range "$port_range"; then
                log_message "ERROR" "Invalid port range format"
                return 1
            fi
            nmap_options+=" -p $port_range"
            scan_name="Custom Port Scan"
            ;;
        5)
            nmap_options+=" -sV --top-ports 1000"
            scan_name="Service Detection Scan"
            ;;
        *)
            log_message "ERROR" "Invalid choice"
            return 1
            ;;
    esac
    
    local results_dir="$LOG_DIR/port_scans"
    mkdir -p "$results_dir"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local scan_file="$results_dir/port_scan_${target_ip}_$timestamp.txt"
    
    log_message "INFO" "Starting $scan_name on $target_ip..."
    echo -e "${CYAN}[SCAN] Scanning ports on $target_ip...${NC}"
    echo -e "${YELLOW}[INFO] This may take several minutes...${NC}"
    echo ""
    
    if nmap $nmap_options "$target_ip" 2>/dev/null | tee "$scan_file"; then
        log_message "SUCCESS" "$scan_name completed successfully"
        echo -e "${CYAN}[INFO] Scan results saved to: $scan_file${NC}"
    else
        log_message "ERROR" "$scan_name failed"
        return 1
    fi
}

advanced_scan() {
    echo -e "${YELLOW}Enter IP address for advanced scan:${NC}"
    read -p "IP: " target_ip
    
    if ! validate_ip "$target_ip"; then
        log_message "ERROR" "Invalid IP address format"
        return 1
    fi
    
    echo -e "${YELLOW}Select advanced scan type:${NC}"
    echo "1. OS Detection"
    echo "2. Service Version Detection"
    echo "3. Aggressive Scan (OS + Services + Scripts)"
    echo "4. Stealth Scan"
    read -p "Choice [1-4]: " scan_type
    
    local nmap_options="-T4"
    local scan_name=""
    
    case $scan_type in
        1)
            nmap_options+=" -O"
            scan_name="OS Detection Scan"
            ;;
        2)
            nmap_options+=" -sV"
            scan_name="Service Version Detection"
            ;;
        3)
            nmap_options+=" -A"
            scan_name="Aggressive Scan"
            echo -e "${RED}[WARNING] This scan is more intrusive and may be detected!${NC}"
            ;;
        4)
            nmap_options+=" -sS -T2"
            scan_name="Stealth Scan"
            ;;
        *)
            log_message "ERROR" "Invalid choice"
            return 1
            ;;
    esac
    
    local results_dir="$LOG_DIR/advanced_scans"
    mkdir -p "$results_dir"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local scan_file="$results_dir/advanced_scan_${target_ip}_$timestamp.txt"
    
    log_message "INFO" "Starting $scan_name on $target_ip..."
    echo -e "${CYAN}[SCAN] Performing $scan_name...${NC}"
    echo -e "${YELLOW}[INFO] This may take several minutes...${NC}"
    echo ""
    
    if nmap $nmap_options "$target_ip" 2>/dev/null | tee "$scan_file"; then
        log_message "SUCCESS" "$scan_name completed successfully"
        echo -e "${CYAN}[INFO] Scan results saved to: $scan_file${NC}"
    else
        log_message "ERROR" "$scan_name failed"
        return 1
    fi
}

vuln_scan() {
    echo -e "${YELLOW}Enter IP address for vulnerability scan:${NC}"
    read -p "IP: " target_ip
    
    if ! validate_ip "$target_ip"; then
        log_message "ERROR" "Invalid IP address format"
        return 1
    fi
    
    echo -e "${RED}[WARNING] This is a basic vulnerability scan for educational purposes only!${NC}"
    echo -e "${YELLOW}[WARNING] Only scan systems you own or have explicit permission to test!${NC}"
    echo -e "${YELLOW}Continue? (y/N):${NC}"
    read -p "Confirm: " confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_message "INFO" "Vulnerability scan cancelled"
        return 0
    fi
    
    local results_dir="$LOG_DIR/vuln_scans"
    mkdir -p "$results_dir"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local scan_file="$results_dir/vuln_scan_${target_ip}_$timestamp.txt"
    
    log_message "INFO" "Starting basic vulnerability scan on $target_ip..."
    echo -e "${CYAN}[SCAN] Scanning for common vulnerabilities...${NC}"
    echo -e "${YELLOW}[INFO] This may take several minutes...${NC}"
    echo ""
    
    local nmap_options="-sV --script vuln -T4"
    
    if nmap $nmap_options "$target_ip" 2>/dev/null | tee "$scan_file"; then
        log_message "SUCCESS" "Vulnerability scan completed"
        echo -e "${CYAN}[INFO] Scan results saved to: $scan_file${NC}"
    else
        log_message "ERROR" "Vulnerability scan failed"
        return 1
    fi
}

dns_lookup() {
    echo -e "${YELLOW}Enter domain name or IP address:${NC}"
    read -p "Target: " target
    
    if [ -z "$target" ]; then
        log_message "ERROR" "Please enter a valid target"
        return 1
    fi
    
    echo -e "${YELLOW}Select DNS query type:${NC}"
    echo "1. A Record (IPv4 address)"
    echo "2. AAAA Record (IPv6 address)"
    echo "3. MX Record (Mail exchange)"
    echo "4. NS Record (Name server)"
    echo "5. TXT Record (Text record)"
    echo "6. All Records"
    read -p "Choice [1-6]: " query_type
    
    local dig_options=""
    local query_name=""
    
    case $query_type in
        1)
            dig_options="A"
            query_name="A Record"
            ;;
        2)
            dig_options="AAAA"
            query_name="AAAA Record"
            ;;
        3)
            dig_options="MX"
            query_name="MX Record"
            ;;
        4)
            dig_options="NS"
            query_name="NS Record"
            ;;
        5)
            dig_options="TXT"
            query_name="TXT Record"
            ;;
        6)
            dig_options="ANY"
            query_name="All Records"
            ;;
        *)
            log_message "ERROR" "Invalid choice"
            return 1
            ;;
    esac
    
    log_message "INFO" "Performing DNS lookup for $target ($query_name)..."
    echo -e "${CYAN}[DNS] Performing DNS lookup...${NC}"
    echo ""
    
    if command -v dig &>/dev/null; then
        echo -e "${PURPLE}=== DNS Lookup Results ($query_name) ===${NC}"
        if dig "$target" "$dig_options" +short 2>/dev/null; then
            echo ""
            echo -e "${PURPLE}=== Detailed DNS Information ===${NC}"
            dig "$target" "$dig_options" 2>/dev/null
        else
            log_message "ERROR" "DNS lookup failed"
        fi
    elif command -v nslookup &>/dev/null; then
        echo -e "${PURPLE}=== DNS Lookup Results ===${NC}"
        if nslookup "$target" 2>/dev/null; then
            log_message "SUCCESS" "DNS lookup completed"
        else
            log_message "ERROR" "DNS lookup failed"
        fi
    else
        log_message "ERROR" "No DNS lookup tools available"
        echo -e "${YELLOW}[INFO] Install dnsutils: pkg install dnsutils${NC}"
    fi
}

network_monitor() {
    echo -e "${YELLOW}Enter IP address to monitor:${NC}"
    read -p "IP: " target_ip
    
    if ! validate_ip "$target_ip"; then
        log_message "ERROR" "Invalid IP address format"
        return 1
    fi
    
    echo -e "${YELLOW}Enter monitoring interval in seconds (default: 5):${NC}"
    read -p "Interval: " interval
    interval=${interval:-5}
    
    if ! [[ "$interval" =~ ^[0-9]+$ ]]; then
        log_message "ERROR" "Invalid interval. Using default: 5"
        interval=5
    fi
    
    local monitor_dir="$LOG_DIR/monitoring"
    mkdir -p "$monitor_dir"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local monitor_file="$monitor_dir/monitor_${target_ip}_$timestamp.log"
    
    log_message "INFO" "Starting network monitoring for $target_ip..."
    echo -e "${CYAN}[MONITOR] Monitoring $target_ip (interval: ${interval}s)...${NC}"
    echo -e "${YELLOW}[INFO] Press Ctrl+C to stop monitoring${NC}"
    echo -e "${CYAN}[INFO] Log file: $monitor_file${NC}"
    echo ""
    
    echo "Network Monitoring Started: $(date)" > "$monitor_file"
    echo "Target: $target_ip" >> "$monitor_file"
    echo "Interval: ${interval}s" >> "$monitor_file"
    echo "----------------------------------------" >> "$monitor_file"
    
    local count=0
    local consecutive_failures=0
    local total_success=0
    local total_failures=0
    
    while true; do
        ((count++))
        local current_time=$(date '+%Y-%m-%d %H:%M:%S')
        
        if ping -c 1 -W 3 "$target_ip" &>/dev/null; then
            echo -e "${GREEN}[$current_time] Host $target_ip is UP (ping #$count)${NC}"
            echo "[$current_time] UP (ping #$count)" >> "$monitor_file"
            consecutive_failures=0
            ((total_success++))
        else
            echo -e "${RED}[$current_time] Host $target_ip is DOWN (ping #$count)${NC}"
            echo "[$current_time] DOWN (ping #$count)" >> "$monitor_file"
            ((consecutive_failures++))
            ((total_failures++))
            
            if [ $consecutive_failures -eq 3 ]; then
                echo -e "${RED}[ALERT] Host has been down for 3 consecutive checks!${NC}"
                echo "[$current_time] ALERT: 3 consecutive failures" >> "$monitor_file"
            fi
        fi
        
        sleep "$interval"
    done
}

mac_lookup() {
    echo -e "${YELLOW}Enter MAC address (format: AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF):${NC}"
    read -p "MAC: " mac_addr
    
    # Normalize MAC address format
    mac_addr=$(echo "$mac_addr" | tr '[:lower:]' '[:upper:]' | tr '-' ':')
    
    if [[ ! $mac_addr =~ ^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$ ]]; then
        log_message "ERROR" "Invalid MAC address format"
        return 1
    fi
    
    log_message "INFO" "Looking up MAC address $mac_addr..."
    echo -e "${CYAN}[LOOKUP] Analyzing MAC address $mac_addr...${NC}"
    echo ""
    local oui=$(echo "$mac_addr" | cut -d':' -f1-3)
    echo -e "${PURPLE}=== MAC Address Analysis ===${NC}"
    echo -e "${BLUE}MAC Address: $mac_addr${NC}"
    echo -e "${BLUE}OUI (Organizationally Unique Identifier): $oui${NC}"
    echo ""
    if command -v curl &>/dev/null; then
        echo -e "${YELLOW}[INFO] Looking up vendor information...${NC}"
        local vendor_info=""
        
        vendor_info=$(curl -s "https://api.macvendors.com/$mac_addr" 2>/dev/null || echo "Unknown")
        
        if [[ "$vendor_info" != "Unknown" && "$vendor_info" != *"Not Found"* ]]; then
            echo -e "${GREEN}Vendor: $vendor_info${NC}"
        else
           
            echo -e "${YELLOW}Vendor: Unable to determine online${NC}"
            echo -e "${BLUE}OUI: $oui (Use online OUI lookup for vendor details)${NC}"
        fi
    else
        echo -e "${YELLOW}[INFO] Install curl for online vendor lookup${NC}"
        echo -e "${BLUE}OUI: $oui${NC}"
    fi
    
    echo ""
    echo -e "${PURPLE}=== MAC Address Details ===${NC}"
    
    local first_octet=$(echo "$mac_addr" | cut -d':' -f1)
    local first_octet_dec=$(printf "%d" "0x$first_octet")
    
    if [ $((first_octet_dec & 2)) -eq 2 ]; then
        echo -e "${YELLOW}Type: Locally Administered Address${NC}"
    else
        echo -e "${GREEN}Type: Universally Administered Address${NC}"
    fi
    
    if [ $((first_octet_dec & 1)) -eq 1 ]; then
        echo -e "${BLUE}Transmission: Multicast${NC}"
    else
        echo -e "${BLUE}Transmission: Unicast${NC}"
    fi
}


traceroute_host() {
    echo -e "${YELLOW}Enter IP address or hostname for traceroute:${NC}"
    read -p "Target: " target
    
    if [ -z "$target" ]; then
        log_message "ERROR" "Please enter a valid target"
        return 1
    fi
    
    echo -e "${YELLOW}Select traceroute method:${NC}"
    echo "1. ICMP traceroute (default)"
    echo "2. UDP traceroute"
    echo "3. TCP traceroute (if available)"
    read -p "Choice [1-3]: " trace_method
    
    local traceroute_cmd="traceroute"
    local method_name="ICMP"
    
    case $trace_method in
        1|"")
            traceroute_cmd="traceroute -I"
            method_name="ICMP"
            ;;
        2)
            traceroute_cmd="traceroute"
            method_name="UDP"
            ;;
        3)
            traceroute_cmd="traceroute -T"
            method_name="TCP"
            ;;
        *)
            log_message "WARNING" "Invalid choice, using default ICMP method"
            traceroute_cmd="traceroute -I"
            method_name="ICMP"
            ;;
    esac
    
    log_message "INFO" "Starting $method_name traceroute to $target..."
    echo -e "${CYAN}[TRACEROUTE] Tracing route to $target using $method_name...${NC}"
    echo -e "${YELLOW}[INFO] This may take several minutes...${NC}"
    echo ""
    
    local trace_dir="$LOG_DIR/traceroute"
    mkdir -p "$trace_dir"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local trace_file="$trace_dir/traceroute_${target}_$timestamp.txt"
    
    echo "Traceroute to $target started at $(date)" > "$trace_file"
    echo "Method: $method_name" >> "$trace_file"
    echo "----------------------------------------" >> "$trace_file"
    
    if command -v traceroute &>/dev/null; then
        if $traceroute_cmd "$target" 2>&1 | tee -a "$trace_file"; then
            log_message "SUCCESS" "Traceroute completed successfully"
            echo -e "${CYAN}[INFO] Traceroute results saved to: $trace_file${NC}"
        else
            log_message "ERROR" "Traceroute failed"
        fi
    else
        log_message "ERROR" "Traceroute not available. Install with: pkg install traceroute"
    fi
}

interface_info() {
    log_message "INFO" "Gathering network interface information..."
    echo -e "${CYAN}[INFO] Network Interface Information${NC}"
    echo ""
    
    if command -v ip &>/dev/null; then
        echo -e "${PURPLE}=== Network Interfaces (ip command) ===${NC}"
        ip addr show 2>/dev/null | while IFS= read -r line; do
            if [[ $line =~ ^[0-9]+: ]]; then
                echo -e "${GREEN}$line${NC}"
            elif [[ $line =~ inet ]]; then
                echo -e "${BLUE}    $line${NC}"
            elif [[ $line =~ link/ ]]; then
                echo -e "${YELLOW}    $line${NC}"
            else
                echo "    $line"
            fi
        done
        echo ""
        
        echo -e "${PURPLE}=== Routing Table ===${NC}"
        ip route show 2>/dev/null
        echo ""
      
    elif command -v ifconfig &>/dev/null; then
        echo -e "${PURPLE}=== Network Interfaces (ifconfig) ===${NC}"
        ifconfig 2>/dev/null
        echo ""
        
        if command -v route &>/dev/null; then
            echo -e "${PURPLE}=== Routing Table ===${NC}"
            route -n 2>/dev/null
            echo ""
        fi
    else
        log_message "ERROR" "No network interface tools available"
        echo -e "${YELLOW}[INFO] Install net-tools: pkg install net-tools${NC}"
    fi
    
    if command -v netstat &>/dev/null; then
        echo -e "${PURPLE}=== Network Statistics ===${NC}"
        netstat -i 2>/dev/null
        echo ""
    fi
}

port_listener() {
    echo -e "${YELLOW}Port Listener Options:${NC}"
    echo "1. Check if port is open on target"
    echo "2. Listen on local port"
    echo "3. Banner grabbing"
    read -p "Choice [1-3]: " listener_choice
    
    case $listener_choice in
        1)
            echo -e "${YELLOW}Enter IP address:${NC}"
            read -p "IP: " target_ip
            echo -e "${YELLOW}Enter port number:${NC}"
            read -p "Port: " port
            
            if ! validate_ip "$target_ip"; then
                log_message "ERROR" "Invalid IP address"
                return 1
            fi
            
            if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
                log_message "ERROR" "Invalid port number"
                return 1
            fi
            
            log_message "INFO" "Checking if port $port is open on $target_ip..."
            
            if command -v nc &>/dev/null; then
                if nc -z -w 3 "$target_ip" "$port" 2>/dev/null; then
                    echo -e "${GREEN}[SUCCESS] Port $port is OPEN on $target_ip${NC}"
                else
                    echo -e "${RED}[INFO] Port $port is CLOSED or filtered on $target_ip${NC}"
                fi
            else
                log_message "ERROR" "netcat not available. Install with: pkg install netcat-openbsd"
            fi
            ;;
            
        2)
            echo -e "${YELLOW}Enter port number to listen on:${NC}"
            read -p "Port: " listen_port
            
            if ! [[ "$listen_port" =~ ^[0-9]+$ ]] || [ "$listen_port" -lt 1 ] || [ "$listen_port" -gt 65535 ]; then
                log_message "ERROR" "Invalid port number"
                return 1
            fi
            
            if [ "$listen_port" -lt 1024 ]; then
                log_message "WARNING" "Port $listen_port requires root privileges"
            fi
            
            log_message "INFO" "Starting listener on port $listen_port..."
            echo -e "${CYAN}[LISTENER] Listening on port $listen_port...${NC}"
            echo -e "${YELLOW}[INFO] Press Ctrl+C to stop${NC}"
            echo -e "${YELLOW}[INFO] Connect using: nc $LOCAL_IP $listen_port${NC}"
            echo ""
            
            if command -v nc &>/dev/null; then
                nc -l -p "$listen_port" 2>/dev/null || nc -l "$listen_port" 2>/dev/null
            else
                log_message "ERROR" "netcat not available. Install with: pkg install netcat-openbsd"
            fi
            ;;
            
        3)
            echo -e "${YELLOW}Enter IP address:${NC}"
            read -p "IP: " target_ip
            echo -e "${YELLOW}Enter port number:${NC}"
            read -p "Port: " port
            
            if ! validate_ip "$target_ip"; then
                log_message "ERROR" "Invalid IP address"
                return 1
            fi
            
            if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
                log_message "ERROR" "Invalid port number"
                return 1
            fi
            
            log_message "INFO" "Attempting banner grab from $target_ip:$port..."
            echo -e "${CYAN}[BANNER] Grabbing banner from $target_ip:$port...${NC}"
            
            if command -v nc &>/dev/null; then
                echo -e "${PURPLE}=== Banner Information ===${NC}"
                timeout 5 nc "$target_ip" "$port" <<< "" 2>/dev/null || echo -e "${YELLOW}No banner received or connection failed${NC}"
            else
                log_message "ERROR" "netcat not available. Install with: pkg install netcat-openbsd"
            fi
            ;;
            
        *)
            log_message "ERROR" "Invalid choice"
            return 1
            ;;
    esac
}
wifi_scan() {
    log_message "INFO" "Scanning for WiFi networks..."
    echo -e "${CYAN}[WIFI] Scanning for available WiFi networks...${NC}"
    echo ""
    
    if command -v iw &>/dev/null; then
        echo -e "${PURPLE}=== WiFi Networks (iw scan) ===${NC}"
        
        local wireless_interfaces=$(iw dev 2>/dev/null | grep Interface | awk '{print $2}')
        
        if [ -n "$wireless_interfaces" ]; then
            for interface in $wireless_interfaces; do
                echo -e "${YELLOW}Scanning interface: $interface${NC}"
                if iw dev "$interface" scan 2>/dev/null | grep -E "(BSS|SSID|freq|signal)" | while read -r line; do
                    if [[ $line =~ BSS ]]; then
                        local bssid=$(echo "$line" | awk '{print $2}')
                        echo -e "${GREEN}Access Point: $bssid${NC}"
                    elif [[ $line =~ SSID ]]; then
                        local ssid=$(echo "$line" | cut -d':' -f2- | sed 's/^ *//')
                        echo -e "${BLUE}  Network Name: $ssid${NC}"
                    elif [[ $line =~ freq ]]; then
                        local freq=$(echo "$line" | awk '{print $2}')
                        echo -e "${BLUE}  Frequency: $freq MHz${NC}"
                    elif [[ $line =~ signal ]]; then
                        local signal=$(echo "$line" | awk '{print $2}')
                        echo -e "${BLUE}  Signal: $signal dBm${NC}"
                        echo ""
                    fi
                done; then
                    log_message "SUCCESS" "WiFi scan completed"
                else
                    log_message "ERROR" "WiFi scan failed for interface $interface"
                fi
            done
        else
            log_message "WARNING" "No wireless interfaces found"
        fi
    else
        log_message "ERROR" "iw command not available"
        echo -e "${YELLOW}[INFO] WiFi scanning requires wireless tools${NC}"
        echo -e "${YELLOW}[INFO] This feature may not be available in Termux${NC}"
    fi
}

view_logs() {
    if [ ! -d "$LOG_DIR" ]; then
        log_message "ERROR" "No log directory found"
        return 1
    fi
    
    echo -e "${YELLOW}Log Viewer Options:${NC}"
    echo "1. View recent logs"
    echo "2. View scan results"
    echo "3. View monitoring logs"
    echo "4. View all logs"
    echo "5. Search logs"
    read -p "Choice [1-5]: " log_choice
    
    case $log_choice in
        1)
            echo -e "${CYAN}[LOGS] Recent log entries:${NC}"
            if find "$LOG_DIR" -name "*.log" -type f -exec tail -n 20 {} \; 2>/dev/null; then
                log_message "SUCCESS" "Recent logs displayed"
            else
                log_message "ERROR" "No recent logs found"
            fi
            ;;
            
        2)
            echo -e "${CYAN}[LOGS] Available scan results:${NC}"
            if find "$LOG_DIR" -name "*scan*" -type f 2>/dev/null; then
                echo ""
                echo -e "${YELLOW}Enter filename to view (or press Enter to skip):${NC}"
                read -p "File: " scan_file
                if [ -n "$scan_file" ] && [ -f "$scan_file" ]; then
                    cat "$scan_file"
                fi
            else
                log_message "INFO" "No scan results found"
            fi
            ;;
            
        3)
            echo -e "${CYAN}[LOGS] Available monitoring logs:${NC}"
            if find "$LOG_DIR" -name "*monitor*" -type f 2>/dev/null; then
                echo ""
                echo -e "${YELLOW}Enter filename to view (or press Enter to skip):${NC}"
                read -p "File: " monitor_file
                if [ -n "$monitor_file" ] && [ -f "$monitor_file" ]; then
                    tail -n 50 "$monitor_file"
                fi
            else
                log_message "INFO" "No monitoring logs found"
            fi
            ;;
            
        4)
            echo -e "${CYAN}[LOGS] All available logs:${NC}"
            find "$LOG_DIR" -type f -name "*.log" -o -name "*.txt" 2>/dev/null | sort
            ;;
            
        5)
            echo -e "${YELLOW}Enter search term:${NC}"
            read -p "Search: " search_term
            if [ -n "$search_term" ]; then
                echo -e "${CYAN}[SEARCH] Searching for '$search_term' in logs...${NC}"
                if grep -r "$search_term" "$LOG_DIR" 2>/dev/null; then
                    log_message "SUCCESS" "Search completed"
                else
                    log_message "INFO" "No matches found"
                fi
            fi
            ;;
            
        *)
            log_message "ERROR" "Invalid choice"
            return 1
            ;;
    esac
}

system_info() {
    echo -e "${CYAN}[SYSTEM] System Information${NC}"
    echo ""
    
    echo -e "${PURPLE}=== System Details ===${NC}"
    echo -e "${BLUE}Hostname: $(hostname 2>/dev/null || echo 'Unknown')${NC}"
    echo -e "${BLUE}Kernel: $(uname -r 2>/dev/null || echo 'Unknown')${NC}"
    echo -e "${BLUE}Architecture: $(uname -m 2>/dev/null || echo 'Unknown')${NC}"
    echo -e "${BLUE}OS: $(uname -o 2>/dev/null || echo 'Unknown')${NC}"
    echo ""
    
    echo -e "${PURPLE}=== Network Configuration ===${NC}"
    echo -e "${BLUE}Local IP: $LOCAL_IP${NC}"
    echo -e "${BLUE}Network Range: $NETWORK${NC}"
    echo ""
    
    if command -v uptime &>/dev/null; then
        echo -e "${PURPLE}=== System Uptime ===${NC}"
        uptime 2>/dev/null || echo "Uptime information not available"
        echo ""
    fi
    
    if command -v free &>/dev/null; then
        echo -e "${PURPLE}=== Memory Usage ===${NC}"
        free -h 2>/dev/null || echo "Memory information not available"
        echo ""
    fi
    
    if command -v df &>/dev/null; then
        echo -e "${PURPLE}=== Disk Usage ===${NC}"
        df -h 2>/dev/null | head -10 || echo "Disk information not available"
        echo ""
    fi
    
    echo -e "${PURPLE}=== DNMAP Information ===${NC}"
    echo -e "${BLUE}Script Version: $SCRIPT_VERSION${NC}"
    echo -e "${BLUE}Log Directory: $LOG_DIR${NC}"
    echo -e "${BLUE}Config File: $CONFIG_FILE${NC}"
    echo ""
}

show_help() {
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}                    DNMAP HELP & USAGE GUIDE                ${NC}"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}MAIN MENU OPTIONS:${NC}"
    echo -e "${BLUE}1.${NC} Network Scan       - Discover active devices on network"
    echo -e "${BLUE}2.${NC} Ping Host         - Test connectivity to specific host"
    echo -e "${BLUE}3.${NC} Port Scan         - Scan ports on target IP"
    echo -e "${BLUE}4.${NC} Advanced Scan     - OS detection, service enumeration"
    echo -e "${BLUE}5.${NC} Vulnerability Scan - Basic vulnerability assessment"
    echo -e "${BLUE}6.${NC} DNS Lookup        - Domain name resolution"
    echo -e "${BLUE}7.${NC} Network Monitor   - Continuous host monitoring"
    echo -e "${BLUE}8.${NC} MAC Lookup        - MAC address vendor lookup"
    echo -e "${BLUE}9.${NC} Traceroute        - Trace network path to destination"
    echo -e "${BLUE}10.${NC} Interface Info    - Show network interface details"
    echo -e "${BLUE}11.${NC} Port Listener     - Port connectivity testing"
    echo -e "${BLUE}12.${NC} WiFi Scan         - Scan for wireless networks"
    echo -e "${BLUE}13.${NC} View Logs         - View scan results and logs"
    echo -e "${BLUE}14.${NC} System Info       - Display system information"
    echo -e "${BLUE}15.${NC} Help              - Show this help message"
    echo -e "${BLUE}16.${NC} Exit              - Exit DNMAP"
    echo ""
    echo -e "${YELLOW}IMPORTANT NOTES:${NC}"
    echo -e "${RED}•${NC} Only scan networks you own or have permission to test"
    echo -e "${RED}•${NC} Aggressive scanning may be detected by security systems"
    echo -e "${RED}•${NC} Use responsibly and follow local laws and regulations"
    echo -e "${RED}•${NC} Some features require root privileges or specific tools"
    echo ""
    echo -e "${YELLOW}LOG FILES:${NC}"
    echo -e "${BLUE}•${NC} All scan results are saved in: $LOG_DIR"
    echo -e "${BLUE}•${NC} Configuration file: $CONFIG_FILE"
    echo -e "${BLUE}•${NC} Use 'View Logs' option to review previous scans"
    echo ""
    echo -e "${YELLOW}PREREQUISITES:${NC}"
    echo -e "${BLUE}•${NC} Run 'pkg update && pkg upgrade' before first use"
    echo -e "${BLUE}•${NC} Required tools are automatically installed"
    echo -e "${BLUE}•${NC} Stable internet connection recommended"
    echo ""
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════${NC}"
}

# Clean up function
cleanup() {
    log_message "INFO" "Cleaning up temporary files..."
    
    # Remove temporary files
    if [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"/* 2>/dev/null
    fi
    
    # Compress old logs (older than 7 days)
    if [ -d "$LOG_DIR" ]; then
        find "$LOG_DIR" -name "*.log" -type f -mtime +7 -exec gzip {} \; 2>/dev/null
    fi
    
    log_message "SUCCESS" "Cleanup completed"
}

# Main menu
main_menu() {
    while true; do
        show_banner
        echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
        echo -e "${CYAN}                         MAIN MENU                          ${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
        echo ""
        echo -e "${YELLOW}Network Discovery & Scanning:${NC}"
        echo -e "${BLUE}1.${NC}  Network Scan"
        echo -e "${BLUE}2.${NC}  Ping Host"
        echo -e "${BLUE}3.${NC}  Port Scan"
        echo -e "${BLUE}4.${NC}  Advanced Scan"
        echo -e "${BLUE}5.${NC}  Vulnerability Scan"
        echo ""
        echo -e "${YELLOW}Network Analysis:${NC}"
        echo -e "${BLUE}6.${NC}  DNS Lookup"
        echo -e "${BLUE}7.${NC}  Network Monitor"
        echo -e "${BLUE}8.${NC}  MAC Lookup"
        echo -e "${BLUE}9.${NC}  Traceroute"
        echo ""
        echo -e "${YELLOW}System & Information:${NC}"
        echo -e "${BLUE}10.${NC} Interface Info"
        echo -e "${BLUE}11.${NC} Port Listener"
        echo -e "${BLUE}12.${NC} WiFi Scan"
        echo -e "${BLUE}13.${NC} View Logs"
        echo -e "${BLUE}14.${NC} System Info"
        echo ""
        echo -e "${YELLOW}Help & Options:${NC}"
        echo -e "${BLUE}15.${NC} Help"
        echo -e "${BLUE}16.${NC} Exit"
        echo ""
        echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}Current Network: $NETWORK${NC}"
        echo -e "${GREEN}Local IP: $LOCAL_IP${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
        echo ""
        
        read -p "$(echo -e "${YELLOW}Select option [1-16]: ${NC}")" choice
        
        case $choice in
            1)
                scan_network
                ;;
            2)
                ping_host
                ;;
            3)
                port_scan
                ;;
            4)
                advanced_scan
                ;;
            5)
                vuln_scan
                ;;
            6)
                dns_lookup
                ;;
            7)
                network_monitor
                ;;
            8)
                mac_lookup
                ;;
            9)
                traceroute_host
                ;;
            10)
                interface_info
                ;;
            11)
                port_listener
                ;;
            12)
                wifi_scan
                ;;
            13)
                view_logs
                ;;
            14)
                system_info
                ;;
            15)
                show_help
                ;;
            16)
                echo -e "${YELLOW}Thank you for using DNMAP!${NC}"
                cleanup
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid choice. Please select 1-16.${NC}"
                ;;
        esac
        
        echo ""
        echo -e "${CYAN}Press Enter to continue...${NC}"
        read
    done
}

init_script() {
    log_message "INFO" "Initializing DNMAP..."
    
    mkdir -p "$LOG_DIR" "$TEMP_DIR" 2>/dev/null
    
    load_config
    
    check_tools
    
    get_network_info
    
    save_config
    
    log_message "SUCCESS" "DNMAP initialized successfully"
}

main() {
    init_script
    
    main_menu
}

main "$@"
