#!/bin/bash
#===============================================================================
#          FILE:  tunnel.sh
#          USAGE:  ./tunnel.sh
#
#   DESCRIPTION:  This script sets up and manages the Feri Tunnel.
#                 Feri Tunnel is a hypothetical tunneling tool for secure
#                 and efficient data transfer across networks.
#===============================================================================

# Define color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Determine script directory
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# SQLite database file
db_file="$script_dir/tunnels.db"

# Function to create SQLite table for tunnels
create_table() {
    sqlite3 "$db_file" "CREATE TABLE IF NOT EXISTS tunnels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        interface_name TEXT NOT NULL,
        created_date TEXT DEFAULT CURRENT_TIMESTAMP,
        remote_ipv4 TEXT NOT NULL,
        local_ipv4 TEXT NOT NULL,
        local_ipv6 TEXT NOT NULL,
        script_file TEXT NOT NULL,
        service_file TEXT NOT NULL,
        tunnel_type TEXT NOT NULL
    );
    "

    sqlite3 "$db_file" "CREATE TABLE IF NOT EXISTS gost_tunnels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        protocol TEXT NOT NULL,
        local_ipv6 TEXT NOT NULL,
        port_range TEXT NOT NULL,
        service_name TEXT NOT NULL,
        service_file TEXT NOT NULL,
        tunnel_type TEXT NOT NULL,
        created_date TEXT DEFAULT CURRENT_TIMESTAMP
    );"

    sqlite3 "$db_file" "CREATE TABLE IF NOT EXISTS ip_state (
        server_type TEXT PRIMARY KEY,
        last_assigned_index INTEGER
    );"
}
# Ensure SQLite database is created and table is initialized
create_table

# Function to print header
print_header() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "

  _____ _____ ____  ___   _____ _   _ _   _ _   _ _____ _
 |  ___| ____|  _ \|_ _| |_   _| | | | \ | | \ | | ____| |
 | |_  |  _| | |_) || |    | | | | | |  \| |  \| |  _| | |
 |  _| | |___|  _ < | |    | | | |_| | |\  | |\  | |___| |___
 |_|   |_____|_| \_\___|   |_|  \___/|_| \_|_| \_|_____|_____|

    "
    echo -e "${NC}"
    echo -e "${YELLOW}Manage your tunnels with ease and security${NC}"
    echo ""
}

# Function to handle Ctrl+C (SIGINT)
handle_exit() {
    echo -e "\n${YELLOW}Ctrl+C detected. Do you really want to exit? (y/n)${NC}"
    read answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        echo -e "${RED}Exiting...${NC}"
        exit 0
    fi
    show_menu
}

# Trap Ctrl+C (SIGINT)
trap handle_exit SIGINT

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root. Please run it with sudo.${NC}"
        exit 1
    fi
}

# Function to check if the system is Ubuntu or Debian-based
check_os() {
    if ! command -v lsb_release &> /dev/null; then
        echo -e "${RED}This script requires lsb_release to identify the OS. Please install lsb-release.${NC}"
        exit 1
    fi

    os=$(lsb_release -is)
    if [[ "$os" != "Ubuntu" && "$os" != "Debian" ]]; then
        echo -e "${RED}This script only supports Ubuntu and Debian-based systems.${NC}"
        exit 1
    fi
}

optimize_tcp() {
    echo -e "${BLUE}Optimizing TCP settings for better performance...${NC}"

    # Backup current sysctl settings
    sudo cp /etc/sysctl.conf /etc/sysctl.conf.backup

    # Apply performance optimizations
    sudo bash -c 'cat <<EOF >> /etc/sysctl.conf
# TCP performance optimizations
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# Additional optimizations
fs.file-max = 67108864
net.core.default_qdisc = fq_codel
net.core.netdev_max_backlog = 32768
net.core.optmem_max = 262144
net.core.somaxconn = 65536
net.core.rmem_max = 33554432
net.core.rmem_default = 1048576
net.core.wmem_max = 33554432
net.core.wmem_default = 1048576
net.ipv4.tcp_rmem = 16384 1048576 33554432
net.ipv4.tcp_wmem = 16384 1048576 33554432
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fin_timeout = 25
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_probes = 7
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_max_orphans = 819200
net.ipv4.tcp_max_syn_backlog = 20480
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_mem = 65536 1048576 33554432
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_notsent_lowat = 32768
net.ipv4.tcp_retries2 = 8
net.ipv4.tcp_sack = 1
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_adv_win_scale = -2
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_ecn_fallback = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.udp_mem = 65536 1048576 33554432
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.lo.disable_ipv6 = 0
net.unix.max_dgram_qlen = 256
vm.min_free_kbytes = 65536
vm.swappiness = 10
vm.vfs_cache_pressure = 250
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.neigh.default.gc_thresh1 = 512
net.ipv4.neigh.default.gc_thresh2 = 2048
net.ipv4.neigh.default.gc_thresh3 = 16384
net.ipv4.neigh.default.gc_stale_time = 60
net.ipv4.conf.default.arp_announce = 2
net.ipv4.conf.lo.arp_announce = 2
net.ipv4.conf.all.arp_announce = 2
kernel.panic = 1
vm.dirty_ratio = 20
EOF'

    # Apply the new sysctl settings
    sudo sysctl -p

    echo -e "${GREEN}TCP settings optimized.${NC}"
}

# Function to enable BBR
enable_bbr() {
    echo -e "${BLUE}Enabling BBR...${NC}"

    # Check if BBR is already enabled
    if lsmod | grep -q bbr; then
        echo -e "${GREEN}BBR is already enabled.${NC}"
    else
        # Load the TCP BBR module
        sudo modprobe tcp_bbr

        # Ensure BBR is loaded on boot
        echo "tcp_bbr" | sudo tee -a /etc/modules-load.d/modules.conf

        # Set BBR as the default congestion control algorithm
        sudo bash -c 'echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf'
        sudo bash -c 'echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf'

        # Apply the new sysctl settings
        sudo sysctl -p

        echo -e "${GREEN}BBR enabled.${NC}"
    fi
}

# Main function to perform all optimizations
optimize_network() {
    optimize_tcp
    enable_bbr
}

# Function to update system and install sqlite3
install_dependencies() {
    echo -e "${BLUE}Updating package list...${NC}"
    sudo apt update -y

    echo -e "${BLUE}Upgrading packages...${NC}"
    sudo apt upgrade -y

    echo -e "${BLUE}Installing sqlite3...${NC}"
    sudo apt install -y sqlite3

    echo -e "${BLUE}Installing openssl...${NC}"
    sudo apt install -y openssl
}

# Call the check functions
check_root
check_os
install_dependencies

# Function to create an IR tunnel
create_ir_tunnel() {
    echo -e "${BLUE}Creating IR Tunnel${NC}"

    echo -e "${MAGENTA}Enter the interface name:${NC}"
    read interface_name

    echo -e "${MAGENTA}Enter the local IPv4 address (Iran):${NC}"
    read local_ipv4

    echo -e "${MAGENTA}Enter the remote IPv4 address (Kharej):${NC}"
    read remote_ipv4

    create_tunnel $interface_name $local_ipv4 $remote_ipv4 "IR"
}

# Function to create a KHAREJ tunnel
create_kharej_tunnel() {
    echo -e "${BLUE}Creating KHAREJ Tunnel${NC}"

    echo -e "${MAGENTA}Enter the interface name:${NC}"
    read interface_name

    echo -e "${MAGENTA}Enter the local IPv4 address (Kharej):${NC}"
    read local_ipv4

    echo -e "${MAGENTA}Enter the remote IPv4 address (Iran):${NC}"
    read remote_ipv4

    create_tunnel $interface_name $local_ipv4 $remote_ipv4 "KHAREJ"
}

# Function to create a tunnel
create_tunnel() {
    local interface_name=$1
    local local_ipv4=$2
    local remote_ipv4=$3
    local tunnel_type=$4

    # Validate IPv4 addresses
    if ! validate_ipv4 "$local_ipv4"; then
        echo -e "${RED}Invalid local IPv4 address. Please enter a valid IPv4 address.${NC}"
        return
    fi

    if ! validate_ipv4 "$remote_ipv4"; then
        echo -e "${RED}Invalid remote IPv4 address. Please enter a valid IPv4 address.${NC}"
        return
    fi

    # Generate and check IPv6 address
    local_ipv6=$(generate_ipv6 "$tunnel_type")
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}$local_ipv6${NC}"  # Display error message if IPv6 generation fails
        return
    fi

    # Create the script file name
    script_file="$script_dir/tunnel_${interface_name}_$(openssl rand -hex 4).sh"

    # Write the tunnel creation commands to the script file
    cat <<EOF > "$script_file"
#!/bin/bash

# Tunnel creation commands
sudo ip tunnel add $interface_name mode sit remote $remote_ipv4 local $local_ipv4
sudo ip -6 addr add $local_ipv6 dev $interface_name
sudo ip link set $interface_name mtu 1480
sudo ip link set $interface_name up
EOF

    # Make the script file executable
    chmod +x "$script_file"

    echo -e "${GREEN}Tunnel creation script generated successfully: ${script_file}${NC}"
    echo -e "${GREEN}Your local IPv6 address is: ${local_ipv6%/64}${NC}"

    # Generate systemd service file
    generate_systemd_service $interface_name "$script_file" $local_ipv6

    # Insert tunnel information into SQLite database
    insert_tunnel_info "$interface_name" "$remote_ipv4" "$local_ipv4" "$local_ipv6" "$script_file" "/usr/lib/systemd/system/$service_file" "$tunnel_type"
}

# Function to generate systemd service file
generate_systemd_service() {
    local interface_name=$1
    local script_file=$2
    local local_ipv6=$3

    # Get the full path of the script file
    script_file_path=$(realpath "$script_file")

    # Create systemd service file name
    service_file="tunnel_${interface_name}_$(openssl rand -hex 4).service"
    service_file_path="/usr/lib/systemd/system/$service_file"

    # Write systemd service content
    cat <<EOF > "$service_file"
[Unit]
Description=Tunnel Creation Service for $interface_name
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash $script_file_path
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    echo -e "${GREEN}Systemd service file generated successfully: ${service_file}${NC}"

    # Move service file to systemd directory
    sudo mv "$service_file" "$service_file_path"

    # Enable and start the service
    enable_and_start_service "$service_file_path"

    # Display paths and IPv6 address
    #echo -e "${YELLOW}Script file path: $script_file_path${NC}"
    #echo -e "${YELLOW}Service file path: $service_file_path${NC}"
}

# Function to enable and start systemd service
enable_and_start_service() {
    local service_file_path=$1

    # Reload systemd
    sudo systemctl daemon-reload

    # Enable the service
    sudo systemctl enable "$(basename "$service_file_path")"

    # Start the service
    sudo systemctl start "$(basename "$service_file_path" .service)"

    echo -e "${GREEN}Service enabled and started successfully.${NC}"
}

# Function to validate IPv4 address
validate_ipv4() {
    local ip=$1
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Function to insert tunnel information into SQLite database
insert_tunnel_info() {
    local interface_name=$1
    local remote_ipv4=$2
    local local_ipv4=$3
    local local_ipv6=$4
    local script_file=$5
    local service_file_path=$6
    local tunnel_type=$7

    sqlite3 "$db_file" "INSERT INTO tunnels (interface_name, remote_ipv4, local_ipv4, local_ipv6, script_file, service_file, tunnel_type)
                         VALUES ('$interface_name', '$remote_ipv4', '$local_ipv4', '${local_ipv6%/64}', '$script_file', '$service_file_path', '$tunnel_type');"
}

# Function to display all tunnels from SQLite database
show_all_tunnels() {
    echo -e "${BLUE}Listing all tunnels:${NC}"
    sqlite3 -header -column "$db_file" "SELECT id, interface_name, created_date, remote_ipv4, local_ipv4, local_ipv6, script_file, service_file, tunnel_type FROM tunnels;"
}

# Function to delete a tunnel
delete_tunnel() {
    echo -e "${YELLOW}Enter the ID of the tunnel to delete:${NC}"
    read tunnel_id

    if [[ -z "$tunnel_id" ]]; then
        echo -e "${RED}Error: No tunnel ID provided. Operation cancelled.${NC}"
        return
    fi

    if ! [[ "$tunnel_id" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}Error: Invalid tunnel ID. Please enter a numeric value.${NC}"
        return
    fi

    # Continue with deletion process
    delete_tunnel_by_id "$tunnel_id"
}

delete_tunnel_by_id() {
    local id=$1
    # Fetch required data from database
    # shellcheck disable=SC2155
    local script_file=$(sqlite3 "$db_file" "SELECT script_file FROM tunnels WHERE id=$id;")
    # shellcheck disable=SC2155
    local service_file=$(sqlite3 "$db_file" "SELECT service_file FROM tunnels WHERE id=$id;")
    # shellcheck disable=SC2155
    local interface_name=$(sqlite3 "$db_file" "SELECT interface_name FROM tunnels WHERE id=$id;")

    if [[ -z $script_file || -z $service_file || -z $interface_name ]]; then
        echo -e "${RED}Failed to find tunnel with ID $id. No records to delete.${NC}"
        return
    fi

    # Proceed with deletion
    echo -e "${BLUE}Deleting tunnel $id...${NC}"
    # Remove tunnel from system
    sudo systemctl stop "$(basename "$service_file")"
    sudo systemctl disable "$(basename "$service_file")"
    sudo rm "$service_file"
    sudo rm "$script_file"

    sudo ip tunnel del "$interface_name"

    rm -f "/etc/systemd/system/$service_file"
    sqlite3 "$db_file" "DELETE FROM tunnels WHERE id=$id;"

    echo -e "${GREEN}Tunnel deleted successfully.${NC}"
}

# Function to edit a tunnel
edit_tunnel() {
    echo -e "${BLUE}Editing a tunnel${NC}"
    echo -e "${MAGENTA}Enter the ID or interface name of the tunnel to edit:${NC}"
    read id_or_interface

    # Fetch tunnel information based on ID or interface name
    tunnel_info=$(sqlite3 -separator " " "$db_file" "SELECT id, tunnel_type, interface_name, remote_ipv4, local_ipv4, service_file FROM tunnels WHERE id=$id_or_interface OR interface_name='$id_or_interface';")

    if [[ -z $tunnel_info ]]; then
        echo -e "${RED}No tunnel found with the provided ID or interface name.${NC}"
        return
    fi

    tunnel_id=$(echo "$tunnel_info" | awk '{print $1}')
    tunnel_type=$(echo "$tunnel_info" | awk '{print $2}')
    interface_name=$(echo "$tunnel_info" | awk '{print $3}')
    remote_ipv4=$(echo "$tunnel_info" | awk '{print $4}')
    local_ipv4=$(echo "$tunnel_info" | awk '{print $5}')
    service_file=$(echo "$tunnel_info" | awk '{print $6}')

    echo -e "${YELLOW}Tunnel information:${NC}"
    echo -e "${BLUE}ID: ${NC}$tunnel_id"
    echo -e "${BLUE}Tunnel Type: ${NC}$tunnel_type"
    echo -e "${BLUE}Interface Name: ${NC}$interface_name"
    echo -e "${BLUE}Remote IPv4 (Kharej): ${NC}$remote_ipv4"
    echo -e "${BLUE}Local IPv4: ${NC}$local_ipv4"

    if [[ $tunnel_type == "IR" ]]; then
        echo -e "${MAGENTA}Enter the new Remote IPv4 (Kharej):${NC}"
        read new_remote_ipv4
        echo -e "${MAGENTA}Enter the new Local IPv4 (Iran):${NC}"
        read new_local_ipv4

    elif [[ $tunnel_type == "KHAREJ" ]]; then
        echo -e "${MAGENTA}Enter the new Remote IPv4 (Iran):${NC}"
        read new_remote_ipv4
        echo -e "${MAGENTA}Enter the new Local IPv4 (Kharej):${NC}"
        read new_local_ipv4
    else
        echo -e "${RED}Invalid tunnel type.${NC}"
        return
    fi

    if ! validate_ipv4 "$new_remote_ipv4"; then
        echo -e "${RED}Invalid local IPv4 address. Please enter a valid IPv4 address.${NC}"
        return
    fi
    if ! validate_ipv4 "$new_local_ipv4"; then
        echo -e "${RED}Invalid local IPv4 address. Please enter a valid IPv4 address.${NC}"
        return
    fi

    # Update tunnel information in the database
    sqlite3 "$db_file" "UPDATE tunnels SET remote_ipv4='$new_remote_ipv4', local_ipv4='$new_local_ipv4' WHERE id=$tunnel_id;"

    sudo ip tunnel del "$interface_name"
    # Update script file
    update_script_file "$interface_name" "$new_remote_ipv4" "$new_local_ipv4"

    # Reload systemd
    sudo systemctl daemon-reload

    # Restart service
    sudo systemctl restart "$(basename "$service_file")"

    echo -e "${GREEN}Tunnel updated successfully.${NC}"
}

# Function to update the script file
update_script_file() {
    local interface_name=$1
    local new_remote_ipv4=$2
    local new_local_ipv4=$3

    # Get the script file
    script_file=$(ls "tunnel_${interface_name}_"*.sh 2>/dev/null)

    if [[ -z $script_file ]]; then
        echo -e "${RED}Script file not found.${NC}"
        return 1
    fi

    # Update the script file with new IP addresses
    sed -i 's|local [0-9.]\+|local '"$new_local_ipv4"'|' "$script_file"
    sed -i 's|remote [0-9.]\+|remote '"$new_remote_ipv4"'|' "$script_file"

    echo -e "${GREEN}Script file updated successfully.${NC}"
}

# Function to generate a unique local IPv6 address within a specific range for 'IR' or 'KHAREJ'
generate_ipv6() {
    local server_type=$1
    local base="23e7:dc8:9a6::"
    local start=1
    local end=1

    if [ "$server_type" == "IR" ]; then
        start=1
        end=99
    elif [ "$server_type" == "KHAREJ" ]; then
        start=100
        end=200
    else
        echo "Error: Invalid server type specified." >&2
        return 1
    fi

    # Initialize or update the SQLite database for tracking the last IP index
    local last_index=$(sqlite3 "$db_file" "SELECT last_assigned_index FROM ip_state WHERE server_type = '$server_type';")

    if [ -z "$last_index" ] || [ "$last_index" -lt "$start" ] || [ "$last_index" -ge "$end" ]; then
        last_index=$start
    else
        last_index=$((last_index + 1))
    fi

    if [ "$last_index" -gt "$end" ]; then
        echo "Error: No available IPv6 addresses in the range from $start to $end." >&2
        return 1
    fi

    local local_ipv6="${base}${last_index}/64"
    echo "$local_ipv6"

    # Update the database with the new last assigned index
    sqlite3 "$db_file" "INSERT OR REPLACE INTO ip_state (server_type, last_assigned_index) VALUES ('$server_type', '$last_index');"

    return 0
}

increase_user_limits() {
    echo -e "${BLUE}Increasing user limits...${NC}"

    # Apply ulimit settings
    ulimit -c unlimited  # Core file size
    ulimit -d unlimited  # Data segment size
    ulimit -f unlimited  # File size
    ulimit -i unlimited  # Pending signals
    ulimit -l unlimited  # Memory lock size
    ulimit -m unlimited  # Memory size
    ulimit -n 1048576    # Number of open file descriptors
    ulimit -q unlimited  # POSIX message queue size
    ulimit -s 32768      # Stack size (soft limit)
    ulimit -s -H 65536   # Stack size (hard limit)
    ulimit -t unlimited  # CPU time
    ulimit -u unlimited  # Number of processes
    ulimit -v unlimited  # Virtual memory
    ulimit -x unlimited  # File locks

    echo -e "${GREEN}User limits have been increased.${NC}"

    # Ask user if they want to reboot
    read -p "Reboot the system now? (y/n): " confirm_reboot
    if [[ $confirm_reboot =~ ^[Yy]$ ]]; then
        echo -e "${RED}Rebooting now...${NC}"
        sudo reboot
    else
        echo -e "${YELLOW}Reboot canceled. Changes will take full effect after the next reboot.${NC}"
    fi
}

validate_ipv6() {
    local ipv6=$1
    local pattern1='^(([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:))$'
    local pattern2='^(([0-9a-fA-F]{1,4}:){1,7}:)$'
    local pattern3='^::([0-9a-fA-F]{1,4}:){0,6}([0-9a-fA-F]{1,4})?$'
    local pattern4='^([0-9a-fA-F]{1,4}:){1,6}:(:|([0-9a-fA-F]{1,4})(:[0-9a-fA-F]{1,4}){0,5})$'
    local pattern5='^([0-9a-fA-F]{1,4}:){1,5}((:[0-9a-fA-F]{1,4}){1,2}:|:([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4})?)$'
    local pattern6='^([0-9a-fA-F]{1,4}:){1,4}((:[0-9a-fA-F]{1,4}){1,3}:|:([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4})?)$'
    local pattern7='^([0-9a-fA-F]{1,4}:){1,3}((:[0-9a-fA-F]{1,4}){1,4}:|:([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4})?)$'
    local pattern8='^([0-9a-fA-F]{1,4}:){1,2}((:[0-9a-fA-F]{1,4}){1,5}:|:([0-9a-fA-F]{1,4}:)(:[0-9a-fA-F]{1,4})?)$'
    local pattern9='^([0-9a-fA-F]{1,4}:)((:[0-9a-fA-F]{1,4}){1,6}:|:([0-9a-fA-F]{1,4}))$'
    local pattern10='^::(([0-9a-fA-F]{1,4}:){0,7}([0-9a-fA-F]{1,4})?)$'
    local pattern11='^([0-9a-fA-F]{1,4}:){1,4}:(:|([0-9a-fA-F]{1,4})(:[0-9a-fA-F]{1,4}){0,5})([0-9a-fA-F]{1,4})$'

    if [[ $ipv6 =~ $pattern1 ]] || [[ $ipv6 =~ $pattern2 ]] || [[ $ipv6 =~ $pattern3 ]] || \
       [[ $ipv6 =~ $pattern4 ]] || [[ $ipv6 =~ $pattern5 ]] || [[ $ipv6 =~ $pattern6 ]] || \
       [[ $ipv6 =~ $pattern7 ]] || [[ $ipv6 =~ $pattern8 ]] || [[ $ipv6 =~ $pattern9 ]] || \
       [[ $ipv6 =~ $pattern10 ]] || [[ $ipv6 =~ $pattern11 ]]; then
        return 0
    else
        return 1
    fi
}

get_all_release_info() {
  curl --silent "https://api.github.com/repos/go-gost/gost/releases"
}

select_tunnel_type() {
    echo -e "${BLUE}Select the tunnel type:${NC}"
    echo -e "${YELLOW}1) TCP${NC}"
    echo -e "${YELLOW}2) WebSocket (WS)${NC}"
    echo -e "${YELLOW}3) gRPC${NC}"
    echo -n "Enter your choice: "
    read tunnel_type_selection
    case $tunnel_type_selection in
        1) tunnel_type="tcp";;
        2) tunnel_type="ws";;
        3) tunnel_type="grpc";;
        *) echo -e "${RED}Invalid selection${NC}"; return 1;;
    esac
}

create_gost_tunnel_single_port() {
    echo -e "${MAGENTA}Enter the local IPv6 address for KHAREJ:${NC}"
    read local_ipv6
    local_ipv6=${local_ipv6// /}  # Remove all spaces from input

    echo -e "${MAGENTA}Enter Gost Port (comma-separated for multiple ports, e.g., 8080 or 8080,8081,8082):${NC}"
    read ports
    ports=${ports// /}  # Remove all spaces from input

    # Validate the IPv6 address
    if ! validate_ipv6 "$local_ipv6"; then
        echo -e "${RED}Invalid IPv6 address.${NC}"
        return 1
    fi

    # Validate and process the ports
    IFS=',' read -ra PORT_ARRAY <<< "$ports"
    for port in "${PORT_ARRAY[@]}"; do
        if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
            echo -e "${RED}Invalid port: $port${NC}"
            return 1
        fi
    done

    # Allow ports through ufw
    for port in "${PORT_ARRAY[@]}"; do
        sudo ufw allow $port
    done

    # Ensure ports are free
    ensure_ports_free "$ports"

    # Ask for tunnel type (tcp, ws, grpc)
    echo -e "${BLUE}Select tunnel type (1 for tcp, 2 for ws, 3 for grpc):${NC}"
    if ! select_tunnel_type; then
        return 1
    fi

    echo -e "${BLUE}Setting up Gost tunnel on ports ${ports} with $tunnel_type...${NC}"
    gost_cmd=""
    for port in "${PORT_ARRAY[@]}"; do
        if [ -z "$gost_cmd" ]; then
            gost_cmd="-L=$tunnel_type://:$port/[$local_ipv6]:$port"
        else
            gost_cmd="$gost_cmd -- -L=$tunnel_type://:$port/[$local_ipv6]:$port"
        fi
    done

    # Create a unique service name
    service_name="gost_single_$(openssl rand -hex 4)"
    service_file="/etc/systemd/system/$service_name.service"

    # Create a systemd service for the Gost tunnel
    create_gost_service "$service_name" "$service_file" "$gost_cmd"

    # Store tunnel details in the database
    sqlite3 "$db_file" "INSERT INTO gost_tunnels (protocol, local_ipv6, port_range, service_name, service_file, tunnel_type)
                        VALUES ('$tunnel_type', '$local_ipv6', '$ports', '$service_name', '$service_file', 'single');"

    echo -e "${GREEN}Gost tunnel service $service_name created and started successfully.${NC}"
}

create_gost_tunnel_multi_range() {
    echo -e "${MAGENTA}Enter the local IPv6 address for KHAREJ:${NC}"
    read local_ipv6
    local_ipv6=${local_ipv6// /}  # Remove all spaces from input

    echo -e "${MAGENTA}Enter the starting port number for the Gost tunnel:${NC}"
    read start_port

    echo -e "${MAGENTA}Enter the ending port number for the Gost tunnel:${NC}"
    read end_port

    # Validate the IPv6 address
    if ! validate_ipv6 "$local_ipv6"; then
        echo -e "${RED}Invalid IPv6 address.${NC}"
        return 1
    fi

    # Validate the port range
    if ! [[ "$start_port" =~ ^[0-9]+$ ]] || ! [[ "$end_port" =~ ^[0-9]+$ ]] || [ "$start_port" -lt 1 ] || [ "$end_port" -gt 65535 ] || [ "$start_port" -gt "$end_port" ]; then
        echo -e "${RED}Invalid port range.${NC}"
        return 1
    fi

    # Allow ports through ufw
    for port in $(seq $start_port $end_port); do
        sudo ufw allow $port
    done

    # Ensure ports are free
    ensure_ports_free "$ports"

    # Select tunnel type
    if ! select_tunnel_type; then
        return 1
    fi

    echo -e "${BLUE}Setting up Gost tunnel from port $start_port to $end_port with $tunnel_type...${NC}"
    gost_cmd=""

    for port in $(seq $start_port $end_port); do
        if [ -z "$gost_cmd" ]; then
            gost_cmd="-L=$tunnel_type://:$port/[$local_ipv6]:$port"
        else
            gost_cmd="$gost_cmd -- -L=$tunnel_type://:$port/[$local_ipv6]:$port"
        fi
    done

    # Create a unique service name
    service_name="gost_multi_${start_port}_${end_port}_$(openssl rand -hex 4)"
    service_file="/etc/systemd/system/$service_name.service"

    # Stop any existing services that might be using the same ports
    sudo systemctl stop "$service_name" 2>/dev/null || true
    sudo systemctl disable "$service_name" 2>/dev/null || true

    # Create a systemd service for the Gost tunnel
    create_gost_service "$service_name" "$service_file" "$gost_cmd"

    # Store tunnel details in the database
    sqlite3 "$db_file" "INSERT INTO gost_tunnels (protocol, local_ipv6, port_range, service_name, service_file, tunnel_type)
                        VALUES ('$tunnel_type', '$local_ipv6', '$start_port-$end_port', '$service_name', '$service_file', 'multi');"

    echo -e "${GREEN}Gost tunnel service $service_name created and started successfully.${NC}"
}

show_all_gost_tunnels() {
    echo -e "${BLUE}Listing all Gost tunnels:${NC}"
    tunnels=$(sqlite3 "$db_file" "SELECT id, protocol, local_ipv6, port_range, service_name, created_date FROM gost_tunnels;")

    echo -e "${MAGENTA}ID\tProtocol\tRemote IPv6\tPort Range\tService Name\tCreated Date\tService Status${NC}"
    echo -e "${MAGENTA}----------------------------------------------------------------------------------------------------------------------${NC}"

    while IFS='|' read -r id protocol local_ipv6 port_range service_name created_date; do
        service_status=$(systemctl is-active "$service_name" 2>/dev/null)
        echo -e "${YELLOW}$id\t$protocol\t$local_ipv6\t$port_range\t$service_name\t$created_date\t$service_status${NC}"
    done <<< "$tunnels"
}

ensure_ports_free() {
    local port_range=$1
    local start_port
    local end_port

    if [[ "$port_range" == *-* ]]; then
        start_port=$(echo $port_range | cut -d'-' -f1)
        end_port=$(echo $port_range | cut -d'-' -f2)

        for port in $(seq $start_port $end_port); do
            fuser -k ${port}/tcp 2>/dev/null || true
        done
    else
        IFS=',' read -ra PORT_ARRAY <<< "$port_range"
        for port in "${PORT_ARRAY[@]}"; do
            fuser -k ${port}/tcp 2>/dev/null || true
        done
    fi
}

delete_gost_tunnel() {
    echo -e "${MAGENTA}Enter the ID of the Gost tunnel to delete:${NC}"
    read tunnel_id

    # Validate the input to ensure it's a valid number
    if ! [[ "$tunnel_id" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}Invalid ID. Please enter a valid numeric ID.${NC}"
        return 1
    fi

    # Fetch current details from the database
    tunnel_info=$(sqlite3 -separator " " "$db_file" "SELECT service_name, service_file FROM gost_tunnels WHERE id=$tunnel_id;")
    if [[ -z $tunnel_info ]]; then
        echo -e "${RED}No tunnel found with the provided ID.${NC}"
        return 1
    fi

    service_name=$(echo "$tunnel_info" | awk '{print $1}')
    service_file=$(echo "$tunnel_info" | awk '{print $2}')

    # Stop and disable the systemd service using the service name
    sudo systemctl stop "$service_name"
    sudo systemctl disable "$service_name"

    # Remove the service file using the service file path
    if [ -f "$service_file" ]; then
        sudo rm "$service_file"
    else
        echo -e "${YELLOW}Service file $service_file does not exist.${NC}"
    fi

    # Remove the tunnel from the database
    sqlite3 "$db_file" "DELETE FROM gost_tunnels WHERE id=$tunnel_id;"

    echo -e "${GREEN}Gost tunnel service $service_name deleted successfully.${NC}"
}

create_gost_service() {
    local service_name=$1
    local service_file=$2
    local gost_cmd=$3
    cat <<EOF | sudo tee $service_file
[Unit]
Description=Gost Tunnel Service for $service_name
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gost $gost_cmd

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable $service_name
    sudo systemctl start $service_name
    echo -e "${GREEN}Gost tunnel service $service_name started successfully.${NC}"
}

install_gost() {
    # Get all release info
    release_info=$(get_all_release_info)

    # Print release info for debugging
    echo -e "${YELLOW}Release Info:${NC}"
    # Extract the latest version tag and download URL for the Linux AMD64 tar.gz file
    LATEST_VERSION=$(echo "$release_info" | jq -r '.[0].tag_name')
    DOWNLOAD_URL=$(echo "$release_info" | jq -r '.[0].assets[] | select(.name | contains("linux_amd64.tar.gz")).browser_download_url')

    # Print extracted information for debugging
    echo -e "${GREEN}Latest Version: $LATEST_VERSION${NC}"
    echo -e "${GREEN}Download URL: $DOWNLOAD_URL${NC}"

    # Check if the download URL is found
    if [ -z "$DOWNLOAD_URL" ]; then
      echo -e "${RED}Error: Could not find the download URL. Please check the release info.${NC}"
      exit 1
    fi

    # Set installation variables
    INSTALL_DIR="/usr/local/bin"
    INSTALL_PATH="$INSTALL_DIR/gost"

    # Download the latest release
    echo -e "${YELLOW}Downloading gost $LATEST_VERSION...${NC}"
    curl -L -o gost.tar.gz "$DOWNLOAD_URL"

    # Check if the download was successful
    if [[ $? -ne 0 ]]; then
      echo -e "${RED}Error downloading gost. Please check the URL and try again.${NC}"
      exit 1
    fi

    # Extract the downloaded tar.gz file
    echo -e "${GREEN}Extracting gost.tar.gz...${NC}"
    sudo tar -xzf gost.tar.gz

    # Check if the extraction was successful
    if [[ $? -ne 0 ]]; then
      echo -e "${RED}Error extracting gost.tar.gz. Please check the file format.${NC}"
      exit 1
    fi

    # Find the extracted gost binary
    GOST_BINARY_PATH=$(find . -type f -name gost | head -1)

    # Make the gost binary executable
    sudo chmod +x "$GOST_BINARY_PATH"

    # Move the gost binary to the installation directory
    echo -e "${BLUE}Installing gost to $INSTALL_PATH...${NC}"
    sudo mv "$GOST_BINARY_PATH" "$INSTALL_PATH"

    # Verify the installation
    echo -e "${YELLOW}Verifying the installation...${NC}"
    if [[ $? -eq 0 ]]; then
      echo -e "${GREEN}gost $LATEST_VERSION has been installed successfully.${NC}"
    else
      echo -e "${RED}Error installing gost. Please check the installation steps.${NC}"
      exit 1
    fi
}

print_divider() {
    echo -e "${CYAN}-------------------------------------------------${NC}"
}

edit_gost_tunnel() {
    echo -e "${MAGENTA}Enter the ID of the Gost tunnel to edit:${NC}"
    read tunnel_id

    # Validate the input to ensure it's a valid number
    if ! [[ "$tunnel_id" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}Invalid ID. Please enter a valid numeric ID.${NC}"
        return 1
    fi

    # Fetch current details from the database
    tunnel_info=$(sqlite3 -separator " " "$db_file" "SELECT protocol, local_ipv6, port_range, service_name, service_file, tunnel_type FROM gost_tunnels WHERE id=$tunnel_id;")
    if [[ -z $tunnel_info ]]; then
        echo -e "${RED}No tunnel found with the provided ID.${NC}"
        return 1
    fi

    protocol=$(echo "$tunnel_info" | awk '{print $1}')
    local_ipv6=$(echo "$tunnel_info" | awk '{print $2}')
    port_range=$(echo "$tunnel_info" | awk '{print $3}')
    service_name=$(echo "$tunnel_info" | awk '{print $4}')
    service_file=$(echo "$tunnel_info" | awk '{print $5}')
    tunnel_type=$(echo "$tunnel_info" | awk '{print $6}')

    echo -e "${YELLOW}Current Protocol: $protocol${NC}"
    echo -e "${YELLOW}Current Local IPv6: $local_ipv6${NC}"
    echo -e "${YELLOW}Current Port Range: $port_range${NC}"
    echo -e "${YELLOW}Current Tunnel Type: $tunnel_type${NC}"

    echo -e "${MAGENTA}Enter new Local IPv6 address:${NC}"
    read new_local_ipv6
    new_local_ipv6=${new_local_ipv6// /}  # Remove all spaces from input

    if [ "$tunnel_type" == "single" ]; then
        echo -e "${MAGENTA}Enter new Port (comma-separated for multiple ports, e.g., 8080 or 8080,8081,8082):${NC}"
    else
        echo -e "${MAGENTA}Enter new Port Range (e.g., 8080-8085):${NC}"
    fi
    read new_port_range
    new_port_range=${new_port_range// /}  # Remove all spaces from input

    # Validate the new IPv6 address
    if ! validate_ipv6 "$new_local_ipv6"; then
        echo -e "${RED}Invalid IPv6 address.${NC}"
        return 1
    fi

    # Stop, disable, and delete the old service
    sudo systemctl stop "$service_name"
    sudo systemctl disable "$service_name"
    sudo rm "$service_file"

    if [ "$tunnel_type" == "multi" ]; then
        # Multi-range port
        start_port=$(echo $new_port_range | cut -d'-' -f1)
        end_port=$(echo $new_port_range | cut -d'-' -f2)

        # Validate the port range
        if ! [[ "$start_port" =~ ^[0-9]+$ ]] || ! [[ "$end_port" =~ ^[0-9]+$ ]] || [ "$start_port" -lt 1 ] || [ "$end_port" -gt 65535 ] || [ "$start_port" -gt "$end_port" ]; then
            echo -e "${RED}Invalid port range.${NC}"
            return 1
        fi

        # Allow new ports through ufw
        for port in $(seq $start_port $end_port); do
            sudo ufw allow $port
        done

        # Ensure ports are free
        ensure_ports_free "$start_port-$end_port"

        # Generate new service details for multi-range
        gost_cmd=""
        for port in $(seq $start_port $end_port); do
            if [ -z "$gost_cmd" ]; then
                gost_cmd="-L=$protocol://:$port/[$new_local_ipv6]:$port"
            else
                gost_cmd="$gost_cmd -- -L=$protocol://:$port/[$new_local_ipv6]:$port"
            fi
        done

        new_service_name="gost_${protocol}_${start_port}_${end_port}_$(openssl rand -hex 4)"
        new_service_file="/etc/systemd/system/$new_service_name.service"
    else
        # Single port or comma-separated ports
        IFS=',' read -ra PORT_ARRAY <<< "$new_port_range"
        for port in "${PORT_ARRAY[@]}"; do
            if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
                echo -e "${RED}Invalid port: $port${NC}"
                return 1
            fi
        done

        # Allow new ports through ufw
        for port in "${PORT_ARRAY[@]}"; do
            sudo ufw allow $port
        done

        # Ensure ports are free
        ensure_ports_free "$new_port_range"

        # Generate new service details for single/comma-separated ports
        gost_cmd=""
        for port in "${PORT_ARRAY[@]}"; do
            if [ -z "$gost_cmd" ]; then
                gost_cmd="-L=$protocol://:$port/[$new_local_ipv6]:$port"
            else
                gost_cmd="$gost_cmd -- -L=$protocol://:$port/[$new_local_ipv6]:$port"
            fi
        done

        new_service_name="gost_${protocol}_${new_port_range}_$(openssl rand -hex 4)"
        new_service_file="/etc/systemd/system/$new_service_name.service"
    fi

    # Create a new systemd service for the Gost tunnel
    create_gost_service "$new_service_name" "$new_service_file" "$gost_cmd"

    # Update the database with the new service details
    sqlite3 "$db_file" "UPDATE gost_tunnels SET local_ipv6='$new_local_ipv6', port_range='$new_port_range', service_name='$new_service_name', service_file='$new_service_file' WHERE id=$tunnel_id;"

    echo -e "${GREEN}Gost tunnel updated successfully.${NC}"
}

# Main menu function
show_menu() {
    clear
    print_header
    print_divider
    echo -e "${BLUE}Welcome to Feri Tunnel Management Script${NC}"
    print_divider
    echo -e "${YELLOW}1. Create IR Tunnel${NC}"
    echo -e "${YELLOW}2. Create KHAREJ Tunnel${NC}"
    echo -e "${YELLOW}3. Show All Tunnels${NC}"
    echo -e "${YELLOW}4. Edit Tunnel${NC}"
    echo -e "${YELLOW}5. Delete Tunnel${NC}"
    echo -e "${YELLOW}6. Optimize Network${NC}"
    echo -e "${YELLOW}7. Increase User Limit${NC}"
    echo -e "${YELLOW}8. Install Gost v3${NC}"
    echo -e "${YELLOW}9. Create Gost tunnel ipv6 (single port)${NC}"
    echo -e "${YELLOW}10. Create Gost tunnel ipv6 (multi-port)${NC}"
    echo -e "${YELLOW}11. Show Gost Tunnels${NC}"
    echo -e "${YELLOW}12. Edit Gost Tunnel${NC}"
    echo -e "${YELLOW}13. Delete Gost Tunnel${NC}"
    echo -e "${MAGENTA}0. Exit${NC}"
    print_divider
    read -p "Enter your choice [0-13]: " choice
    run_choice "$choice"
}

# Function to handle user choice
run_choice() {
    case $1 in
        1) create_ir_tunnel;;
        2) create_kharej_tunnel;;
        3) show_all_tunnels;;
        4) edit_tunnel;;
        5) delete_tunnel;;
        6) optimize_network;;
        7) increase_user_limits;;
        8) install_gost;;
        9) create_gost_tunnel_single_port;;
        10) create_gost_tunnel_multi_range;;
        11) show_all_gost_tunnels;;
        12) edit_gost_tunnel;;
        13) delete_gost_tunnel;;
        0) echo -e "${RED}Exiting...${NC}"
           exit 0;;
        *) echo -e "${RED}Invalid choice, please select a valid option.${NC}"
           pause;;
    esac
    pause
}

# Pause function for readability
pause() {
    echo -e "${GREEN}Press any key to continue...${NC}"
    read -p "" fackEnterKey
    show_menu
}

# Starting the script with the menu
show_menu
