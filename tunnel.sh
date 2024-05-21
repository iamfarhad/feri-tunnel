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
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

source optimization/tcp.sh
source optimization/requirement.sh

# Function to handle Ctrl+C (SIGINT)
handle_exit() {
    echo -e "\n${YELLOW}Ctrl+C detected. Do you really want to exit? (y/n)${NC}"
    read answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        echo -e "${RED}Exiting...${NC}"
        exit 0
    fi
}

# Trap Ctrl+C (SIGINT)
trap handle_exit SIGINT

# Call the check functions
check_root
check_os
install_dependencies

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
    );"
}

# Ensure SQLite database is created and table is initialized
create_table

# Function to create an IR tunnel
create_ir_tunnel() {
    echo -e "${BLUE}Creating IR Tunnel${NC}"

    echo -e "${BLUE}Enter the interface name:${NC}"
    read interface_name

    echo -e "${BLUE}Enter the local IPv4 address (Iran):${NC}"
    read local_ipv4

    echo -e "${BLUE}Enter the remote IPv4 address (Kharej):${NC}"
    read remote_ipv4

    create_tunnel $interface_name $local_ipv4 $remote_ipv4 "IR"
}

# Function to create a KHAREJ tunnel
create_kharej_tunnel() {
    echo -e "${BLUE}Creating KHAREJ Tunnel${NC}"

    echo -e "${BLUE}Enter the interface name:${NC}"
    read interface_name

    echo -e "${BLUE}Enter the local IPv4 address (Kharej):${NC}"
    read local_ipv4

    echo -e "${BLUE}Enter the remote IPv4 address (Iran):${NC}"
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

    # Generate a random local IPv6 address in the fc00::/7 range
    local_ipv6=$(openssl rand -hex 8 | sed 's/\(..\)/\1:/g; s/.$//' | awk -F: '{print "fc00:" $1 $2 ":" $3 $4 "::1/64"}')

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
    echo -e "${YELLOW}Your local IPv6 address is: $local_ipv6${NC}"

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
    echo -e "${YELLOW}Script file path: $script_file_path${NC}"
    echo -e "${YELLOW}Service file path: $service_file_path${NC}"
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
                         VALUES ('$interface_name', '$remote_ipv4', '$local_ipv4', '$local_ipv6', '$script_file', '$service_file_path', '$tunnel_type');"
}

# Function to display all tunnels from SQLite database
show_all_tunnels() {
    echo -e "${BLUE}Listing all tunnels:${NC}"
    sqlite3 -header -column "$db_file" "SELECT id, interface_name, created_date, remote_ipv4, local_ipv4, local_ipv6, script_file, service_file, tunnel_type FROM tunnels;"
}

# Function to delete a tunnel
delete_tunnel() {
    echo -e "${BLUE}Deleting a tunnel${NC}"
    echo -e "${BLUE}Enter the ID of the tunnel to delete:${NC}"
    read tunnel_id

    # Get script file path, service file path, and interface name
    script_file=$(sqlite3 -separator " " "$db_file" "SELECT script_file FROM tunnels WHERE id=$tunnel_id;")
    service_file=$(sqlite3 -separator " " "$db_file" "SELECT service_file FROM tunnels WHERE id=$tunnel_id;")
    interface_name=$(sqlite3 -separator " " "$db_file" "SELECT interface_name FROM tunnels WHERE id=$tunnel_id;")

    # Remove tunnel from system
    sudo systemctl stop "$(basename "$service_file" .service)"
    sudo systemctl disable "$(basename "$service_file" .service)"
    sudo rm "$service_file"
    sudo rm "$script_file"

    # Delete tunnel from Ubuntu
    sudo ip tunnel del $interface_name

    # Remove tunnel from database
    sqlite3 "$db_file" "DELETE FROM tunnels WHERE id=$tunnel_id;"

    echo -e "${GREEN}Tunnel deleted successfully.${NC}"
}

# Function to edit a tunnel
edit_tunnel() {
    echo -e "${BLUE}Editing a tunnel${NC}"
    echo -e "${BLUE}Enter the ID or interface name of the tunnel to edit:${NC}"
    read id_or_interface

    # Fetch tunnel information based on ID or interface name
    tunnel_info=$(sqlite3 -separator " " "$db_file" "SELECT id, tunnel_type, interface_name, remote_ipv4, local_ipv4 FROM tunnels WHERE id=$id_or_interface OR interface_name='$id_or_interface';")

    if [[ -z $tunnel_info ]]; then
        echo -e "${RED}No tunnel found with the provided ID or interface name.${NC}"
        return
    fi

    tunnel_id=$(echo "$tunnel_info" | awk '{print $1}')
    tunnel_type=$(echo "$tunnel_info" | awk '{print $2}')
    interface_name=$(echo "$tunnel_info" | awk '{print $3}')
    remote_ipv4=$(echo "$tunnel_info" | awk '{print $4}')
    local_ipv4=$(echo "$tunnel_info" | awk '{print $5}')

    echo -e "${YELLOW}Tunnel information:${NC}"
    echo -e "${BLUE}ID: ${NC}$tunnel_id"
    echo -e "${BLUE}Tunnel Type: ${NC}$tunnel_type"
    echo -e "${BLUE}Interface Name: ${NC}$interface_name"
    echo -e "${BLUE}Remote IPv4 (Kharej): ${NC}$remote_ipv4"
    echo -e "${BLUE}Local IPv4: ${NC}$local_ipv4"

    if [[ $tunnel_type == "IR" ]]; then
        echo -e "${BLUE}Enter the new Remote IPv4 (Kharej):${NC}"
        read new_remote_ipv4
        echo -e "${BLUE}Enter the new Local IPv4 (Iran):${NC}"
        read new_local_ipv4
    elif [[ $tunnel_type == "KHAREJ" ]]; then
        echo -e "${BLUE}Enter the new Remote IPv4 (Iran):${NC}"
        read new_remote_ipv4
        echo -e "${BLUE}Enter the new Local IPv4 (Kharej):${NC}"
        read new_local_ipv4
    else
        echo -e "${RED}Invalid tunnel type.${NC}"
        return
    fi

    # Update tunnel information in the database
    sqlite3 "$db_file" "UPDATE tunnels SET remote_ipv4='$new_remote_ipv4', local_ipv4='$new_local_ipv4' WHERE id=$tunnel_id;"


    sudo ip tunnel del $interface_name
    # Update script file
    update_script_file "$interface_name" "$new_remote_ipv4" "$new_local_ipv4"

    # Reload systemd
    sudo systemctl daemon-reload

    # Restart service
    sudo systemctl restart "tunnel_${interface_name}_*.service"

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

# Function to optimize TCP settings for performance



# Main menu
while true; do
    echo ""
    echo -e "${BLUE}Menu:${NC}"
    echo -e "${YELLOW}1. Create IR Tunnel${NC}"
    echo -e "${YELLOW}2. Create KHAREJ Tunnel${NC}"
    echo -e "${YELLOW}3. Show all tunnels${NC}"
    echo -e "${YELLOW}4. Edit a tunnel${NC}"
    echo -e "${YELLOW}5. Delete a tunnel${NC}"
    echo -e "${YELLOW}6. Optimize network${NC}"
    echo -e "${YELLOW}7. Exit${NC}"

    read -p "Enter your choice: " choice
    case $choice in
        1)
            create_ir_tunnel
            ;;
        2)
            create_kharej_tunnel
            ;;
        3)
            show_all_tunnels
            ;;
        4)
            edit_tunnel
            ;;
        5)
            delete_tunnel
            ;;
        6)
            optimize_network
            ;;
        7)
            echo -e "${RED}Exiting...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice. Please enter a valid option (1-5).${NC}"
            ;;
    esac
done
