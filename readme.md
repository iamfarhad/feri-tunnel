# Feri Tunnel Script

Overview
Based on the shell script you've shared, here's a full Markdown documentation that explains how to use and understand the functionalities within tunnel.sh. This script is designed to manage secure network tunnels, optimize network settings, and handle system services related to these tunnels on Ubuntu or Debian-based systems.

## Requirements

- Bash
- SQLite3
- OpenSSL
- Systemd
- Root privileges

## Usage

### Running the Script

To run the script, use the following command:

```bash
wget "https://raw.githubusercontent.com/iamfarhad/feri-tunnel/main/tunnel.sh" -O tunnel.sh && chmod +x tunnel.sh && bash tunnel.sh 
```


## Features
1. Root and OS Check: Ensures the script is running with root privileges and on a supported Ubuntu or Debian-based system.
2. Dependency Installation: Updates the system and installs necessary packages like sqlite3 and openssl.
3. Network Optimization: Applies performance enhancements to TCP settings and enables BBR (Bottleneck Bandwidth and Round-trip propagation time) congestion control.
4. #### Tunnel Management:
- Create Tunnels: Supports creation of IR (Iran to Kharej) and KHAREJ (Kharej to Iran) tunnels.
- List Tunnels: Displays all configured tunnels from a SQLite database.
- Edit Tunnels: Allows modification of existing tunnel configurations.
- Delete Tunnels: Removes specified tunnels from the system and the database.

# Functions Description
### check_root
  Verifies that the script is run as root, exiting if not.

### check_os
  Checks if the operating system is Ubuntu or Debian-based using lsb_release, exits if not.

### install_dependencies
  Installs and updates necessary packages like sqlite3 and openssl.

### optimize_tcp
  Backs up current TCP settings, then applies optimized settings for better performance.

### enable_bbr
  Enables BBR for improved network congestion control.

### create_ir_tunnel and create_kharej_tunnel
  Prompts user for necessary details and calls create_tunnel to set up an IR or KHAREJ tunnel.

### create_tunnel
  Validates IP addresses, generates a local IPv6 address, creates necessary script and service files, and inserts tunnel info into the SQLite database.

### generate_systemd_service
  Creates a systemd service file for the tunnel and configures it to start on boot.

### validate_ipv4
  Validates the format of IPv4 addresses.

### insert_tunnel_info
  Inserts tunnel details into a SQLite database for record-keeping.

### show_all_tunnels
  Lists all tunnels configured in the SQLite database.

### delete_tunnel
  Deletes specified tunnel by stopping the service, removing configuration files, and deleting database records.

### edit_tunnel
  Allows modification of existing tunnel settings.

### update_script_file
  Updates the tunnel script file with new IP addresses when a tunnel is edited.
