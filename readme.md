
# Tunnel.sh - Feri Tunnel Management Script

## Description

This script sets up and manages the Feri Tunnel, a hypothetical tunneling tool designed for secure and efficient data transfer across networks.

## Features

- Supports Ubuntu and Debian-based systems.
- Optimizes TCP settings for better performance.
- Enables BBR (Bottleneck Bandwidth and Round-trip propagation time).
- Creates, lists, edits, and deletes tunnels.
- Uses SQLite for storing tunnel configurations.

## Prerequisites

- Ubuntu or Debian-based system.
- `sudo` privileges.
- `lsb_release`, `sqlite3`, and `openssl` installed.

## Usage

1. Clone the repository:
    ```bash
    git clone git@github.com:iamfarhad/feri-tunnel.git
    
    cd feri-tunnel
    ```

2. Run the script:
    ```bash
    wget "https://raw.githubusercontent.com/iamfarhad/feri-tunnel/main/tunnel.sh" -O tunnel.sh && chmod +x tunnel.sh && bash tunnel.sh 
    ```

## Script Details

### Functions

- **handle_exit:** Handles Ctrl+C interruption.
- **check_root:** Checks if the script is run as root.
- **check_os:** Checks if the OS is Ubuntu or Debian-based.
- **optimize_tcp:** Optimizes TCP settings.
- **enable_bbr:** Enables BBR for congestion control.
- **install_dependencies:** Updates the system and installs necessary dependencies.
- **create_table:** Creates a SQLite table for tunnels.
- **create_ir_tunnel:** Creates a tunnel with local IPv4 in Iran.
- **create_kharej_tunnel:** Creates a tunnel with local IPv4 outside Iran.
- **create_tunnel:** General function to create a tunnel.
- **generate_systemd_service:** Generates a systemd service for the tunnel.
- **enable_and_start_service:** Enables and starts the systemd service.
- **validate_ipv4:** Validates an IPv4 address.
- **insert_tunnel_info:** Inserts tunnel information into the SQLite database.
- **show_all_tunnels:** Displays all tunnels stored in the SQLite database.
- **delete_tunnel:** Deletes a tunnel based on ID.
- **edit_tunnel:** Edits an existing tunnel.
- **update_script_file:** Updates the script file with new IP addresses.
- **optimize_network:** Optimizes network settings.

### Main Menu Options

1. **Create IR Tunnel:** Sets up a tunnel with a local IPv4 address in Iran.
2. **Create KHAREJ Tunnel:** Sets up a tunnel with a local IPv4 address outside Iran.
3. **Show all tunnels:** Lists all configured tunnels.
4. **Edit a tunnel:** Allows editing of an existing tunnel.
5. **Delete a tunnel:** Deletes a specified tunnel.
6. **Optimize network:** Applies TCP and network optimizations.
7. **Exit:** Exits the script.

## Example

### Creating an IR Tunnel

1. Choose "1. Create IR Tunnel" from the menu.
2. Enter the interface name.
3. Enter the local IPv4 address (Iran).
4. Enter the remote IPv4 address (outside Iran).
5. The script will generate the necessary tunnel creation commands and save them to a script file. It will also create a systemd service to manage the tunnel.

## Troubleshooting

- Ensure you have `sudo` privileges.
- Ensure the required dependencies (`lsb_release`, `sqlite3`, `openssl`) are installed.
- Check if the OS is Ubuntu or Debian-based.
- For any issues with network optimizations, refer to the script for specific sysctl configurations.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.
