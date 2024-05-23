
# Tunnel.sh - Feri Tunnel Management Script

## Overview

This script sets up and manages the Feri Tunnel, a hypothetical tunneling tool designed for secure and efficient data transfer across networks.


telegram group https://t.me/feritunnel

![Screenshot from 2024-05-24 00-18-34](https://github.com/iamfarhad/feri-tunnel/assets/1936147/4294ec25-4953-462d-bd69-0cbaa09ade04)



## Table of Contents

- [For End Users](#for-end-users)
  - [Description](#description)
  - [Usage](#usage)
  - [Example](#example)
- [For Developers](#for-developers)
  - [Script Details](#script-details)
  - [Development Setup](#development-setup)
  - [Extending the Script](#extending-the-script)

## For End Users

### Description

The Feri Tunnel script is ideal for system administrators and users who need to establish secure and optimized network tunnels across different geographic locations.

### Usage

1. **Installation**:
   Clone the repository and navigate to the script directory:
   ```bash
   git clone git@github.com:iamfarhad/feri-tunnel.git
   cd feri-tunnel
   ```

2. **Running the Script**:
   Download and execute the script:
   ```bash
   wget "https://raw.githubusercontent.com/iamfarhad/feri-tunnel/main/tunnel.sh" -O tunnel.sh && chmod +x tunnel.sh && bash tunnel.sh 
   ```

### Example

#### Creating an IR Tunnel

- **Steps**:
  1. Select "Create IR Tunnel" from the menu.
  2. Enter the interface name, e.g., `tun0`.
  3. Enter the local IPv4 address in Iran, e.g., `192.168.1.1`.
  4. Enter the remote IPv4 address outside Iran, e.g., `10.1.1.1`.
  5. Confirm to generate the tunnel setup commands.

- **Verify Connection**:
  Ping the generated local IPv6 address:
  ```bash
  ping6 <Generated Local IPV6>
  ```

## For Developers

### Script Details

The script includes multiple functions designed to streamline tunnel management and optimize network settings.

### Development Setup

1. **Dependencies**:
   Ensure `lsb_release`, `sqlite3`, and `openssl` are installed:
   ```bash
   sudo apt install lsb-release sqlite3 openssl
   ```

2. **Clone the Repository**:
   ```bash
   git clone git@github.com:iamfarhad/feri-tunnel.git
   ```

3. **Run the Script**:
   Modify and execute the script locally for development:
   ```bash
   ./tunnel.sh
   ```


### Extending the Script

Developers can extend the script by adding new features or enhancing existing functionalities:

- **Add New Tunnel Types**:
  Modify the `create_tunnel` function to support new tunneling protocols.

- **Improve Security Features**:
  Incorporate advanced encryption methods within the tunnel creation process.

- **Enhance Performance Optimization**:
  Update the `optimize_network` function with the latest TCP tuning parameters.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.
