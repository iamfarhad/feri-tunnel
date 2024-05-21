#!/bin/bash

# Function to check for root access
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