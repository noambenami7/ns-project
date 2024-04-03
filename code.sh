#!/bin/bash

# Define colors
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Log file path
LOG_FILE="activity.log"

# Enable error handling
set -e

# Function to check and install services
function check_and_install_services() {
    echo "  [#] Checking the services."
    if ! command -v ssh &> /dev/null; then
        echo -e " ${BLUE} [#] Installing SSH...${NC}"
        sudo apt-get install -y openssh-server
    else
        echo -e " ${BLUE} [#] SSH is already installed.${NC}"
    fi

    if ! command -v smbd &> /dev/null; then
        echo -e " ${BLUE} [#] Installing Samba...${NC}"
        sudo apt-get install -y samba
    else
        echo -e " ${BLUE} [#] Samba is already installed.${NC}"
    fi

    if ! command -v vsftpd &> /dev/null; then
        echo -e " ${BLUE} [#] Installing FTP...${NC}"
        sudo apt-get -o Acquire::ForceIPv4=true install -y vsftpd
    else
        echo -e " ${BLUE} [#] FTP is already installed.${NC}"
    fi
}

# Function to start services
function start_service() {
    service_name="$1"
    echo "  [#] Starting $service_name service..."
    if sudo systemctl start "$service_name"; then
        echo -e " ${BLUE} [#] $service_name service started.${NC}"
    else
        echo -e " ${BLUE} [#] Failed to start $service_name service.${NC}"
    fi
}

# Function to create Samba shared directory
function smb_share_directory() {
    # Define the directory path
    local directory_path=$(realpath -q -s ./secret)

    # Check if the directory already exists
    if [ -d "$directory_path" ]; then
        echo -e " ${BLUE} [#] shared smb directory '$directory_path' already exists. ${NC}"
    else
        mkdir -p "$directory_path"

        chmod -R 777 "$directory_path"

        sudo tee -a /etc/samba/smb.conf 

        sudo systemctl restart smbd

        echo -e " ${BLUE} [#] shered smb directory '$directory_path' created. ${NC} "
    fi
}

# Function to create honeypot credentials
function create_honeypot_credentials() {
    read -p "  Do you want to create a new username and password for the honeypot? (yes/no): " choice
    case "$choice" in
        [Yy]|[Yy][Ee][Ss])
            read -p "  Enter the username for the honeypot: " username
            read -sp "  Enter the password for the honeypot: " password
            echo -e "\n"
            # Create the user with the specified username
            sudo useradd "$username"
            # Set the password for the user
            echo "$username:$password" | sudo chpasswd
            echo -e "\nHoneypot credentials created:"
            echo "Username: $username"
            echo "Password: ******** (hidden)"
            ;;
        [Nn]|[Nn][Oo])
            echo "  Moving on without creating new credentials."
            ;;
        *)
            echo "  Please choose 'yes' or 'no'."
            create_honeypot_credentials
            ;;
    esac
}

# Function to handle user connections
function connections() {
    echo " "
    echo -e " ${BLUE} [#] What would you like to choose? :${NC}"
    echo "  1. SSH"
    echo "  2. Samba"
    echo "  3. FTP"
    echo "  4. All of them"

    read -rp "  [#] Choose scan type (1-4): " choice

    case $choice in
        1)
            start_service "ssh"
            ;;
        2)
            start_service "smb"
            smb_share_directory
            ;;
        3)
            start_service "vsftpd"
            ;;
        4)
            echo -e " ${BLUE} [#] All services were chosen ${NC}"
            start_service "ssh"
            start_service "smb"
            smb_share_directory
            start_service "vsftpd"
            ;;
        *)
            echo -e " ${BLUE} [#] Invalid scan type. Exiting.${NC}"
            exit 1
            ;;
    esac
}

# Main function
function main() {
    check_and_install_services
    create_honeypot_credentials
    connections
    monitor_connections
    deepsearch
}

# Function to monitor connections and display unique IPs with service and port number
function monitor_connections() {
    sudo rm -rf /home/kali/activity_log
    sudo touch /home/kali/activity_log
    
    echo "  [#] Waiting for connections..."
    # Associative array to keep track of displayed connections
    declare -A displayed_connections
    
    while true; do
        # Get current connections from netstat and filter by specific ports
        current_connections=$(sudo netstat -natp -t | grep -E "(:21|:22|:445)" | grep "ESTABLISHED")

        # Loop through each line in current connections
        while IFS= read -r line; do
            # Extract IP address, port number, and process name
            date=$(date +"%Y-%m-%d %T")
            ip_address=$(echo "$line" | awk '{print $5}' | grep -oP '(\d{1,3}\.){3}\d{1,3}')
            port_number=$(echo "$line" | awk '{print $4}' | cut -d ':' -f 2)
            process_name=$(echo "$line" | awk '{print $7}')
            
            # Determine if IP is private
            if [[ "$ip_address" =~ ^192\.168\..* || "$ip_address" =~ ^10\..* || "$ip_address" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\..* ]]; then
                whoisdetails="(Private IP - Whois not available)"
            else
                whoisdetails=$(whois "$ip_address" | grep -E 'country|Phone' || echo "Unable to retrieve whois details")
            fi

            # Create a unique key for the connection
            connection_key="$ip_address:$port_number:$process_name"
            
            # Check if this connection has already been displayed
            if [ -z "${displayed_connections[$connection_key]}" ]; then
                # Display the connection information
                echo -e " ${RED} [+] ($date) $ip_address:$port_number ($process_name) $whoisdetails ${NC}"
                echo "  [+] ($date) $ip_address:$port_number ($process_name) $whoisdetails" >> "/home/kali/activity_log"
                
                # Mark this connection as displayed
                displayed_connections[$connection_key]=1
                
                # Run Nmap scan for this IP address
                echo -e "  ${BLUE}[+] Running Nmap scan for $ip_address...${NS}"
                sudo nmap -sV -T3 "$ip_address" >> "/home/kali/nmap_scan.txt"
            fi
        done <<< "$current_connections"

        # Wait for a while before checking again
        sleep 1
    done
}

 main
