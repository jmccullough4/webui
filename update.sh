#!/bin/bash

cd /apps/webui

# Get the IP address of wt0 interface
WT0_IP=$(ip addr show wt0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

if [ ! -z "$WT0_IP" ]; then
    # Check if env.sh exists
    if [ -f env.sh ]; then
        # Update or add MANAGEMENT_INTERFACE_1 in env.sh
        if grep -q "^export MANAGEMENT_INTERFACE_1=" env.sh; then
            # Replace existing MANAGEMENT_INTERFACE_1
            sed -i "s/^export MANAGEMENT_INTERFACE_1=.*/export MANAGEMENT_INTERFACE_1=$WT0_IP/" env.sh
        else
            # Add MANAGEMENT_INTERFACE_1 if it doesn't exist
            echo "export MANAGEMENT_INTERFACE_1=$WT0_IP" >> env.sh
        fi
    else
        # Create env.sh if it doesn't exist
        echo "export MANAGEMENT_INTERFACE_1=$WT0_IP" > env.sh
    fi
fi

# Source the env file
source env.sh

# Function to check and create a route for a management interface
check_and_create_route() {
    local interface=$1
    local peer_id=$2
    local this_peer=$3

    # Check if route exists
    ROUTE_EXISTS=$(curl -s -X GET -H "Authorization: Bearer $NETBIRD_TOKEN" "https://$NETBIRD_DOMAIN/api/routes" | \
        jq -r --arg peer "$peer_id" --arg net "$interface/32" \
        'any(.[]; .peer == $peer and .network == $net)')

    if [ "$ROUTE_EXISTS" != "true" ]; then
        echo "Management interface route not found for $interface"
        echo "Creating route for $interface/32"
        PEER_GROUP_IDS=$(echo "$this_peer" | jq -r '.groups[] | .id' | jq -R -s -c 'split("\n")[:-1]')
        echo "Peer group IDs: $PEER_GROUP_IDS"
        DATA=$(jq -n \
            --arg network "$interface/32" \
            --arg peer "$peer_id" \
            --arg hostname "$HOSTNAME Management Interface" \
            --argjson groups "$PEER_GROUP_IDS" \
            '{
                "network": $network,
                "peer": $peer,
                "description": "persistent,ui_interface",
                "network_id": $hostname,
                "enabled": true,
                "metric": 9999,
                "keep_route": true,
                "masquerade": true,
                "groups": $groups
            }')
        echo "Route data: $DATA"
        # Create the route
        curl -s -X POST -H "Authorization: Bearer $NETBIRD_TOKEN" \
             -H "Content-Type: application/json" \
             -d "$DATA" \
             "https://$NETBIRD_DOMAIN/api/routes"
    fi
}

# using the netbird api, we need to make sure that the peer has routes that point to the management interfaces

# Get the peer fqdn from the netbird cli status command where the line starts with "FQDN"
PEER_FQDN=$(netbird status | grep "FQDN" | awk '{print $2}')

#install jq if it is not installed
if ! command -v jq &> /dev/null; then
    apt-get install -y jq
fi

# using the url and the token from the env.sh file, we need to make a request to the netbird api to get the peer id
PEERS=$(curl -s -X GET -H "Authorization: Bearer $NETBIRD_TOKEN" "https://$NETBIRD_DOMAIN/api/peers")
THIS_PEER=$(echo "$PEERS" | jq -r '.[] | select(.dns_label == "'"$PEER_FQDN"'")')
PEER_ID=$(echo "$THIS_PEER" | jq -r '.id')

# Check and create routes for both management interfaces
check_and_create_route "$MANAGEMENT_INTERFACE_1" "$PEER_ID" "$THIS_PEER"
if [ ! -z "$MANAGEMENT_INTERFACE_3" ]; then
    check_and_create_route "$MANAGEMENT_INTERFACE_3" "$PEER_ID" "$THIS_PEER"
fi

# Capture current directory
current_dir=$(pwd)

# Function to handle errors
handle_error() {
    echo "Error: $1"
    rollback
    exit 1
}

# Function to perform rollback
rollback() {
    echo "Rolling back changes..."
    if [ -n "$previous_version_directory" ]; then
        echo "Rolling back to previous version: $previous_version_directory"
        cd $previous_version_directory || exit 1
        cd "wh" || exit 1
        nohup python3 app.py &
    else
        echo "No previous version found to roll back to."
    fi
}

makeSureRunningAndExit() {
    if ! pgrep -f "python3 app.py" >/dev/null; then
        echo "Application not running. Starting the application..."
        cd "wh-$1/wh" || handle_error "Failed to navigate to the app directory"
        nohup python3 app.py &
    else
      echo "Continuing..."
    fi

    cd "$current_dir"
    exit 0
}

# Find the most recent version
previous_version_directory=$(ls -d wh-*/ | sort -r | head -n 1)
previous_version=$(basename "$previous_version_directory" | sed 's/wh-//')
echo "Found previous version: $previous_version at: $previous_version_directory"

# Step 1: Extract the Tarball
tarball=$(find -name "wh-*.tar.gz" -type f -printf "%f\n" | sort -r | head -n 1)

if [ -z "$tarball" ]; then
    echo "No tarball found."
    makeSureRunningAndExit $previous_version
fi

version=$(echo "$tarball" | sed 's/wh-//; s/.tar.gz//')
export WARHAMMER_VERSION=$version

# Check if the previous version matches the tarball version
if [ "$previous_version" = "$version" ]; then
    echo "Previous version matches the tarball version."
    # Clean up dist directory
    rm -f $tarball
    # Check if the application is running
    makeSureRunningAndExit $version
fi

# Stop the current instance (if running)
echo "Stopping current instance..."
pkill -f "python3 app.py" || echo "No instance is currently running"

echo "Extracting tarball: $tarball"
echo "Version: $version"
tar -xzvf "$tarball" || handle_error "Failed to extract the tarball"

# Step 1.5: check for updates to the update script itself, if any are found, update the script and restart
# copy existing script to a temp file so we can reinstate if errrors occur
cp /apps/webui/update.sh /apps/webui/update.sh.bak
# get the latest version of the update script from the extracted tarball
cp /apps/webui/wh-$version/wh/config/update.sh /apps/webui/update.sh.new
# compare the two files
if ! cmp -s /apps/webui/update.sh /apps/webui/update.sh.new; then
    echo "New version of update.sh found, updating and restarting"
    # copy the new version of the update script to the correct location
    cp /apps/webui/update.sh.new /apps/webui/update.sh
    # remove unpacked tarball so that it can be re-extracted when the script is run again
    rm -rf /apps/webui/wh-$version
    # restart the update script - reinstate backup if errors occur
    bash /apps/webui/update.sh
    if [ $? -ne 0 ]; then
        echo "Error occurred while restarting the update script, reinstating backup"
        cp /apps/webui/update.sh.bak /apps/webui/update.sh
    else
        echo "Update script restarted successfully"
        # remove the temp file and new file
        rm /apps/webui/update.sh.new
        rm /apps/webui/update.sh.bak
        exit 0
    fi
else
    echo "No new version of update.sh found"
        # remove the temp file and new file
    rm /apps/webui/update.sh.new
    rm /apps/webui/update.sh.bak
fi

# Step 2: Navigate to the App Directory
cd "wh-$version/wh" || handle_error "Failed to navigate to the app directory"

# Step 3: Install Dependencies
echo "Installing dependencies..."
pip install -r requirements.txt || handle_error "Failed to install dependencies"

# Copy nginx config and restart nginx
# run envsubst on the nginx config to replace the management interfaces
echo "Updating nginx config..."
envsubst '${MANAGEMENT_INTERFACE_1},${MANAGEMENT_INTERFACE_2},${MANAGEMENT_INTERFACE_3},${WARHAMMER_VERSION}' < "config/nginx.conf.template" > "config/nginx.conf" || handle_error "Failed to update nginx config"
cp "config/nginx.conf" /etc/nginx/conf.d/nginx.conf || handle_error "Failed to copy nginx config"
systemctl restart nginx || handle_error "Failed to restart nginx"

echo "updating netplan templates..."
envsubst '${PORT_1_INTERFACE},${PORT_2_INTERFACE},${BRIDGED_CIDR},${BRIDGE_INTERFACE},${MANAGEMENT_INTERFACE_1}' < "config/bridged.yaml.template" > "/apps/webui/bridged.yaml" || handle_error "Failed to update netplan config"
envsubst '${PORT_1_INTERFACE},${PORT_2_INTERFACE},${BRIDGED_CIDR},${BRIDGE_INTERFACE},${MANAGEMENT_INTERFACE_1}' < "config/unbridged.yaml.template" > "/apps/webui/unbridged.yaml" || handle_error "Failed to update netplan config"

# Step 5: Run the Web Server
echo "Starting the web server..."
nohup python3 app.py &
if [ $? -ne 0 ]; then
    handle_error "Failed to start the web server"
fi

echo "Web ui started. Access the application at: http://$MANAGEMENT_INTERFACE_1/management or http://$MANAGEMENT_INTERFACE_2/management"


# If script reaches this point, update was successful
# Clean up dist directory
rm -f "$current_dir/$tarball"

# Remove the folder of the previous version
echo "CD to: $current_dir"
cd "$current_dir" || return 1
if [ -n "$previous_version_directory" ]; then
    echo "Removing previous version: $previous_version_directory"
    rm -rf "$previous_version_directory"
fi
