#!/bin/bash

cd /apps/webui

# Ensure nginx is stopped before we touch environment state so we don't race on
# configuration reloads that still have the old bindings.
NGINX_WAS_ACTIVE=false
if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files | grep -q '^nginx\.service'; then
        if systemctl is-active --quiet nginx 2>/dev/null; then
            echo "Stopping nginx before update..."
            if systemctl stop nginx; then
                NGINX_WAS_ACTIVE=true
            else
                echo "Warning: Failed to stop nginx before update"
            fi
        else
            echo "nginx is not active before update."
        fi
    else
        echo "nginx systemd unit not detected; skipping nginx stop."
    fi
else
    echo "systemctl not available; skipping nginx stop."
fi

# Helper to get IPv4 address of an interface
get_interface_ipv4() {
    local interface="$1"
    ip -4 addr show "$interface" 2>/dev/null | awk '/inet / {print $2}' | cut -d'/' -f1 | head -n 1
}

get_interface_for_ip() {
    local target_ip="$1"
    ip -4 addr show 2>/dev/null | awk '/inet / {print $2 " " $NF}' | while read cidr iface; do
        local addr=${cidr%/*}
        if [ "$addr" = "$target_ip" ]; then
            echo "$iface"
            return 0
        fi
    done
    return 1
}

is_interface_operational() {
    local iface="$1"
    if [ -z "$iface" ]; then
        return 1
    fi
    if [ ! -d "/sys/class/net/$iface" ]; then
        return 1
    fi
    local state
    state=$(cat "/sys/class/net/$iface/operstate" 2>/dev/null)
    case "$state" in
        up|unknown)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

wait_for_interface_ipv4() {
    local interface="$1"
    local timeout="${2:-60}"
    local interval=2
    local waited=0

    while [ "$waited" -lt "$timeout" ]; do
        local addr
        addr=$(get_interface_ipv4 "$interface")
        if [ -n "$addr" ]; then
            echo "$addr"
            return 0
        fi
        sleep "$interval"
        waited=$((waited + interval))
    done
    return 1
}

wait_for_ip_presence() {
    local target_ip="$1"
    local timeout="${2:-60}"
    local interval=3
    local waited=0

    if [ -z "$target_ip" ] || [ "$target_ip" = "0.0.0.0" ] || [ "$target_ip" = "127.0.0.1" ]; then
        return 0
    fi

    while [ "$waited" -lt "$timeout" ]; do
        local iface
        iface=$(get_interface_for_ip "$target_ip")
        if [ -n "$iface" ]; then
            if is_interface_operational "$iface"; then
                if ip route get "$target_ip" >/dev/null 2>&1; then
                    return 0
                fi
            else
                echo "Interface $iface for $target_ip present but not operational (waiting)..."
            fi
        fi
        sleep "$interval"
        waited=$((waited + interval))
    done
    return 1
}

restart_nginx_with_retry() {
    local attempts="${1:-5}"
    local delay="${2:-5}"

    while [ "$attempts" -gt 0 ]; do
        if systemctl restart nginx; then
            if systemctl is-active --quiet nginx; then
                echo "nginx is active."
                return 0
            fi
        fi
        attempts=$((attempts - 1))
        if [ "$attempts" -gt 0 ]; then
            echo "nginx restart failed, retrying in $delay seconds..."
            sleep "$delay"
        fi
    done
    return 1
}

start_nginx_or_schedule_retry() {
    local context="${1:-restart}"

    if ! command -v systemctl >/dev/null 2>&1; then
        echo "systemctl not available; skipping nginx restart."
        return
    fi

    for ip in "$MANAGEMENT_INTERFACE_1" "$MANAGEMENT_INTERFACE_2" "$MANAGEMENT_INTERFACE_3"; do
        if [ -n "$ip" ] && [ "$ip" != "0.0.0.0" ] && [ "$ip" != "127.0.0.1" ]; then
            if wait_for_ip_presence "$ip" 120; then
                echo "Confirmed $ip is present before attempting nginx ${context}."
            else
                echo "Warning: $ip not present after waiting; nginx may fail to bind."
            fi
        fi
    done

    if [ "$NGINX_WAS_ACTIVE" = "true" ]; then
        echo "Starting nginx..."
    else
        if [ "$context" = "restart" ]; then
            echo "Restarting nginx (was inactive before update)..."
        else
            echo "Ensuring nginx is running..."
        fi
    fi

    if restart_nginx_with_retry 12 10; then
        return 0
    fi

    if [ "${CAN_RENDER_NGINX:-0}" = "1" ]; then
        if handle_nginx_bind_failure; then
            if render_nginx_config; then
                if restart_nginx_with_retry 6 5; then
                    return 0
                fi
            else
                echo "Unable to re-render nginx config after bind failure."
            fi
        fi
    fi

    echo "Warning: Failed to restart nginx after multiple attempts."
    echo "nginx will be retried in the background when management IPs become available."

    if [ -z "$NGINX_BACKGROUND_RETRY" ]; then
        NGINX_BACKGROUND_RETRY=true
        (
            for attempt in {1..12}; do
                sleep 20
                for ip in "$MANAGEMENT_INTERFACE_1" "$MANAGEMENT_INTERFACE_2" "$MANAGEMENT_INTERFACE_3"; do
                    if [ -n "$ip" ] && [ "$ip" != "0.0.0.0" ] && [ "$ip" != "127.0.0.1" ] && wait_for_ip_presence "$ip" 5; then
                        if systemctl restart nginx && systemctl is-active --quiet nginx; then
                            echo "nginx successfully restarted in background attempt $attempt." >> /apps/webui/update.log
                            exit 0
                        fi
                    fi
                done
            done
            echo "nginx failed to start in background retries." >> /apps/webui/update.log
        ) &
    fi
}

# Get the IP address of wt0 interface, waiting briefly if needed
WT0_IP=$(get_interface_ipv4 wt0)
if [ -z "$WT0_IP" ]; then
    echo "Waiting for wt0 interface to obtain an IP address..."
    if WT0_IP=$(wait_for_interface_ipv4 wt0 60); then
        echo "wt0 acquired IP: $WT0_IP"
    else
        echo "Warning: wt0 did not obtain an IP address within timeout. Using existing MANAGEMENT_INTERFACE_1 value."
    fi
fi

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

ensure_firewall_ports() {
    if command -v ufw >/dev/null 2>&1; then
        if ufw status | grep -q "Status: active"; then
            echo "Ensuring HTTPS access through UFW..."
            ufw allow 443/tcp >/dev/null 2>&1 || echo "Warning: Failed to allow 443/tcp in UFW"
            ufw allow 80/tcp >/dev/null 2>&1 || echo "Warning: Failed to allow 80/tcp in UFW"
        else
            echo "UFW not enabled; skipping firewall port updates."
        fi
    fi
}

ensure_firewall_ports

# Update or append a value in env.sh
update_env_value() {
    local key="$1"
    local value="$2"

    if grep -q "^export $key=" env.sh; then
        if [ -n "$value" ]; then
            sed -i "s/^export $key=.*/export $key=$value/" env.sh
        else
            sed -i "s/^export $key=.*/export $key=/" env.sh
        fi
    else
        echo "export $key=$value" >> env.sh
    fi
}

render_nginx_config() {
    echo "Updating nginx config..."
    if ! envsubst '${MANAGEMENT_INTERFACE_1},${MANAGEMENT_INTERFACE_2},${MANAGEMENT_INTERFACE_3},${WARHAMMER_VERSION}' < "config/nginx.conf.template" > "config/nginx.conf"; then
        echo "Failed to render nginx config"
        return 1
    fi
    if ! cp "config/nginx.conf" /etc/nginx/conf.d/nginx.conf; then
        echo "Failed to copy nginx config to /etc/nginx/conf.d"
        return 1
    fi
    return 0
}

handle_nginx_bind_failure() {
    local log_line
    log_line=$(journalctl -u nginx -n 20 --no-pager 2>/dev/null | grep 'bind() to' | tail -1)
    if [ -z "$log_line" ]; then
        return 1
    fi

    if [[ $log_line =~ bind\(\)\ to\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+): ]]; then
        local failed_ip="${BASH_REMATCH[1]}"
        local modified=0

        if [ "$failed_ip" = "$MANAGEMENT_INTERFACE_1" ]; then
            echo "Detected nginx bind failure on $failed_ip; falling back to 127.0.0.1 for management interface 1."
            MANAGEMENT_INTERFACE_1="127.0.0.1"
            export MANAGEMENT_INTERFACE_1
            update_env_value "MANAGEMENT_INTERFACE_1" "$MANAGEMENT_INTERFACE_1"
            modified=1
        elif [ "$failed_ip" = "$MANAGEMENT_INTERFACE_2" ]; then
            echo "Detected nginx bind failure on $failed_ip; disabling secondary management interface."
            MANAGEMENT_INTERFACE_2=""
            export MANAGEMENT_INTERFACE_2
            update_env_value "MANAGEMENT_INTERFACE_2" "$MANAGEMENT_INTERFACE_2"
            modified=1
        elif [ "$failed_ip" = "$MANAGEMENT_INTERFACE_3" ]; then
            echo "Detected nginx bind failure on $failed_ip; disabling tertiary management interface."
            MANAGEMENT_INTERFACE_3=""
            export MANAGEMENT_INTERFACE_3
            update_env_value "MANAGEMENT_INTERFACE_3" "$MANAGEMENT_INTERFACE_3"
            modified=1
        fi

        if [ "$modified" -eq 1 ]; then
            # Refresh environment for subsequent commands
            source env.sh
            CAN_RENDER_NGINX=1
            return 0
        fi
    fi

    return 1
}

CAN_RENDER_NGINX=0

# Provide fallback binding targets when management interfaces are unavailable (offline boot)
if [ -z "$MANAGEMENT_INTERFACE_1" ]; then
    echo "Management interface 1 not set; defaulting nginx bind to 127.0.0.1."
    MANAGEMENT_INTERFACE_1="127.0.0.1"
fi
if [ -z "$MANAGEMENT_INTERFACE_2" ]; then
    MANAGEMENT_INTERFACE_2=""
fi
if [ -z "$MANAGEMENT_INTERFACE_3" ]; then
    MANAGEMENT_INTERFACE_3=""
fi

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

# Wait for NetBird to be ready so that nginx isn't restarted before the overlay link is up
wait_for_netbird() {
    local timeout="${1:-60}"
    local interval=3
    local waited=0

    while [ "$waited" -lt "$timeout" ]; do
        if netbird status 2>/dev/null | grep -q "FQDN"; then
            return 0
        fi
        sleep "$interval"
        waited=$((waited + interval))
    done
    return 1
}

if wait_for_netbird 60; then
    PEER_FQDN=$(netbird status | grep "FQDN" | awk '{print $2}')
else
    echo "Warning: NetBird status unavailable after waiting; skipping route synchronization."
fi

#install jq if it is not installed
if ! command -v jq &> /dev/null; then
    apt-get install -y jq
fi

# using the url and the token from the env.sh file, we need to make a request to the netbird api to get the peer id
if [ -n "$PEER_FQDN" ]; then
    PEERS=$(curl -s -X GET -H "Authorization: Bearer $NETBIRD_TOKEN" "https://$NETBIRD_DOMAIN/api/peers")
    THIS_PEER=$(echo "$PEERS" | jq -r '.[] | select(.dns_label == "'"$PEER_FQDN"'")')
    PEER_ID=$(echo "$THIS_PEER" | jq -r '.id')

    if [ -n "$PEER_ID" ] && [ "$PEER_ID" != "null" ]; then
        # Check and create routes for both management interfaces
        check_and_create_route "$MANAGEMENT_INTERFACE_1" "$PEER_ID" "$THIS_PEER"
        if [ ! -z "$MANAGEMENT_INTERFACE_3" ]; then
            check_and_create_route "$MANAGEMENT_INTERFACE_3" "$PEER_ID" "$THIS_PEER"
        fi
    else
        echo "Warning: NetBird peer ID not available; skipping route synchronization."
    fi
else
    echo "Warning: NetBird FQDN not available; skipping route synchronization."
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

    CAN_RENDER_NGINX=0
    start_nginx_or_schedule_retry "ensure"

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

# Step 3.5: SSL Certificate Setup (for nginx)
echo "Setting up SSL certificates for nginx..."
if [ -f "scripts/generate_ssl_cert.py" ]; then
    # Create SSL directory if it doesn't exist
    mkdir -p /etc/warhammer/ssl
    
    # Set environment variables for certificate generation
    export SSL_HOSTNAME="${SSL_HOSTNAME:-localhost}"
    export SSL_IP_ADDRESSES="${SSL_IP_ADDRESSES:-127.0.0.1,0.0.0.0}"
    
    # Generate SSL certificates
    python3 scripts/generate_ssl_cert.py || echo "Warning: SSL certificate generation failed, continuing without SSL..."
    
    # Set proper permissions
    if [ -f "/etc/warhammer/ssl/warhammer.crt" ] && [ -f "/etc/warhammer/ssl/warhammer.key" ]; then
        chmod 600 /etc/warhammer/ssl/warhammer.key
        chmod 644 /etc/warhammer/ssl/warhammer.crt
        chmod 700 /etc/warhammer/ssl
        
        echo "SSL certificates generated successfully for nginx"
        echo "Note: SSL is terminated at nginx level, Flask app runs on HTTP internally"
    else
        echo "Warning: SSL certificate files not found, nginx will not have SSL"
    fi
else
    echo "Warning: scripts/generate_ssl_cert.py not found, nginx will not have SSL"
fi

# Step 3.6: License System Setup
echo "Setting up license system..."
echo "Current directory: $(pwd)"
echo "Available directories:"
ls -la
echo "Looking for issuer_keys directory..."
# Create license system directories
mkdir -p /etc/warhammer/issuer_keys
mkdir -p /etc/warhammer/device_keys

if [ -f "issuer_keys/issuer_public_key.pem" ]; then
    # Copy issuer public key
    cp "issuer_keys/issuer_public_key.pem" "/etc/warhammer/issuer_keys/" || echo "Warning: Failed to copy issuer public key"
    
    # Set proper permissions
    chmod 644 "/etc/warhammer/issuer_keys/issuer_public_key.pem"
    chmod 700 "/etc/warhammer/issuer_keys"
    chmod 700 "/etc/warhammer/device_keys"
    
    echo "License system configured successfully"
else
    echo "Warning: issuer_keys/issuer_public_key.pem not found, license system will not function"
    echo "Current directory: $(pwd)"
    echo "Looking for: issuer_keys/issuer_public_key.pem"
    echo "Available files:"
    ls -la issuer_keys/ 2>/dev/null || echo "issuer_keys directory not found"
fi

# Step 3.7: Device Registration
echo "Running device registration..."
if [ -f "scripts/device_registration.py" ]; then
    python3 scripts/device_registration.py --output /etc/warhammer/device_info.json || echo "Warning: Device registration failed, continuing..."
    echo "Device registration completed"
else
    echo "Warning: scripts/device_registration.py not found, skipping device registration"
fi

# Copy nginx config and restart nginx
# run envsubst on the nginx config to replace the management interfaces
if ! render_nginx_config; then
    handle_error "Failed to update nginx config"
fi
CAN_RENDER_NGINX=1
start_nginx_or_schedule_retry "restart"

echo "Updating netplan templates..."
envsubst '${PORT_1_INTERFACE},${PORT_2_INTERFACE},${BRIDGED_CIDR},${BRIDGE_INTERFACE},${MANAGEMENT_INTERFACE_1}' < "config/bridged.yaml.template" > "/apps/webui/bridged.yaml" || handle_error "Failed to update netplan config"
envsubst '${PORT_1_INTERFACE},${PORT_2_INTERFACE},${BRIDGED_CIDR},${BRIDGE_INTERFACE},${MANAGEMENT_INTERFACE_1}' < "config/unbridged.yaml.template" > "/apps/webui/unbridged.yaml" || handle_error "Failed to update netplan config"

# Step 5: Run the Web Server
echo "Starting the web server..."
nohup python3 app.py &
if [ $? -ne 0 ]; then
    handle_error "Failed to start the web server"
fi

# Show access information
if [ -f "/etc/warhammer/ssl/warhammer.crt" ] && [ -f "/etc/warhammer/ssl/warhammer.key" ]; then
    echo "Web ui started with SSL terminated at nginx level!"
    echo "Access the application at:"
    echo "  HTTPS: https://$MANAGEMENT_INTERFACE_1/management (recommended)"
    echo "  HTTP:  http://$MANAGEMENT_INTERFACE_1/management"
    if [ ! -z "$MANAGEMENT_INTERFACE_2" ]; then
        echo "  HTTPS: https://$MANAGEMENT_INTERFACE_2/management (recommended)"
        echo "  HTTP:  http://$MANAGEMENT_INTERFACE_2/management"
    fi
    if [ ! -z "$MANAGEMENT_INTERFACE_3" ]; then
        echo "  HTTPS: https://$MANAGEMENT_INTERFACE_3/management (recommended)"
        echo "  HTTP:  http://$MANAGEMENT_INTERFACE_3/management"
    fi
    echo ""
    echo "📋 SSL Certificate Installation:"
    echo "  1. Download certificate from: https://$MANAGEMENT_INTERFACE_1/management/api/ssl/certificate"
    echo "  2. Extract the ZIP file"
    echo "  3. Install warhammer.crt in your browser"
    echo "  4. Follow instructions in SSL_SETUP_README.md"
    echo ""
    echo "💡 Note: SSL is terminated at nginx level. Flask app runs on HTTP internally."
else
    echo "Web ui started without SSL (HTTP only)."
    echo "Access the application at:"
    echo "  HTTP: http://$MANAGEMENT_INTERFACE_1/management"
    if [ ! -z "$MANAGEMENT_INTERFACE_2" ]; then
        echo "  HTTP: http://$MANAGEMENT_INTERFACE_2/management"
    fi
    if [ ! -z "$MANAGEMENT_INTERFACE_3" ]; then
        echo "  HTTP: http://$MANAGEMENT_INTERFACE_3/management"
    fi
    echo ""
    echo "⚠️  Note: SSL certificates not found. For production use, generate SSL certificates for nginx."
fi

# Show license system status
echo ""
echo "🔐 License System Status:"
if [ -f "/etc/warhammer/issuer_keys/issuer_public_key.pem" ]; then
    echo "  ✅ License system: ENABLED"
    echo "  📁 Issuer key: /etc/warhammer/issuer_keys/issuer_public_key.pem"
    echo "  📁 Device keys: /etc/warhammer/device_keys/"
    if [ -f "/etc/warhammer/device_info.json" ]; then
        echo "  ✅ Device registration: COMPLETED"
    else
        echo "  ⚠️  Device registration: PENDING"
        echo "  💡 Run device registration to generate device-specific keys"
    fi
else
    echo "  ⚠️  License system: DISABLED (issuer public key not found)"
    echo "  💡 Add issuer_public_key.pem to backend/wh/issuer_keys/ to enable"
fi

# If script reaches this point, update was successful
echo ""
echo "🎉 Warhammer Node upgrade completed successfully!"
echo "📋 Summary:"
echo "  ✅ Application: Updated to version $version"
echo "  ✅ Dependencies: Installed"
if [ -f "/etc/warhammer/ssl/warhammer.crt" ] && [ -f "/etc/warhammer/ssl/warhammer.key" ]; then
    echo "  ✅ SSL: Enabled (nginx termination)"
else
    echo "  ⚠️  SSL: Disabled (no certificates)"
fi
if [ -f "/etc/warhammer/issuer_keys/issuer_public_key.pem" ]; then
    echo "  ✅ License System: Enabled"
else
    echo "  ⚠️  License System: Disabled"
fi
echo "  ✅ Web Server: Running"
echo "  ✅ Nginx: Restarted"
echo ""

# Clean up dist directory
rm -f "$current_dir/$tarball"

# Remove the folder of the previous version
echo "CD to: $current_dir"
cd "$current_dir" || return 1
if [ -n "$previous_version_directory" ]; then
    echo "Removing previous version: $previous_version_directory"
    rm -rf "$previous_version_directory"
fi
