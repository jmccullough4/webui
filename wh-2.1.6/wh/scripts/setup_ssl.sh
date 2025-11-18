#!/bin/bash

# Warhammer Node SSL Setup Script
# This script sets up SSL certificates and configures the application for HTTPS

set -e

echo "🔒 Warhammer Node SSL Setup"
echo "=========================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root (needed for /etc/warhammer directory)
if [[ $EUID -eq 0 ]]; then
    print_status "Running as root - good for system-wide installation"
else
    print_warning "Not running as root. Some operations may fail."
    print_warning "Consider running with sudo for system-wide installation."
fi

# Check Python and dependencies
print_status "Checking Python dependencies..."
if ! python3 -c "import cryptography" 2>/dev/null; then
    print_error "cryptography package not found. Installing..."
    pip3 install cryptography
else
    print_success "cryptography package found"
fi

# Generate SSL certificates
print_status "Generating SSL certificates..."
cd "$(dirname "$0")"

# Set environment variables for certificate generation
export SSL_HOSTNAME="${SSL_HOSTNAME:-localhost}"
export SSL_IP_ADDRESSES="${SSL_IP_ADDRESSES:-127.0.0.1,0.0.0.0}"

print_status "Using hostname: $SSL_HOSTNAME"
print_status "Using IP addresses: $SSL_IP_ADDRESSES"

# Generate the certificate
python3 generate_ssl_cert.py

if [ $? -eq 0 ]; then
    print_success "SSL certificates generated successfully"
else
    print_error "Failed to generate SSL certificates"
    exit 1
fi

# Set environment variables for the application
print_status "Setting up environment variables..."

# Create environment file
ENV_FILE="/etc/warhammer/ssl.env"
sudo tee "$ENV_FILE" > /dev/null << EOF
# SSL Configuration for Warhammer Node
SSL_ENABLED=true
SSL_CERT_PATH=/etc/warhammer/ssl/warhammer.crt
SSL_KEY_PATH=/etc/warhammer/ssl/warhammer.key
SSL_HOSTNAME=$SSL_HOSTNAME
EOF

print_success "Environment file created: $ENV_FILE"

# Create a systemd service file (optional)
print_status "Creating systemd service file..."
SERVICE_FILE="/etc/systemd/system/warhammer-node.service"

sudo tee "$SERVICE_FILE" > /dev/null << EOF
[Unit]
Description=Warhammer Node Application
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$(pwd)
EnvironmentFile=/etc/warhammer/ssl.env
ExecStart=/usr/bin/python3 $(pwd)/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

print_success "Systemd service file created: $SERVICE_FILE"

# Set proper permissions
print_status "Setting proper permissions..."
sudo chmod 600 /etc/warhammer/ssl/warhammer.key
sudo chmod 644 /etc/warhammer/ssl/warhammer.crt
sudo chmod 644 "$ENV_FILE"

print_success "Permissions set correctly"

# Instructions for the user
echo ""
echo "🎉 SSL Setup Complete!"
echo "====================="
echo ""
echo "📋 Next Steps:"
echo "1. Install the certificate in your browser:"
echo "   - Open: /etc/warhammer/ssl/warhammer.crt"
echo "   - Add to trusted certificates"
echo ""
echo "2. Start the application with SSL:"
echo "   Option A - Direct start:"
echo "     export SSL_ENABLED=true"
echo "     export SSL_CERT_PATH=/etc/warhammer/ssl/warhammer.crt"
echo "     export SSL_KEY_PATH=/etc/warhammer/ssl/warhammer.key"
echo "     python3 app.py"
echo ""
echo "   Option B - Use systemd service:"
echo "     sudo systemctl daemon-reload"
echo "     sudo systemctl enable warhammer-node"
echo "     sudo systemctl start warhammer-node"
echo ""
echo "3. Access your application:"
echo "   - HTTPS: https://$SSL_HOSTNAME:8080"
echo "   - You may see browser warnings (normal for self-signed certs)"
echo ""
echo "🔧 Environment variables are saved in: $ENV_FILE"
echo "📁 SSL files are in: /etc/warhammer/ssl/"
echo ""
echo "💡 To disable SSL later, set SSL_ENABLED=false or remove the env file"

