#!/usr/bin/env python3
"""
SSL Demo Script for Warhammer Node
Demonstrates how to start the server with SSL enabled.
"""

import os
import sys
import subprocess
import time

def check_ssl_files():
    """Check if SSL certificate files exist."""
    cert_path = "/etc/warhammer/ssl/warhammer.crt"
    key_path = "/etc/warhammer/ssl/warhammer.key"
    
    if not os.path.exists(cert_path):
        print(f"❌ SSL certificate not found: {cert_path}")
        print("💡 Run: sudo ./setup_ssl.sh to generate certificates")
        return False
    
    if not os.path.exists(key_path):
        print(f"❌ SSL private key not found: {key_path}")
        print("💡 Run: sudo ./setup_ssl.sh to generate certificates")
        return False
    
    print("✅ SSL certificate files found")
    return True

def set_ssl_environment():
    """Set SSL environment variables."""
    os.environ['SSL_ENABLED'] = 'true'
    os.environ['SSL_CERT_PATH'] = '/etc/warhammer/ssl/warhammer.crt'
    os.environ['SSL_KEY_PATH'] = '/etc/warhammer/ssl/warhammer.key'
    
    print("🔧 SSL environment variables set:")
    print(f"   SSL_ENABLED: {os.environ['SSL_ENABLED']}")
    print(f"   SSL_CERT_PATH: {os.environ['SSL_CERT_PATH']}")
    print(f"   SSL_KEY_PATH: {os.environ['SSL_KEY_PATH']}")

def start_server_with_ssl():
    """Start the server with SSL enabled."""
    print("\n🚀 Starting Warhammer Node with SSL enabled...")
    print("=" * 50)
    
    # Check if SSL files exist
    if not check_ssl_files():
        return False
    
    # Set SSL environment
    set_ssl_environment()
    
    # Get host and port from environment
    host = os.environ.get('HOST_IP', '127.0.0.1')
    port = os.environ.get('HOST_PORT', '8080')
    
    print(f"\n🌐 Server will be available at:")
    print(f"   HTTPS: https://{host}:{port}")
    print(f"   HTTP:  http://{host}:{port}")
    
    print(f"\n⚠️  Note: You may see browser security warnings")
    print(f"   This is normal for self-signed certificates")
    print(f"   Install the certificate in your browser to avoid warnings")
    
    print(f"\n📋 To install the certificate:")
    print(f"   1. Open: /etc/warhammer/ssl/warhammer.crt")
    print(f"   2. Add to your browser's trusted certificates")
    
    print(f"\n🔄 Starting server in 3 seconds...")
    for i in range(3, 0, -1):
        print(f"   {i}...")
        time.sleep(1)
    
    print(f"\n🎯 Starting Warhammer Node...")
    print(f"   Press Ctrl+C to stop the server")
    print("=" * 50)
    
    try:
        # Start the server
        subprocess.run([sys.executable, "app.py"], check=True)
    except KeyboardInterrupt:
        print(f"\n⏹️  Server stopped by user")
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Server failed to start: {e}")
        return False
    
    return True

def main():
    """Main function."""
    print("🔒 Warhammer Node SSL Demo")
    print("=" * 30)
    
    # Check if we're in the right directory
    if not os.path.exists("app.py"):
        print("❌ app.py not found in current directory")
        print("💡 Run this script from the backend/wh directory")
        sys.exit(1)
    
    # Start server with SSL
    if start_server_with_ssl():
        print("\n🎉 SSL demo completed successfully!")
    else:
        print("\n❌ SSL demo failed")
        sys.exit(1)

if __name__ == "__main__":
    main()

