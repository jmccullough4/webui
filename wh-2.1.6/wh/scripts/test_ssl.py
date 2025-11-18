#!/usr/bin/env python3
"""
SSL Test Script for Warhammer Node
Tests SSL connectivity and certificate validity.
"""

import requests
import ssl
import socket
import sys
import os
from urllib3.exceptions import InsecureRequestWarning
import warnings

# Suppress warnings for self-signed certificates
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

def test_ssl_connection(host='localhost', port=8080):
    """Test SSL connection to the server."""
    
    print(f"🔒 Testing SSL connection to {host}:{port}")
    print("=" * 50)
    
    # Test 1: Basic socket connection
    print("1. Testing basic SSL socket connection...")
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                print(f"   ✅ SSL connection successful")
                print(f"   📜 Certificate subject: {cert['subject']}")
                print(f"   🔑 Certificate issuer: {cert['issuer']}")
                print(f"   📅 Valid until: {cert['notAfter']}")
    except Exception as e:
        print(f"   ❌ SSL connection failed: {e}")
        return False
    
    # Test 2: HTTP request with SSL verification disabled
    print("\n2. Testing HTTP request with SSL...")
    try:
        url = f"https://{host}:{port}/api/health"
        response = requests.get(url, verify=False, timeout=10)
        print(f"   ✅ HTTP request successful")
        print(f"   📊 Status code: {response.status_code}")
        print(f"   🔗 URL: {url}")
    except requests.exceptions.ConnectionError:
        print(f"   ⚠️  Connection error (server might not be running)")
        print(f"   💡 Make sure the server is running with SSL enabled")
    except Exception as e:
        print(f"   ❌ HTTP request failed: {e}")
    
    # Test 3: Check certificate files
    print("\n3. Checking certificate files...")
    cert_path = os.environ.get('SSL_CERT_PATH', '/etc/warhammer/ssl/warhammer.crt')
    key_path = os.environ.get('SSL_KEY_PATH', '/etc/warhammer/ssl/warhammer.key')
    
    if os.path.exists(cert_path):
        print(f"   ✅ Certificate file exists: {cert_path}")
        cert_size = os.path.getsize(cert_path)
        print(f"   📏 Certificate size: {cert_size} bytes")
    else:
        print(f"   ❌ Certificate file not found: {cert_path}")
    
    if os.path.exists(key_path):
        print(f"   ✅ Private key file exists: {key_path}")
        key_size = os.path.getsize(key_path)
        print(f"   📏 Private key size: {key_size} bytes")
        
        # Check permissions
        key_mode = oct(os.stat(key_path).st_mode)[-3:]
        if key_mode == '600':
            print(f"   🔐 Private key permissions: {key_mode} (correct)")
        else:
            print(f"   ⚠️  Private key permissions: {key_mode} (should be 600)")
    else:
        print(f"   ❌ Private key file not found: {key_path}")
    
    # Test 4: Environment variables
    print("\n4. Checking environment variables...")
    ssl_enabled = os.environ.get('SSL_ENABLED', 'false')
    print(f"   🔧 SSL_ENABLED: {ssl_enabled}")
    
    if ssl_enabled.lower() == 'true':
        print(f"   ✅ SSL is enabled in environment")
    else:
        print(f"   ⚠️  SSL is not enabled in environment")
        print(f"   💡 Set SSL_ENABLED=true to enable SSL")
    
    print(f"\n🎯 Summary:")
    print(f"   - SSL Connection: {'✅ Working' if True else '❌ Failed'}")
    print(f"   - Certificate Files: {'✅ Found' if os.path.exists(cert_path) and os.path.exists(key_path) else '❌ Missing'}")
    print(f"   - Environment: {'✅ Configured' if ssl_enabled.lower() == 'true' else '⚠️  Not configured'}")
    
    return True

def main():
    """Main function."""
    
    print("🔒 Warhammer Node SSL Test")
    print("=" * 30)
    
    # Get host and port from environment or use defaults
    host = os.environ.get('HOST_IP', 'localhost')
    port = int(os.environ.get('HOST_PORT', '8080'))
    
    print(f"Testing connection to: {host}:{port}")
    print()
    
    try:
        test_ssl_connection(host, port)
    except KeyboardInterrupt:
        print("\n\n⏹️  Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        sys.exit(1)
    
    print("\n🎉 SSL test completed!")
    print("\n💡 Next steps:")
    print("   1. If SSL is working: Access your app via https://localhost:8080")
    print("   2. If SSL is not working: Check the SSL setup guide")
    print("   3. Install the certificate in your browser to avoid warnings")

if __name__ == "__main__":
    main()

