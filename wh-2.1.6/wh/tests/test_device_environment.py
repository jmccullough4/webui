#!/usr/bin/env python3
"""
Test script for device environment setup
Verifies that device environment variables are properly set and accessible.
"""

import os
import sys
import json

def test_device_environment():
    """Test device environment setup"""
    print("🧪 Testing Device Environment Setup")
    print("=" * 40)
    
    # Test 1: Check if device.env file exists
    env_file_path = "/etc/warhammer/device.env"
    print(f"📁 Checking device environment file: {env_file_path}")
    
    if os.path.exists(env_file_path):
        print("✅ Device environment file exists")
        
        # Read and display contents
        try:
            with open(env_file_path, 'r') as f:
                content = f.read()
                print(f"📄 File contents:\n{content}")
        except Exception as e:
            print(f"❌ Error reading file: {e}")
    else:
        print("❌ Device environment file not found")
        print("💡 Run device_registration.py first to create it")
    
    # Test 2: Check environment variables
    print(f"\n🌍 Checking environment variables:")
    device_id_env = os.environ.get('DEVICE_ID')
    warhammer_device_id_env = os.environ.get('WARHAMMER_DEVICE_ID')
    
    if device_id_env:
        print(f"✅ DEVICE_ID: {device_id_env}")
    else:
        print("❌ DEVICE_ID not set in environment")
    
    if warhammer_device_id_env:
        print(f"✅ WARHAMMER_DEVICE_ID: {warhammer_device_id_env}")
    else:
        print("❌ WARHAMMER_DEVICE_ID not set in environment")
    
    # Test 3: Check device info file
    device_info_path = "/etc/warhammer/device_info.json"
    print(f"\n📊 Checking device info file: {device_info_path}")
    
    if os.path.exists(device_info_path):
        print("✅ Device info file exists")
        try:
            with open(device_info_path, 'r') as f:
                device_info = json.load(f)
                device_id_file = device_info.get('device_id')
                if device_id_file:
                    print(f"✅ Device ID from file: {device_id_file}")
                    
                    # Check if it matches environment
                    if device_id_env and device_id_env == device_id_file:
                        print("✅ Environment and file device IDs match!")
                    elif device_id_env:
                        print("⚠️  Environment and file device IDs don't match")
                    else:
                        print("ℹ️  Environment not loaded yet")
                else:
                    print("❌ No device ID found in file")
        except Exception as e:
            print(f"❌ Error reading device info: {e}")
    else:
        print("❌ Device info file not found")
    
    # Test 4: Test license decorator import
    print(f"\n🔒 Testing license decorator import:")
    try:
        from utils.license_decorators import get_current_device_id
        print("✅ License decorators imported successfully")
        
        # Test device ID function
        device_id = get_current_device_id()
        if device_id:
            print(f"✅ get_current_device_id() returned: {device_id}")
        else:
            print("❌ get_current_device_id() returned None")
            
    except ImportError as e:
        print(f"❌ Failed to import license decorators: {e}")
    except Exception as e:
        print(f"❌ Error testing license decorators: {e}")
    
    print(f"\n" + "=" * 40)
    
    # Summary
    if device_id_env or warhammer_device_id_env:
        print("🎉 Device environment is properly configured!")
        return 0
    else:
        print("❌ Device environment is not configured")
        print("\n💡 To fix this:")
        print("1. Run: python3 device_registration.py")
        print("2. Or run: python3 device_registration.py --env-only")
        return 1

def main():
    """Main function"""
    return test_device_environment()

if __name__ == "__main__":
    sys.exit(main())
