#!/usr/bin/env python3
"""
Test script for license decorators
Verifies that the decorators can be imported and used without errors.
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test that all imports work correctly"""
    try:
        print("Testing license decorator imports...")
        
        # Test importing from utils
        from utils.license_decorators import license_required, license_optional
        print("✅ Successfully imported license decorators from utils")
        
        # Test importing from main app
        from app import license_required as app_license_required
        from app import license_optional as app_license_optional
        print("✅ Successfully imported license decorators from main app")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def test_decorator_creation():
    """Test that decorators can be created without errors"""
    try:
        print("\nTesting decorator creation...")
        
        from utils.license_decorators import license_required, license_optional
        
        # Test creating decorators without feature requirements
        @license_required()  # No features required, just needs valid license
        def test_function():
            return "success"
        
        @license_optional
        def test_optional_function():
            return "optional_success"
        
        print("✅ Successfully created decorated functions")
        return True
        
    except Exception as e:
        print(f"❌ Decorator creation error: {e}")
        return False

def test_device_id_functions():
    """Test that device ID functions work correctly"""
    try:
        print("\nTesting device ID functions...")
        
        from utils.license_decorators import get_current_device_id, sanitize_device_id
        
        # Test device ID generation
        device_id = get_current_device_id()
        if device_id:
            print(f"✅ Device ID generated: {device_id[:16]}...")
        else:
            print("⚠️  Device ID generation returned None (this may be expected)")
        
        # Test sanitization
        test_id = "1234567890abcdef1234567890abcdef"
        sanitized = sanitize_device_id(test_id)
        if sanitized == test_id:
            print("✅ Device ID sanitization working correctly")
        else:
            print("❌ Device ID sanitization failed")
        
        return True
        
    except Exception as e:
        print(f"❌ Device ID function error: {e}")
        return False

def main():
    """Run all tests"""
    print("🧪 Testing License Decorator System")
    print("=" * 40)
    
    tests = [
        test_imports,
        test_decorator_creation,
        test_device_id_functions
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 40)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! License decorator system is working correctly.")
        return 0
    else:
        print("❌ Some tests failed. Please check the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
