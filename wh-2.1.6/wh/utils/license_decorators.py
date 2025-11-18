"""
License Decorators for Warhammer Node Backend
Provides license enforcement decorators for API endpoints.
"""

import os
import logging
from functools import wraps
from flask import request, jsonify, current_app

logger = logging.getLogger(__name__)

def load_device_environment():
    """Load device environment variables from file"""
    try:
        env_file_path = "/etc/warhammer/device.env"
        if os.path.exists(env_file_path):
            with open(env_file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        os.environ[key] = value
                        logger.debug(f"Loaded device environment: {key}={value}")
            return True
    except Exception as e:
        logger.debug(f"Failed to load device environment: {e}")
    return False

def get_current_device_id():
    """Get current device ID from request or system"""
    try:
        # First, try to load device environment if not already loaded
        if not os.environ.get('DEVICE_ID') and not os.environ.get('WARHAMMER_DEVICE_ID'):
            load_device_environment()
        
        # Try to get from request headers first (for multi-device scenarios)
        device_id = request.headers.get('X-Device-ID')
        if device_id:
            logger.debug(f"Device ID from request header: {device_id}")
            return device_id
        
        # Try to get from environment variables
        device_id = os.environ.get('DEVICE_ID') or os.environ.get('WARHAMMER_DEVICE_ID')
        if device_id:
            logger.debug(f"Device ID from environment: {device_id}")
            return device_id
        
        # Try to get from Flask app config
        device_id = current_app.config.get('DEVICE_ID')
        if device_id:
            logger.debug(f"Device ID from app config: {device_id}")
            return device_id
        
        # Try to read from device info file as last resort
        try:
            device_info_path = "/etc/warhammer/device_info.json"
            if os.path.exists(device_info_path):
                import json
                with open(device_info_path, 'r') as f:
                    device_info = json.load(f)
                    device_id = device_info.get('device_id')
                    if device_id:
                        logger.debug(f"Device ID from device info file: {device_id}")
                        return device_id
        except Exception as e:
            logger.debug(f"Failed to read device info file: {e}")
        
        # Generate from system info as absolute last resort
        logger.warning("No device ID found, generating from system info")
        import hashlib
        import platform
        
        system_info = f"{platform.node()}-{platform.machine()}-{platform.processor()}"
        device_id = hashlib.sha256(system_info.encode()).hexdigest()[:32]
        
        logger.info(f"Generated device ID from system info: {device_id}")
        return device_id
        
    except Exception as e:
        logger.error(f"Error getting device ID: {e}")
        return None

def sanitize_device_id(device_id):
    """Sanitize device ID to prevent injection attacks"""
    if not device_id or not isinstance(device_id, str):
        return None
    
    # Check for reasonable length (device IDs are typically 32-64 chars)
    if len(device_id) < 16 or len(device_id) > 128:
        return None
    
    # Check for valid hex characters only
    if not all(c in '0123456789abcdefABCDEF' for c in device_id):
        return None
    
    return device_id

def license_required(required_features=None, allow_unlicensed=False, fallback_response=None):
    """
    Decorator to enforce license requirements for API endpoints.
    
    Args:
        required_features (list, optional): List of specific features required.
                                          If None, any valid license is sufficient.
        allow_unlicensed (bool): Whether to allow access when unlicensed.
                                Default False.
        fallback_response (dict, optional): Custom response when license check fails.
    
    Usage:
        @app.route('/api/peers')
        @license_required(['peers', 'network'])
        def get_peers():
            return jsonify(peers)
            
        @app.route('/api/admin/users')
        @admin_required
        @license_required(['user_management'])
        def get_users():
            return jsonify(users)
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                # Get device ID from current user or system
                device_id = get_current_device_id()
                if not device_id:
                    logger.warning(f"License check failed: Device ID not found for user {request.remote_addr}")
                    if fallback_response:
                        return jsonify(fallback_response), 403
                    return jsonify({
                        "error": "License check failed",
                        "message": "Device ID not found",
                        "code": "DEVICE_ID_MISSING"
                    }), 403
                
                # Sanitize device ID
                device_id = sanitize_device_id(device_id)
                if not device_id:
                    logger.warning(f"License check failed: Invalid device ID format from {request.remote_addr}")
                    if fallback_response:
                        return jsonify(fallback_response), 403
                    return jsonify({
                        "error": "License check failed",
                        "message": "Invalid device ID format",
                        "code": "INVALID_DEVICE_ID"
                    }), 403
                
                # Check if issuer public key exists
                issuer_public_key_path = current_app.config.get('ISSUER_PUBLIC_KEY_PATH')
                if not issuer_public_key_path or not os.path.exists(issuer_public_key_path):
                    logger.error(f"License check failed: Issuer public key not configured")
                    if fallback_response:
                        return jsonify(fallback_response), 403
                    return jsonify({
                        "error": "License check failed",
                        "message": "License system not configured",
                        "code": "LICENSE_SYSTEM_ERROR"
                    }), 500
                
                # Check if device has a valid license
                license_file_path = f"/etc/warhammer/device_keys/{device_id}/license.txt"
                
                if not os.path.exists(license_file_path):
                    if allow_unlicensed:
                        logger.info(f"License check: No license found for device {device_id}, but access allowed")
                        return fn(*args, **kwargs)
                    else:
                        logger.info(f"License check failed: No license found for device {device_id}")
                        if fallback_response:
                            return jsonify(fallback_response), 403
                        return jsonify({
                            "error": "License required",
                            "message": "This feature requires a valid license",
                            "code": "LICENSE_REQUIRED",
                            "device_id": device_id
                        }), 403
                
                # Read and validate license
                with open(license_file_path, 'r') as f:
                    license_string = f.read().strip()
                
                try:
                    from license_manager import DeviceLicenseValidator
                    validator = DeviceLicenseValidator(issuer_public_key_path, device_id)
                    is_valid, result = validator.validate_license(license_string)
                except ImportError:
                    logger.warning(f"License check: License manager not available, assuming valid")
                    is_valid = True
                    result = {}
                
                if not is_valid:
                    if allow_unlicensed:
                        logger.info(f"License check: Invalid license for device {device_id}, but access allowed")
                        return fn(*args, **kwargs)
                    else:
                        logger.warning(f"License check failed: Invalid/expired license for device {device_id}")
                        if fallback_response:
                            return jsonify(fallback_response), 403
                        return jsonify({
                            "error": "License invalid",
                            "message": "Your license is invalid or expired",
                            "code": "LICENSE_INVALID",
                            "device_id": device_id,
                            "details": result
                        }), 403
                
                # If specific features are required, check them
                if required_features and isinstance(required_features, list):
                    available_features = result.get('features', [])
                    missing_features = [feature for feature in required_features if feature not in available_features]
                    
                    if missing_features:
                        logger.warning(f"License check failed: Missing required features {missing_features} for device {device_id}")
                        if fallback_response:
                            return jsonify(fallback_response), 403
                        return jsonify({
                            "error": "Insufficient license",
                            "message": f"This feature requires: {', '.join(missing_features)}",
                            "code": "INSUFFICIENT_LICENSE",
                            "device_id": device_id,
                            "missing_features": missing_features,
                            "available_features": available_features
                        }), 403
                
                # License check passed
                logger.debug(f"License check passed for device {device_id}")
                return fn(*args, **kwargs)
                
            except Exception as e:
                logger.error(f"License check error: {e}")
                if fallback_response:
                    return jsonify(fallback_response), 403
                return jsonify({
                    "error": "License check failed",
                    "message": "An error occurred during license validation",
                    "code": "LICENSE_CHECK_ERROR"
                }), 500
        
        return wrapper
    return decorator

def license_optional(fn):
    """
    Decorator that makes license checking optional - endpoint works with or without license.
    Useful for endpoints that provide different functionality based on license status.
    
    Usage:
        @app.route('/api/status')
        @license_optional
        def get_status():
            # This endpoint will work regardless of license status
            return jsonify(status)
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Add license status to request context for the endpoint to use
        try:
            device_id = get_current_device_id()
            if device_id:
                device_id = sanitize_device_id(device_id)
                if device_id:
                    license_file_path = f"/etc/warhammer/device_keys/{device_id}/license.txt"
                    if os.path.exists(license_file_path):
                        issuer_public_key_path = current_app.config.get('ISSUER_PUBLIC_KEY_PATH')
                        if issuer_public_key_path and os.path.exists(issuer_public_key_path):
                            try:
                                from license_manager import DeviceLicenseValidator
                                with open(license_file_path, 'r') as f:
                                    license_string = f.read().strip()
                                validator = DeviceLicenseValidator(issuer_public_key_path, device_id)
                                is_valid, result = validator.validate_license(license_string)
                                request.license_status = 'licensed' if is_valid else 'expired'
                                request.license_info = result if is_valid else None
                            except:
                                request.license_status = 'unknown'
                                request.license_info = None
                        else:
                            request.license_status = 'unknown'
                            request.license_info = None
                    else:
                        request.license_status = 'unlicensed'
                        request.license_info = None
                else:
                    request.license_status = 'unknown'
                    request.license_info = None
            else:
                request.license_status = 'unknown'
                request.license_info = None
        except:
            request.license_status = 'unknown'
            request.license_info = None
        
        return fn(*args, **kwargs)
    
    return wrapper
