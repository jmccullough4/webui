"""
License Management Routes for Warhammer Node
Handles license activation, validation, and status checking.
"""

from flask import Blueprint, request, jsonify, current_app
import os
import json
import logging
import re
from datetime import datetime

# Import our license manager
from license_manager import DeviceLicenseValidator, DeviceLicenseManager

# Import the protected_route decorator from the main app
from app import protected_route

def validate_license_key_format(license_key):
    """Validate license key format to prevent injection attacks"""
    if not license_key or not isinstance(license_key, str):
        return False, "License key must be a non-empty string"
    
    # Check for reasonable length (base64 encoded keys are typically long)
    if len(license_key) < 100 or len(license_key) > 10000:
        return False, "License key length is invalid"
    
    # Check for valid base64 characters only
    if not re.match(r'^[A-Za-z0-9+/=]+$', license_key):
        return False, "License key contains invalid characters"
    
    return True, None

def sanitize_device_id(device_id):
    """Sanitize device ID to prevent path traversal attacks"""
    if not device_id or not isinstance(device_id, str):
        return None
    
    # Remove any path traversal characters
    device_id = re.sub(r'[./\\]', '', device_id)
    
    # Ensure it's a valid hex string (for SHA256 hashes)
    if not re.match(r'^[a-fA-F0-9]{64}$', device_id):
        return None
    
    return device_id

def log_security_event(event_type, details, user_id=None, device_id=None):
    """Log security-related events for audit purposes"""
    log_data = {
        'timestamp': datetime.utcnow().isoformat(),
        'event_type': event_type,
        'user_id': user_id,
        'device_id': device_id,
        'remote_addr': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', 'Unknown'),
        'details': details
    }
    logger.info(f"SECURITY_EVENT: {json.dumps(log_data)}")

logger = logging.getLogger(__name__)

# Create blueprint
license_bp = Blueprint('license', __name__, url_prefix='/api/license')

@license_bp.route('/status', methods=['GET'])
@protected_route
def get_license_status():
    """Get current license status"""
    try:
        # Get device ID from current user or system
        device_id = get_current_device_id()
        if not device_id:
            logger.warning(f"Device ID not found for user {request.remote_addr}")
            return jsonify({
                'error': 'Device ID not found',
                'status': 'unlicensed'
            }), 400
        
        # Sanitize device ID
        device_id = sanitize_device_id(device_id)
        if not device_id:
            logger.warning(f"Invalid device ID format from {request.remote_addr}")
            return jsonify({
                'error': 'Invalid device ID format',
                'status': 'error'
            }), 400
        
        # Check if issuer public key exists
        issuer_public_key_path = current_app.config.get('ISSUER_PUBLIC_KEY_PATH')
        if not issuer_public_key_path or not os.path.exists(issuer_public_key_path):
            logger.error(f"Issuer public key not configured or missing")
            return jsonify({
                'error': 'Issuer public key not configured',
                'status': 'error'
            }), 500
        
        # Check if device has a valid license
        license_file_path = f"/etc/warhammer/device_keys/{device_id}/license.txt"
        
        if not os.path.exists(license_file_path):
            logger.info(f"License status check: No license found for device {device_id}")
            return jsonify({
                'status': 'unlicensed',
                'device_id': device_id,
                'message': 'No license found'
            })
        
        # Read and validate license
        with open(license_file_path, 'r') as f:
            license_string = f.read().strip()
        
        validator = DeviceLicenseValidator(issuer_public_key_path, device_id)
        is_valid, result = validator.validate_license(license_string)
        
        if is_valid:
            logger.info(f"License status check: Valid license found for device {device_id}")
            return jsonify({
                'status': 'licensed',
                'device_id': device_id,
                'license_info': result,
                'expires_in_days': calculate_days_until_expiry(result['expiry_date'])
            })
        else:
            logger.warning(f"License status check: Invalid/expired license for device {device_id}")
            return jsonify({
                'status': 'expired',
                'device_id': device_id,
                'error': result,
                'message': 'License validation failed'
            })
            
    except Exception as e:
        logger.error(f"Error getting license status: {e}")
        return jsonify({
            'error': 'Internal server error',
            'status': 'error'
        }), 500

@license_bp.route('/activate', methods=['POST'])
@protected_route
def activate_license():
    """Activate a license for the device"""
    try:
        data = request.get_json()
        if not data or 'license_key' not in data:
            logger.warning(f"License activation attempt without license key from {request.remote_addr}")
            return jsonify({
                'error': 'License key is required'
            }), 400
        
        license_key = data['license_key'].strip()
        if not license_key:
            logger.warning(f"License activation attempt with empty license key from {request.remote_addr}")
            return jsonify({
                'error': 'License key cannot be empty'
            }), 400
        
        # Validate license key format
        is_valid_format, format_error = validate_license_key_format(license_key)
        if not is_valid_format:
            logger.warning(f"License activation attempt with invalid format from {request.remote_addr}: {format_error}")
            return jsonify({
                'error': format_error
            }), 400
        
        # Get device ID
        device_id = get_current_device_id()
        if not device_id:
            logger.warning(f"License activation attempt without device ID from {request.remote_addr}")
            return jsonify({
                'error': 'Device ID not found'
            }), 400
        
        # Sanitize device ID
        device_id = sanitize_device_id(device_id)
        if not device_id:
            logger.warning(f"License activation attempt with invalid device ID format from {request.remote_addr}")
            return jsonify({
                'error': 'Invalid device ID format'
            }), 400
        
        # Check if issuer public key exists
        issuer_public_key_path = current_app.config.get('ISSUER_PUBLIC_KEY_PATH')
        if not issuer_public_key_path or not os.path.exists(issuer_public_key_path):
            logger.error(f"Issuer public key not configured for license activation")
            return jsonify({
                'error': 'Issuer public key not configured'
            }), 500
        
        # Validate license
        validator = DeviceLicenseValidator(issuer_public_key_path, device_id)
        is_valid, result = validator.validate_license(license_key)
        
        if not is_valid:
            logger.warning(f"License activation attempt with invalid license for device {device_id} from {request.remote_addr}")
            return jsonify({
                'error': 'Invalid license',
                'details': result
            }), 400
        
        # Save license to device
        license_dir = f"/etc/warhammer/device_keys/{device_id}"
        os.makedirs(license_dir, exist_ok=True)
        
        # Set restrictive permissions on directory
        os.chmod(license_dir, 0o700)
        
        license_file_path = f"{license_dir}/license.txt"
        with open(license_file_path, 'w') as f:
            f.write(license_key)
        
        # Set restrictive permissions on license file
        os.chmod(license_file_path, 0o600)
        
        # Save license metadata
        metadata_path = f"{license_dir}/license_metadata.json"
        metadata = {
            'activated_at': datetime.utcnow().isoformat(),
            'activated_by': 'system',  # Simplified for now
            'license_info': result
        }
        
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Set restrictive permissions on metadata file
        os.chmod(metadata_path, 0o600)
        
        # Log successful activation
        from flask_jwt_extended import get_jwt_identity
        user_id = get_jwt_identity()
        log_security_event('license_activated', {
            'device_id': device_id,
            'license_type': result.get('license_type', 'unknown'),
            'expiry_date': result.get('expiry_date', 'unknown')
        }, user_id, device_id)
        
        logger.info(f"License activated successfully for device {device_id}")
        
        return jsonify({
            'message': 'License activated successfully',
            'device_id': device_id,
            'license_info': result,
            'expires_in_days': calculate_days_until_expiry(result['expiry_date'])
        })
        
    except Exception as e:
        logger.error(f"Error activating license: {e}")
        return jsonify({
            'error': 'Internal server error'
        }), 500

@license_bp.route('/deactivate', methods=['POST'])
@protected_route
def deactivate_license():
    """Deactivate the current license"""
    try:
        device_id = get_current_device_id()
        if not device_id:
            logger.warning(f"License deactivation attempt without device ID from {request.remote_addr}")
            return jsonify({
                'error': 'Device ID not found'
            }), 400
        
        # Sanitize device ID
        device_id = sanitize_device_id(device_id)
        if not device_id:
            logger.warning(f"License deactivation attempt with invalid device ID format from {request.remote_addr}")
            return jsonify({
                'error': 'Invalid device ID format'
            }), 400
        
        license_dir = f"/etc/warhammer/device_keys/{device_id}"
        license_file_path = f"{license_dir}/license.txt"
        metadata_path = f"{license_dir}/license_metadata.json"
        
        # Remove license files
        if os.path.exists(license_file_path):
            os.remove(license_file_path)
        
        if os.path.exists(metadata_path):
            os.remove(metadata_path)
        
        # Log successful deactivation
        from flask_jwt_extended import get_jwt_identity
        user_id = get_jwt_identity()
        log_security_event('license_deactivated', {
            'device_id': device_id
        }, user_id, device_id)
        
        logger.info(f"License deactivated for device {device_id}")
        
        return jsonify({
            'message': 'License deactivated successfully',
            'device_id': device_id
        })
        
    except Exception as e:
        logger.error(f"Error deactivating license: {e}")
        return jsonify({
            'error': 'Internal server error'
        }), 500

@license_bp.route('/info', methods=['GET'])
@protected_route
def get_license_info():
    """Get detailed license information"""
    try:
        device_id = get_current_device_id()
        if not device_id:
            logger.warning(f"License info request without device ID from {request.remote_addr}")
            return jsonify({
                'error': 'Device ID not found'
            }), 400
        
        # Sanitize device ID
        device_id = sanitize_device_id(device_id)
        if not device_id:
            logger.warning(f"License info request with invalid device ID format from {request.remote_addr}")
            return jsonify({
                'error': 'Invalid device ID format'
            }), 400
        
        # Check if license exists
        license_dir = f"/etc/warhammer/device_keys/{device_id}"
        license_file_path = f"{license_dir}/license.txt"
        metadata_path = f"{license_dir}/license_metadata.json"
        
        if not os.path.exists(license_file_path):
            logger.info(f"License info request: No license found for device {device_id}")
            return jsonify({
                'error': 'No license found',
                'status': 'unlicensed'
            }), 404
        
        # Read license metadata
        metadata = {}
        if os.path.exists(metadata_path):
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
        
        # Get current license status
        issuer_public_key_path = current_app.config.get('ISSUER_PUBLIC_KEY_PATH')
        if issuer_public_key_path and os.path.exists(issuer_public_key_path):
            with open(license_file_path, 'r') as f:
                license_string = f.read().strip()
            
            validator = DeviceLicenseValidator(issuer_public_key_path, device_id)
            is_valid, result = validator.validate_license(license_string)
            
            if is_valid:
                logger.info(f"License info request: Valid license found for device {device_id}")
                return jsonify({
                    'status': 'licensed',
                    'device_id': device_id,
                    'license_info': result,
                    'metadata': metadata,
                    'expires_in_days': calculate_days_until_expiry(result['expiry_date']),
                    'is_valid': True
                })
            else:
                logger.warning(f"License info request: Invalid/expired license for device {device_id}")
                return jsonify({
                    'status': 'expired',
                    'device_id': device_id,
                    'metadata': metadata,
                    'error': result,
                    'is_valid': False
                })
        else:
            logger.warning(f"License info request: Issuer public key not available for device {device_id}")
            return jsonify({
                'status': 'unknown',
                'device_id': device_id,
                'metadata': metadata,
                'message': 'Issuer public key not available for validation'
            })
            
    except Exception as e:
        logger.error(f"Error getting license info: {e}")
        return jsonify({
            'error': 'Internal server error'
        }), 500

@license_bp.route('/device-info', methods=['GET'])
@protected_route
def get_device_info():
    """Get current device information"""
    try:
        # Get device ID from current user or system
        device_id = get_current_device_id()
        if not device_id:
            logger.warning(f"Device info request without device ID from {request.remote_addr}")
            return jsonify({
                'error': 'Device ID not found'
            }), 400
        
        # Sanitize device ID
        device_id = sanitize_device_id(device_id)
        if not device_id:
            logger.warning(f"Device info request with invalid device ID format from {request.remote_addr}")
            return jsonify({
                'error': 'Invalid device ID format'
            }), 400
        
        # Try to get device info from the system
        device_info_path = "/etc/warhammer/device_info.json"
        if os.path.exists(device_info_path):
            try:
                with open(device_info_path, 'r') as f:
                    device_info = json.load(f)
                
                # Add current device ID to the response
                device_info['current_device_id'] = device_id
                device_info['last_updated'] = datetime.fromtimestamp(os.path.getmtime(device_info_path)).isoformat()
                
                logger.info(f"Device info retrieved successfully for device {device_id}")
                return jsonify(device_info)
            except Exception as e:
                logger.error(f"Error reading device info file: {e}")
        
        # Fallback: generate device info on-the-fly
        try:
            from license_manager import DeviceLicenseManager
            device_manager = DeviceLicenseManager()
            device_info = device_manager.get_device_info()
            device_info['current_device_id'] = device_id
            device_info['source'] = 'generated'
            
            logger.info(f"Device info generated on-the-fly for device {device_id}")
            return jsonify(device_info)
        except Exception as e:
            logger.error(f"Error generating device info: {e}")
            return jsonify({
                'error': 'Failed to retrieve device information',
                'device_id': device_id
            }), 500
            
    except Exception as e:
        logger.error(f"Error getting device info: {e}")
        return jsonify({
            'error': 'Internal server error'
        }), 500

@license_bp.route('/features', methods=['GET'])
@protected_route
def get_license_features():
    """Get features available with current license"""
    try:
        device_id = get_current_device_id()
        if not device_id:
            logger.warning(f"License features request without device ID from {request.remote_addr}")
            return jsonify({
                'error': 'Device ID not found'
            }), 400
        
        # Sanitize device ID
        device_id = sanitize_device_id(device_id)
        if not device_id:
            logger.warning(f"License features request with invalid device ID format from {request.remote_addr}")
            return jsonify({
                'error': 'Invalid device ID format'
            }), 400
        
        # Check license status
        issuer_public_key_path = current_app.config.get('ISSUER_PUBLIC_KEY_PATH')
        if not issuer_public_key_path or not os.path.exists(issuer_public_key_path):
            logger.error(f"Issuer public key not configured for license features request")
            return jsonify({
                'error': 'Issuer public key not configured'
            }), 500
        
        license_dir = f"/etc/warhammer/device_keys/{device_id}"
        license_file_path = f"{license_dir}/license.txt"
        
        if not os.path.exists(license_file_path):
            logger.info(f"License features request: No license found for device {device_id}")
            return jsonify({
                'features': [],
                'status': 'unlicensed',
                'message': 'No license found'
            })
        
        # Validate license and get features
        with open(license_file_path, 'r') as f:
            license_string = f.read().strip()
        
        validator = DeviceLicenseValidator(issuer_public_key_path, device_id)
        is_valid, result = validator.validate_license(license_string)
        
        if is_valid:
            logger.info(f"License features request: Valid license found for device {device_id}")
            return jsonify({
                'features': result.get('features', []),
                'status': 'licensed',
                'license_type': result.get('license_type', 'unknown'),
                'expires_in_days': calculate_days_until_expiry(result['expiry_date'])
            })
        else:
            logger.warning(f"License features request: Invalid/expired license for device {device_id}")
            return jsonify({
                'features': [],
                'status': 'expired',
                'error': result
            })
            
    except Exception as e:
        logger.error(f"Error getting license features: {e}")
        return jsonify({
            'error': 'Internal server error'
        }), 500

def get_current_device_id():
    """Get the current device ID from various sources"""
    try:
        # Try to get from system configuration
        system_device_id = current_app.config.get('DEVICE_ID')
        if system_device_id:
            return system_device_id
        
        # Try to get from environment variable
        env_device_id = os.environ.get('WARHAMMER_DEVICE_ID')
        if env_device_id:
            return env_device_id
        
        # Try to generate from hardware fingerprint
        from license_manager import DeviceLicenseManager
        device_manager = DeviceLicenseManager()
        return device_manager.device_id
        
    except Exception as e:
        logger.error(f"Error getting device ID: {e}")
        return None

def calculate_days_until_expiry(expiry_date_str):
    """Calculate days until license expires"""
    try:
        expiry_date = datetime.fromisoformat(expiry_date_str)
        now = datetime.utcnow()
        delta = expiry_date - now
        return max(0, delta.days)
    except Exception as e:
        logger.error(f"Error calculating expiry days: {e}")
        return None
