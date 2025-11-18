# License Decorator Implementation Guide

This guide shows how to implement the new backend license decorators without breaking existing functionality.

## Available Decorators

### 1. `@license_required(required_features=None, allow_unlicensed=False, fallback_response=None)`

**Purpose**: Enforces license requirements for API endpoints.

**Parameters**:
- `required_features`: List of specific features required (optional)
- `allow_unlicensed`: Whether to allow access when unlicensed (default: False)
- `fallback_response`: Custom response when license check fails (optional)

### 2. `@license_optional`

**Purpose**: Makes license checking optional - endpoint works with or without license.

## Implementation Examples

### Example 1: Basic License Enforcement

```python
from app import license_required

@app.route('/api/peers')
@protected_route
@license_required(['peers', 'network'])
def get_peers():
    """Get network peers - requires 'peers' and 'network' features"""
    return jsonify(peers)
```

### Example 2: Admin + License Enforcement

```python
from app import admin_required, license_required

@app.route('/api/admin/users')
@protected_route
@admin_required
@license_required(['user_management'])
def get_users():
    """Get users - requires admin role AND 'user_management' feature"""
    return jsonify(users)
```

### Example 3: Custom Fallback Response

```python
@app.route('/api/advanced-analytics')
@protected_route
@license_required(
    required_features=['analytics'],
    fallback_response={
        "error": "Premium Feature",
        "message": "Advanced analytics requires a premium license",
        "upgrade_url": "/license/upgrade"
    }
)
def get_analytics():
    """Get advanced analytics - requires 'analytics' feature"""
    return jsonify(analytics_data)
```

### Example 4: Allow Unlicensed Access

```python
@app.route('/api/basic-status')
@protected_route
@license_required(allow_unlicensed=True)
def get_basic_status():
    """Get basic status - works with or without license"""
    return jsonify(basic_status)
```

### Example 5: License Optional Endpoint

```python
from app import license_optional

@app.route('/api/status')
@protected_route
@license_optional
def get_status():
    """Get status - license status available in request context"""
    status = {
        "system": "operational",
        "license_status": getattr(request, 'license_status', 'unknown'),
        "features": getattr(request, 'license_info', {}).get('features', [])
    }
    
    if request.license_status == 'licensed':
        status["premium_features"] = ["advanced_monitoring", "custom_alerts"]
    
    return jsonify(status)
```

## Migration Strategy

### Phase 1: Add License Checks to Critical Endpoints

Start with endpoints that provide core functionality:

```python
# Before
@app.route('/api/peers')
@protected_route
def get_peers():
    return jsonify(peers)

# After
@app.route('/api/peers')
@protected_route
@license_required(['peers'])
def get_peers():
    return jsonify(peers)
```

### Phase 2: Add Feature-Specific Requirements

```python
# Before
@app.route('/api/admin/users')
@protected_route
@admin_required
def get_users():
    return jsonify(users)

# After
@app.route('/api/admin/users')
@protected_route
@admin_required
@license_required(['user_management'])
def get_users():
    return jsonify(users)
```

### Phase 3: Add Graceful Degradation

```python
@app.route('/api/performance')
@protected_route
@license_required(['performance_monitoring'])
def get_performance():
    return jsonify(performance_data)

@app.route('/api/performance/basic')
@protected_route
@license_required(allow_unlicensed=True)
def get_basic_performance():
    """Basic performance data available without license"""
    return jsonify(basic_performance_data)
```

## Error Response Format

All license decorators return consistent error responses:

```json
{
    "error": "License required",
    "message": "This feature requires a valid license",
    "code": "LICENSE_REQUIRED",
    "device_id": "device_123",
    "missing_features": ["feature1", "feature2"],
    "available_features": ["feature3"]
}
```

## Error Codes

- `DEVICE_ID_MISSING`: Device ID not found
- `INVALID_DEVICE_ID`: Invalid device ID format
- `LICENSE_SYSTEM_ERROR`: License system not configured
- `LICENSE_REQUIRED`: No license found
- `LICENSE_INVALID`: License is invalid or expired
- `INSUFFICIENT_LICENSE`: Missing required features
- `LICENSE_CHECK_ERROR`: General license check error

## Testing License Enforcement

### Test Unlicensed Access

```bash
# Remove license
curl -X POST /api/license/deactivate \
  -H "Authorization: Bearer $TOKEN"

# Try to access protected endpoint
curl /api/peers \
  -H "Authorization: Bearer $TOKEN"
# Should return 403 with license error
```

### Test Feature Requirements

```bash
# Activate basic license (no 'analytics' feature)
curl -X POST /api/license/activate \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"license_key": "basic_license_key"}'

# Try to access analytics endpoint
curl /api/analytics \
  -H "Authorization: Bearer $TOKEN"
# Should return 403 with insufficient license error
```

## Best Practices

1. **Start Small**: Begin with critical endpoints and gradually expand
2. **Feature Mapping**: Map frontend features to backend license requirements
3. **Graceful Degradation**: Provide basic functionality when possible
4. **Clear Error Messages**: Help users understand what's needed
5. **Logging**: Monitor license check failures for debugging
6. **Testing**: Test all license states (licensed, unlicensed, expired)

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure `license_manager` is available
2. **Device ID Issues**: Check `get_current_device_id()` implementation
3. **Permission Errors**: Verify file permissions on license files
4. **Configuration**: Ensure `ISSUER_PUBLIC_KEY_PATH` is set

### Debug Mode

Enable debug logging to see license check details:

```python
import logging
logging.getLogger().setLevel(logging.DEBUG)
```

## Security Considerations

- **Client-side checks are for UX only**: Always validate on backend
- **License files are secure**: Stored with restrictive permissions
- **Cryptographic validation**: Licenses are cryptographically signed
- **Device binding**: Licenses are tied to specific devices
- **Audit logging**: All license operations are logged

## Performance Impact

- **Minimal overhead**: License checks are fast file operations
- **Caching**: Consider caching license status for high-traffic endpoints
- **Async validation**: For non-critical endpoints, consider async license checks
