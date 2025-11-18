# Warhammer Node License System

A comprehensive, decentralized license management system for Warhammer Node devices that works without internet connectivity.

## 🏗️ Architecture Overview

The license system uses **asymmetric cryptography** with **per-device public keys** to ensure:
- **Device binding**: Licenses cannot be shared between devices
- **Offline operation**: No internet required for license validation
- **Tamper resistance**: Cryptographic signatures prevent license forgery
- **Flexible licensing**: Support for different license types and durations

## 🔑 Key Components

### 1. **Device License Manager** (`license_manager.py`)
- Generates unique RSA key pairs for each device
- Creates device fingerprints from hardware characteristics
- Manages device certificates and key storage

### 2. **Issuer License Generator** (`company_license_generator.py`) - *Moved to secure repository*
- Generates licenses using issuer's private key
- Creates device-specific licenses with embedded expiration dates
- Supports multiple license types (basic, premium, enterprise)

### 3. **Device Registration Script** (`device_registration.py`)
- Customers run this to get device information
- Generates device keys and hardware fingerprint
- Creates `device_info.json` for license requests

### 4. **Issuer Key Generator** (`generate_company_keys.py`) - *Moved to secure repository*
- Creates issuer's RSA key pair for signing licenses
- Generates issuer certificate and documentation

### 5. **License API Routes** (`routes/license_routes.py`)
- Flask API endpoints for license management
- License activation, validation, and status checking
- Feature access control

## 🚀 Complete Workflow

### **Phase 1: Issuer Setup**

1. **Generate Issuer Keys**
   ```bash
   cd warhammer-node/backend/wh
   python generate_company_keys.py --output-dir issuer_keys --key-size 2048  # *Script moved to secure repository*
   ```

2. **Secure Storage**
   - Keep `issuer_private_key.pem` secure (never share)
   - Distribute `issuer_public_key.pem` to customer devices
   - Backup keys securely

### **Phase 2: Device Manufacturing**

1. **Pre-install Software**
   - Install Warhammer Node software on devices
   - Include company public key in distribution

2. **Device Initialization**
   - Each device generates unique RSA key pair on first boot
   - Creates device-specific fingerprint from hardware

### **Phase 3: Customer Purchase & Setup**

1. **Customer Runs Device Registration**
   ```bash
   python device_registration.py
   ```

2. **Customer Sends Device Info**
   - Email `device_info.json` to Warhammer Systems
   - Include company name and desired license type

### **Phase 4: License Generation**

1. **Issuer Generates License**
   ```bash
   python company_license_generator.py \  # *Script moved to secure repository*
       --private-key issuer_keys/issuer_private_key.pem \
       --device-info customer_device_info.json \
       --customer-name "Customer Company" \
       --license-type premium \
       --duration 2
   ```

2. **Send License to Customer**
   - Email license file to customer
   - Include activation instructions

### **Phase 5: License Activation**

1. **Customer Activates License**
   - Copy license key from email
   - Navigate to device web interface: Settings > License
   - Paste license key and click "Activate"

2. **Device Validation**
   - Device validates license using company public key
   - Verifies device binding and expiration
   - Enables licensed features

## 📋 License Types & Features

### **Basic License**
- Network monitoring
- Basic VPN
- GPS tracking
- Cellular connectivity

### **Premium License**
- All Basic features
- Advanced analytics
- Custom alerts
- API access

### **Enterprise License**
- All Premium features
- Multi-tenant support
- Custom integrations
- Priority support
- Dedicated servers

## 🔒 Security Features

### **Device Binding**
- Each device has unique RSA key pair
- License includes device's public key
- Prevents license sharing between devices

### **Hardware Fingerprinting**
- Combines CPU serial, MAC addresses, disk serial
- Creates deterministic device identifier
- Resistant to basic hardware changes

### **Cryptographic Signatures**
- RSA-PSS-SHA256 signatures
- Company private key signs all licenses
- Public key verification prevents forgery

### **Secure Storage**
- Private keys encrypted with device-specific passphrases
- Restrictive file permissions (600 for private, 644 for public)
- Keys stored in `/etc/warhammer/device_keys/`

## 🛠️ Installation & Setup

### **Dependencies**
```bash
pip install cryptography netifaces
```

### **File Structure**
```
warhammer-node/backend/wh/
├── license_manager.py           # Core license management
├── company_license_generator.py # Company license creation (*moved to secure repo*)
├── device_registration.py       # Customer device setup
├── generate_company_keys.py     # Company key generation (*moved to secure repo*)
├── routes/
│   └── license_routes.py       # API endpoints
├── issuer_keys/                 # Issuer cryptographic keys (bundled)
│   ├── issuer_public_key.pem   # Public key for license verification
│   └── README.md               # Setup documentation
└── LICENSE_SYSTEM_README.md     # This file
```

### **Automatic Setup**
The license system is now automatically configured during upgrades:
- **Upgrade script** (`config/update.sh`) automatically copies the issuer public key
- **Directory creation** with proper permissions (700 for directories, 644 for public key)
- **License system status** displayed during upgrade process
- **No manual configuration** required for basic functionality

### **Configuration**
Add to your Flask app configuration:
```python
app.config['ISSUER_PUBLIC_KEY_PATH'] = '/path/to/issuer_public_key.pem'
app.config['DEVICE_ID'] = 'optional_device_id_override'
```

## 📱 API Endpoints

### **License Status**
```
GET /api/license/status
```
Returns current license status and expiration information.

### **License Activation**
```
POST /api/license/activate
Body: {"license_key": "base64_encoded_license"}
```
Activates a license for the device.

### **License Deactivation**
```
POST /api/license/deactivate
```
Removes the current license from the device.

### **License Information**
```
GET /api/license/info
```
Returns detailed license information and metadata.

### **Available Features**
```
GET /api/license/features
```
Returns list of features available with current license.

## 🔄 License Renewal Process

1. **Customer Requests Renewal**
   - Contact Warhammer Systems before expiration
   - Provide device ID and desired license type

2. **Company Generates New License**
   - Use existing device info or request updated info
   - Generate new license with extended expiration

3. **Customer Activates New License**
   - Deactivate old license (optional)
   - Activate new license
   - Features continue uninterrupted

## 🚨 Troubleshooting

### **Common Issues**

1. **"Issuer public key not configured"**
   - Ensure `ISSUER_PUBLIC_KEY_PATH` is set in Flask config
   - Verify public key file exists and is readable

2. **"Device ID not found"**
   - Check environment variable `WARHAMMER_DEVICE_ID`
   - Verify device registration completed successfully

3. **"License validation failed"**
   - Check device fingerprint hasn't changed significantly
   - Verify license hasn't expired
   - Ensure company public key matches license issuer

4. **"Permission denied" errors**
   - Ensure proper file permissions on key directories
   - Run device registration as appropriate user

### **Debug Mode**
Enable verbose logging:
```bash
python device_registration.py --verbose
```

## 🔐 Key Management

### **Issuer Key Rotation**
1. Generate new key pair
2. Update all devices with new public key
3. Generate new licenses with new private key
4. Securely destroy old private key

### **Device Key Recovery**
If device keys are lost:
1. Customer runs device registration again
2. New device ID and keys generated
3. Company generates new license for new device ID

## 📞 Support

For technical support:
- Email: support@warhammer-systems.com
- Security: security@warhammer-systems.com

## 🔮 Future Enhancements

- **License pooling**: Multiple devices under single license
- **Feature flags**: Granular feature control
- **Usage analytics**: License usage tracking
- **Automated renewal**: Self-service license renewal
- **Cloud sync**: Optional cloud-based license management

## 📄 License

This license system is proprietary to Warhammer Systems Inc.
Unauthorized copying or distribution is prohibited.
