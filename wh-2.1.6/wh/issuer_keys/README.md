# License System Setup

This directory contains the issuer public key required for the Warhammer Node license system to function.

## File Structure

- `issuer_public_key.pem` - The issuer's RSA public key for verifying license signatures
- `README.md` - This documentation file

## Security Notes

⚠️ **IMPORTANT**: 
- This file contains the **public key only** - it is safe to distribute
- The corresponding **private key** should remain secure and separate
- Never commit the private key to version control

## Setup Process

1. **Generate Issuer Keys** (in secure warhammer-license repository):
   ```bash
   python generate_issuer_keys.py --output-dir issuer_keys --key-size 2048
   ```

2. **Copy Public Key** to this directory:
   ```bash
   cp /path/to/secure/issuer_keys/issuer_public_key.pem ./issuer_keys/
   ```

3. **Verify Permissions**:
   ```bash
   chmod 644 issuer_keys/issuer_public_key.pem
   chmod 700 issuer_keys/
   ```

## Deployment

The upgrade script (`config/update.sh`) will automatically:
- Copy this key to `/etc/warhammer/issuer_keys/` on the target system
- Set proper permissions
- Create necessary directories (`/etc/warhammer/issuer_keys/` and `/etc/warhammer/device_keys/`)
- Run device registration to generate device-specific keys
- Verify the license system is functional

**Note**: Device registration happens AFTER the issuer key is copied, ensuring proper license system setup order.

## Troubleshooting

If the license system is not working:
1. Verify `issuer_public_key.pem` exists in this directory
2. Check that the key is a valid RSA public key
3. Ensure the upgrade script has access to copy the key
4. Verify the target system has proper directory permissions

## Key Rotation

When rotating issuer keys:
1. Generate new key pair in secure repository
2. Update this file with new public key
3. Deploy new version to all devices
4. Generate new licenses with new private key
5. Securely destroy old private key

## Support

For questions about key management, contact: security@warhammer-systems.com
