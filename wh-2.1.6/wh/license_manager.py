import os
import hashlib
import json
import base64
import subprocess
import re
import netifaces
import logging
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)

class DeviceLicenseManager:
    """Manages device-specific licenses and cryptographic keys"""
    
    def __init__(self, device_id=None):
        self.device_id = device_id or self.generate_device_fingerprint()
        self.keys_dir = f"/etc/warhammer/device_keys/{self.device_id}"
        self.ensure_keys_directory()
    
    def ensure_keys_directory(self):
        """Create keys directory if it doesn't exist"""
        os.makedirs(self.keys_dir, exist_ok=True)
        # Set restrictive permissions
        os.chmod(self.keys_dir, 0o700)
    
    def generate_device_fingerprint(self):
        """Create unique device identifier from hardware characteristics"""
        try:
            # Get CPU serial
            cpu_info = subprocess.check_output(['cat', '/proc/cpuinfo']).decode()
            serial_match = re.search(r'Serial\s+:\s+(\w+)', cpu_info)
            serial = serial_match.group(1) if serial_match else 'unknown'
            
            # Get primary MAC address
            mac_address = None
            for interface in netifaces.interfaces():
                if interface.startswith('en') or interface.startswith('eth'):
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_LINK in addrs:
                        mac_address = addrs[netifaces.AF_LINK][0]['addr']
                        break
            
            # Get disk serial
            try:
                disk_info = subprocess.check_output(['lsblk', '-no', 'SERIAL']).decode()
                disk_serial = disk_info.strip().split('\n')[0]
            except:
                disk_serial = 'unknown'
            
            # Create deterministic fingerprint
            fingerprint_data = f"{serial}-{mac_address or 'unknown'}-{disk_serial}"
            return hashlib.sha256(fingerprint_data.encode()).hexdigest()
            
        except Exception as e:
            logger.error(f"Error generating device fingerprint: {e}")
            return None
    
    def generate_device_keys(self):
        """Generate unique RSA key pair for this specific device"""
        try:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            # Get public key
            public_key = private_key.public_key()
            
            # Generate device-specific passphrase
            passphrase = self._generate_device_passphrase()
            
            # Save private key (encrypted with device-specific passphrase)
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    passphrase.encode()
                )
            )
            
            private_key_path = f"{self.keys_dir}/private_key.pem"
            with open(private_key_path, 'wb') as f:
                f.write(private_pem)
            os.chmod(private_key_path, 0o600)
            
            # Save public key
            public_key_path = f"{self.keys_dir}/public_key.pem"
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            with open(public_key_path, 'wb') as f:
                f.write(public_pem)
            os.chmod(public_key_path, 0o644)
            
            # Generate device certificate
            self._generate_device_certificate(private_key, public_key)
            
            logger.info(f"Device keys generated successfully for device {self.device_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error generating device keys: {e}")
            return False
    
    def _generate_device_passphrase(self):
        """Generate device-specific passphrase from hardware characteristics"""
        # Combine multiple hardware identifiers for stronger entropy
        cpu_info = subprocess.check_output(['cat', '/proc/cpuinfo']).decode()
        serial_match = re.search(r'Serial\s+:\s+(\w+)', cpu_info)
        serial = serial_match.group(1) if serial_match else 'unknown'
        
        # Get multiple MAC addresses
        mac_addresses = []
        for interface in netifaces.interfaces():
            if interface.startswith('en') or interface.startswith('eth'):
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_LINK in addrs:
                    mac_addresses.append(addrs[netifaces.AF_LINK][0]['addr'])
        
        # Get disk serial
        try:
            disk_info = subprocess.check_output(['lsblk', '-no', 'SERIAL']).decode()
            disk_serial = disk_info.strip().split('\n')[0]
        except:
            disk_serial = 'unknown'
        
        # Create deterministic passphrase
        passphrase_data = f"{serial}-{'-'.join(sorted(mac_addresses))}-{disk_serial}"
        return hashlib.sha256(passphrase_data.encode()).hexdigest()[:32]
    
    def _generate_device_certificate(self, private_key, public_key):
        """Generate self-signed certificate for the device"""
        try:
            # Create certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, f"Warhammer-Node-{self.device_id}"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Warhammer Systems"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Device Certificate")
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                public_key
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365*10)  # 10 year validity
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(f"device-{self.device_id}.warhammer.local")
                ]),
                critical=False
            ).sign(
                private_key, hashes.SHA256()
            )
            
            # Save certificate
            cert_path = f"{self.keys_dir}/device_cert.pem"
            with open(cert_path, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            os.chmod(cert_path, 0o644)
            
        except Exception as e:
            logger.error(f"Error generating device certificate: {e}")
    
    def get_device_public_key(self):
        """Get device's public key as PEM string"""
        try:
            public_key_path = f"{self.keys_dir}/public_key.pem"
            if not os.path.exists(public_key_path):
                return None
            
            with open(public_key_path, 'r') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading device public key: {e}")
            return None
    
    def get_device_info(self):
        """Get complete device information for license generation"""
        return {
            'device_id': self.device_id,
            'public_key': self.get_device_public_key(),
            'fingerprint': self.generate_device_fingerprint(),
            'hardware_info': self._get_hardware_info()
        }
    
    def _get_hardware_info(self):
        """Get detailed hardware information"""
        try:
            # CPU info
            cpu_info = subprocess.check_output(['cat', '/proc/cpuinfo']).decode()
            cpu_model = re.search(r'Model name\s+:\s+(.+)', cpu_info)
            cpu_model = cpu_model.group(1) if cpu_model else 'Unknown'
            
            # Memory info
            mem_info = subprocess.check_output(['cat', '/proc/meminfo']).decode()
            mem_total = re.search(r'MemTotal:\s+(\d+)', mem_info)
            mem_total = int(mem_total.group(1)) // 1024 if mem_total else 0  # Convert to MB
            
            # Disk info
            try:
                disk_info = subprocess.check_output(['lsblk', '-no', 'SIZE']).decode()
                disk_size = disk_info.strip().split('\n')[0]
            except:
                disk_size = 'Unknown'
            
            return {
                'cpu_model': cpu_model.strip(),
                'memory_mb': mem_total,
                'disk_size': disk_size,
                'generated_at': datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Error getting hardware info: {e}")
            return {'error': str(e)}

class DeviceLicenseValidator:
    """Validates licenses using device-specific keys"""
    
    def __init__(self, issuer_public_key_path, device_id):
        self.device_id = device_id
        self.keys_dir = f"/etc/warhammer/device_keys/{device_id}"
        
        # Load issuer's public key for signature verification
        try:
            with open(issuer_public_key_path, 'rb') as key_file:
                self.issuer_public_key = serialization.load_pem_public_key(key_file.read())
        except Exception as e:
            logger.error(f"Error loading issuer public key: {e}")
            self.issuer_public_key = None
        
        # Load device's own public key
        try:
            with open(f"{self.keys_dir}/public_key.pem", 'rb') as key_file:
                self.device_public_key = serialization.load_pem_public_key(key_file.read())
        except Exception as e:
            logger.error(f"Error loading device public key: {e}")
            self.device_public_key = None
    
    def validate_license(self, license_string):
        """Validate license using device-specific public key"""
        try:
            if not self.issuer_public_key or not self.device_public_key:
                return False, "Required keys not available"
            
            # Decode license
            decoded = base64.b64decode(license_string)
            license_payload = json.loads(decoded.decode('utf-8'))
            
            license_data = license_payload['data']
            issuer_signature = base64.b64decode(license_payload['issuer_signature'])
            
            # Verify issuer signature
            license_string_for_verification = json.dumps(
                license_data, sort_keys=True, separators=(',', ':')
            )
            
            try:
                self.issuer_public_key.verify(
                    issuer_signature,
                    license_string_for_verification.encode('utf-8'),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            except Exception as e:
                return False, f"Invalid issuer signature: {str(e)}"
            
            # Verify device public key matches
            if license_data['device_public_key'] != self._get_device_public_key_pem():
                return False, "License not valid for this device"
            
            # Check expiry
            expiry_date = datetime.fromisoformat(license_data['expiry_date'])
            if datetime.utcnow() > expiry_date:
                return False, "License expired"
            
            # Verify device fingerprint
            expected_fingerprint = license_data['device_fingerprint']
            # Use the same fingerprint method as generation (hardware-based)
            actual_fingerprint = self._get_hardware_based_fingerprint()
            
            if expected_fingerprint != actual_fingerprint:
                return False, "Device fingerprint mismatch"
            
            return True, {
                'customer_name': license_data['customer_name'],
                'expiry_date': license_data['expiry_date'],
                'license_type': license_data['license_type'],
                'features': license_data['features'],
                'issued_date': license_data['issued_date']
            }
            
        except Exception as e:
            logger.error(f"License validation error: {e}")
            return False, f"License validation error: {str(e)}"
    
    def _get_device_public_key_pem(self):
        """Get device's public key as PEM string"""
        try:
            with open(f"{self.keys_dir}/public_key.pem", 'r') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading device public key: {e}")
            return None
    
    def _get_device_fingerprint(self):
        """Get current device fingerprint from public key"""
        try:
            public_bytes = self.device_public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return hashlib.sha256(public_bytes).hexdigest()
        except Exception as e:
            logger.error(f"Error generating device fingerprint: {e}")
            return None

    def _get_hardware_based_fingerprint(self):
        """Get device fingerprint using the same method as generation (hardware-based)"""
        try:
            # Get CPU serial
            cpu_info = subprocess.check_output(['cat', '/proc/cpuinfo']).decode()
            serial_match = re.search(r'Serial\s+:\s+(\w+)', cpu_info)
            serial = serial_match.group(1) if serial_match else 'unknown'
            
            # Get primary MAC address
            mac_address = None
            for interface in netifaces.interfaces():
                if interface.startswith('en') or interface.startswith('eth'):
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_LINK in addrs:
                        mac_address = addrs[netifaces.AF_LINK][0]['addr']
                        break
            
            # Get disk serial
            try:
                disk_info = subprocess.check_output(['lsblk', '-no', 'SERIAL']).decode()
                disk_serial = disk_info.strip().split('\n')[0]
            except:
                disk_serial = 'unknown'
            
            # Create deterministic fingerprint (same as generation)
            fingerprint_data = f"{serial}-{mac_address or 'unknown'}-{disk_serial}"
            return hashlib.sha256(fingerprint_data.encode()).hexdigest()
            
        except Exception as e:
            logger.error(f"Error generating hardware-based device fingerprint: {e}")
            return None
