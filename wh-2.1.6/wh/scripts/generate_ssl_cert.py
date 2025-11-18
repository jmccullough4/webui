#!/usr/bin/env python3
"""
SSL Certificate Generator for Warhammer Node
Generates self-signed certificates for local/development use.
"""

import os
import sys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import ipaddress

def generate_ssl_certificate(hostname='localhost', ip_addresses=None, days_valid=365):
    """
    Generate a self-signed SSL certificate.
    
    Args:
        hostname (str): The hostname for the certificate
        ip_addresses (list): List of IP addresses to include
        days_valid (int): Number of days the certificate is valid
    
    Returns:
        tuple: (private_key, certificate)
    """
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Get the public key
    public_key = private_key.public_key()
    
    # Create the certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Warhammer Node"),
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])
    
    # Set certificate validity period
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
        datetime.utcnow() + timedelta(days=days_valid)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(hostname),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            x509.IPAddress(ipaddress.IPv4Address("0.0.0.0")),
        ] + ([x509.IPAddress(ipaddress.IPv4Address(ip)) for ip in (ip_addresses or []) if ip != "127.0.0.1" and ip != "0.0.0.0"])),
        critical=False,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            content_commitment=False,
            data_encipherment=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
        ]),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).sign(private_key, hashes.SHA256())
    
    return private_key, cert

def save_certificate_files(private_key, certificate, cert_dir="/etc/warhammer/ssl"):
    """
    Save the private key and certificate to files.
    
    Args:
        private_key: The private key object
        certificate: The certificate object
        cert_dir (str): Directory to save the files
    
    Returns:
        tuple: (private_key_path, certificate_path)
    """
    
    # Create directory if it doesn't exist
    os.makedirs(cert_dir, exist_ok=True)
    
    # Set restrictive permissions for the directory
    os.chmod(cert_dir, 0o700)
    
    # File paths
    private_key_path = os.path.join(cert_dir, "warhammer.key")
    certificate_path = os.path.join(cert_dir, "warhammer.crt")
    
    # Save private key
    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save certificate
    with open(certificate_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    
    # Set restrictive permissions for the private key
    os.chmod(private_key_path, 0o600)
    os.chmod(certificate_path, 0o644)
    
    return private_key_path, certificate_path

def main():
    """Main function to generate and save SSL certificates."""
    
    print("🔒 Warhammer Node SSL Certificate Generator")
    print("=" * 50)
    
    # Get hostname from environment or use default
    hostname = os.environ.get('SSL_HOSTNAME', 'localhost')
    
    # Get IP addresses from environment or use defaults
    ip_env = os.environ.get('SSL_IP_ADDRESSES', '')
    ip_addresses = [ip.strip() for ip in ip_env.split(',') if ip.strip()] if ip_env else []
    
    # Add common local IPs if none specified
    if not ip_addresses:
        ip_addresses = ['127.0.0.1', '0.0.0.0']
    
    print(f"📝 Generating certificate for:")
    print(f"   Hostname: {hostname}")
    print(f"   IP Addresses: {', '.join(ip_addresses)}")
    print(f"   Validity: 365 days")
    
    try:
        # Generate the certificate
        print("\n🔑 Generating private key and certificate...")
        private_key, certificate = generate_ssl_certificate(
            hostname=hostname,
            ip_addresses=ip_addresses,
            days_valid=365
        )
        
        # Save the files
        print("💾 Saving certificate files...")
        private_key_path, certificate_path = save_certificate_files(private_key, certificate)
        
        print("\n✅ SSL Certificate generated successfully!")
        print(f"   Private Key: {private_key_path}")
        print(f"   Certificate: {certificate_path}")
        print(f"   Directory: {os.path.dirname(private_key_path)}")
        
        print("\n📋 Next steps:")
        print("   1. Install the certificate in your browser:")
        print(f"      - Open: {certificate_path}")
        print("      - Add to trusted certificates")
        print("   2. Restart your Warhammer Node application")
        print("   3. Access via HTTPS (you may see browser warnings)")
        
        print("\n🔧 To use with your app, set these environment variables:")
        print(f"   export SSL_CERT_PATH={certificate_path}")
        print(f"   export SSL_KEY_PATH={private_key_path}")
        print(f"   export SSL_ENABLED=true")
        
    except Exception as e:
        print(f"\n❌ Error generating SSL certificate: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

