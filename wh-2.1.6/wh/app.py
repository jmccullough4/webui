import os
import sys

# Add the current directory to Python path to ensure imports work correctly
# This is needed when the app is run from an installed package location
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Also add the parent directory to handle cases where the app is run from a different location
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Debug: Print current Python path for troubleshooting (only in debug mode)
if os.environ.get('SERVER_DEBUG', 'False').lower() == 'true':
    print(f"Python path: {sys.path}")
    print(f"Current directory: {current_dir}")
    print(f"Parent directory: {parent_dir}")

import netifaces
import ipaddress
import subprocess
import yaml
import re
import requests
import time
import shlex
import hashlib
import json
from datetime import timedelta
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin
from flask_security.utils import verify_and_update_password, hash_password
from flask_jwt_extended import JWTManager, create_access_token, verify_jwt_in_request, get_jwt_identity
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import logging
import threading
import atexit
from math import radians, sin, cos, sqrt, atan2
from gps3 import gps3
import asyncio
import aiohttp

# Import license decorators from utils
try:
    from utils.license_decorators import license_required, license_optional
except ImportError:
    # Fallback if utils not available
    def license_required(required_features=None, allow_unlicensed=False, fallback_response=None):
        def decorator(fn):
            return fn
        return decorator
    
    def license_optional(fn):
        return fn

ISSUER_PUBLIC_KEY_PATH = os.environ.get('ISSUER_PUBLIC_KEY_PATH', '/etc/warhammer/issuer_keys/issuer_public_key.pem')

def ensure_warhammer_directories():
    """Ensure all necessary Warhammer directories exist with proper permissions"""
    directories = [
        '/etc/warhammer',
        '/etc/warhammer/issuer_keys',
        '/etc/warhammer/device_keys'
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        # Set restrictive permissions (owner read/write/execute, group/others no access)
        os.chmod(directory, 0o700)
    
    if os.environ.get('SERVER_DEBUG', 'False').lower() == 'true':
        print(f"✅ Ensured Warhammer directories exist: {directories}")

# Ensure directories exist at startup
ensure_warhammer_directories()

# Load device environment if available
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
                        if os.environ.get('SERVER_DEBUG', 'False').lower() == 'true':
                            print(f"🌍 Loaded device environment: {key}={value}")
            return True
    except Exception as e:
        if os.environ.get('SERVER_DEBUG', 'False').lower() == 'true':
            print(f"⚠️  Failed to load device environment: {e}")
    return False

# Load device environment at startup
load_device_environment()

app = Flask(__name__, static_folder='flask_static')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'your_secret_key_here')
app.config['JWT_TOKEN_LOCATION'] = ['cookies', 'headers']
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////apps/webui/users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Suppress deprecation warning
app.config['SECURITY_PASSWORD_SALT'] = 'this_should_be_a_long_random_and_secret_string'
app.config['ISSUER_PUBLIC_KEY_PATH'] = ISSUER_PUBLIC_KEY_PATH

CORS(app)

version_globals = {}
with open("./version.py") as f:
    exec(f.read(), version_globals)

WARHAMMER_NAME = os.environ.get('WARHAMMER_NAME', 'REMOTE4')
HOST_IP = os.environ.get('HOST_IP', '127.0.0.1')
HOST_PORT = os.environ.get('HOST_PORT', '8080')
SERVER_DEBUG = os.environ.get('SERVER_DEBUG', False)
PORT_1_INTERFACE = os.environ.get('PORT_1_INTERFACE', 'enp1s0')
PORT_2_INTERFACE = os.environ.get('PORT_2_INTERFACE', 'enp2s0')
MANAGEMENT_INTERFACE_1 = os.environ.get('MANAGEMENT_INTERFACE_1', '')
MANAGEMENT_INTERFACE_2 = os.environ.get('MANAGEMENT_INTERFACE_2', '')
BRIDGE_INTERFACE = os.environ.get('BRIDGE_INTERFACE', 'br0')
WWAN_INTERFACE = os.environ.get('WWAN_INTERFACE', 'wwan0')
WIFI_INTERFACE = os.environ.get('WWAN_INTERFACE', 'wlo1')
BASE_NETPLAN = os.environ.get('BASE_NETPLAN', '/etc/netplan/01-network-manager-all.yaml')
WIFI_NETPLAN = os.environ.get('WIFI_NETPLAN', '/etc/netplan/99-wifi.yaml')
VERSION = os.environ.get('WARHAMMER_VERSION', version_globals['__version__'])
UPLOAD_LOCATION = os.environ.get('UPLOAD_LOCATION', '/apps/webui')
SCRIPT_LOCATION = os.environ.get('SCRIPT_LOCATION', '/apps/webui/update.sh')
UPDATE_LOG_LOCATION = os.environ.get('UPDATE_LOG_LOCATION', '/apps/webui/update.log')
HOSTAPD_CONFIG_PATH = os.environ.get('HOSTAPD_CONFIG_PATH', '/etc/hostapd/hostapd.conf')
BRIDGED_TEMPLATE = os.environ.get('BRIDGED_TEMPLATE', '/apps/webui/bridged.yaml')
UNBRIDGED_TEMPLATE = os.environ.get('UNBRIDGED_TEMPLATE', '/apps/webui/unbridged.yaml')
BRIDGED_CIDR = os.environ.get('BRIDGED_CIDR', '10.1.100.1/24')
NETBIRD_FQDN = os.environ.get('NETBIRD_DOMAIN', 'hammertime.crabsthatgrab.com')
NETBIRD_TOKEN = os.environ.get('NETBIRD_TOKEN', 'nbp_OkvcYygpDGehijGsN6ef40z9jkmGcj3Px7KI')
ENV_SH = os.environ.get('ENV_SH', '/apps/webui/env.sh')

jwt = JWTManager(app)  # Initialize JWTManager
db = SQLAlchemy(app)
socketio = SocketIO(app)

# Import and register license blueprint
try:
    from routes.license_routes import license_bp
    app.register_blueprint(license_bp)
    if os.environ.get('SERVER_DEBUG', 'False').lower() == 'true':
        print("✅ License routes imported successfully")
except ImportError as e:
    if os.environ.get('SERVER_DEBUG', 'False').lower() == 'true':
        print(f"❌ Failed to import license routes: {e}")
        print("This is expected if running in development mode without the full package structure")
    # Create a minimal blueprint to prevent crashes
    from flask import Blueprint
    license_bp = Blueprint('license', __name__, url_prefix='/api/license')
    app.register_blueprint(license_bp)

roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    last_login_at = db.Column(db.Float())
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))

class IPAddress(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    ip_address = db.Column(db.String(15), nullable=False)  # IPv4 address
    interface = db.Column(db.String(50), nullable=False)  # Interface name
    created_at = db.Column(db.Float(), default=time.time)
    created_by = db.Column(db.Integer(), db.ForeignKey('user.id'))
    user = db.relationship('User', backref=db.backref('ip_addresses', lazy=True))

user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

@app.before_first_request
def create_user():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        user_role = Role(name='user')
        admin_role = Role(name='admin')
        admin_user = User(username='admin', password=hash_password('warhammer'), active=True)
        user_datastore.add_role_to_user(admin_user, admin_role)
        db.session.add(user_role)
        db.session.add(admin_role)
        db.session.add(admin_user)
        db.session.commit()

def protected_route(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if SERVER_DEBUG:
            return fn(*args, **kwargs)
        try:
            verify_jwt_in_request()
            identity = get_jwt_identity()
            if identity:
                user = User.query.filter_by(id=identity).first()
                if user and user.active:
                    return fn(*args, **kwargs)
            return jsonify({"message": "Access denied"}), 401
        except Exception as e:
            return jsonify({"message": "Access denied", "error": str(e)}), 401

    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        identity = get_jwt_identity()
        if not identity:
            return jsonify({"message": "Access denied"}), 401
        user = User.query.filter_by(id=identity).first()
        if not user or not user.has_role('admin'):
            return jsonify({"message": "Access denied"}), 401
        return fn(*args, **kwargs)
    return wrapper

def check_if_bridged():
    # Bridge interface is up, check number of interfaces
    with open(BASE_NETPLAN) as f:
        netplan_config = yaml.safe_load(f)
        bridges = netplan_config.get('network', {}).get('bridges', {})
        bridge_interfaces = bridges.get(BRIDGE_INTERFACE, {}).get('interfaces', [])
        if len(bridge_interfaces) > 1:
            return True
    return False

def build_physical_interface_dict():
    # TODO: clean this up - remove duplicate config
    # if bridge is up, return the bridge interface
    if check_if_bridged():
        return {
            BRIDGE_INTERFACE: {
            'interface_name': BRIDGE_INTERFACE,
            'display_name': 'Bridged Ethernet',
            'hidden_addresses': [
                MANAGEMENT_INTERFACE_1,
                MANAGEMENT_INTERFACE_2,
            ],
            'immutable_addresses': [
                MANAGEMENT_INTERFACE_1,
                MANAGEMENT_INTERFACE_2,
                BRIDGED_CIDR.split('/')[0],
            ],
            'order': 3,
            'editable': True,
            'dhcp_enabled': True,  # Default to True, will be updated with actual status
            'is_safe_to_modify': True,  # Bridge interface is always safe to modify when bridged
            },
        }
    else:
        return {
            PORT_1_INTERFACE: {
                'interface_name': PORT_1_INTERFACE,
                'display_name': 'Port 1',
                'order': 4,
                'editable': True,
                'dhcp_enabled': True,  # Default to True, will be updated with actual status
                'is_safe_to_modify': True,  # Individual ports are safe to modify when not bridged
            },
            PORT_2_INTERFACE: {
                'interface_name': PORT_2_INTERFACE,
                'display_name': 'Port 2',
                'order': 5,
                'editable': True,
                'dhcp_enabled': True,  # Default to True, will be updated with actual status
                'is_safe_to_modify': True,  # Individual ports are safe to modify when not bridged
            },
        }

# Function to get network interfaces and their IP addresses
def get_network_interfaces():
    interfaces = {
        'STATIC': {
            'interface_name': 'STATIC',
            'display_name': 'Static',
            'addresses': ['18.18.18.18'],
            'order': 1,
            'editable': False,
        },
        # spread results of build_physical_interface_dict into interfaces
        **build_physical_interface_dict(),
        'WARHAMMER': {
            'interface_name': 'WARHAMMER',
            'display_name': 'WARHAMMER Network',
            'addresses': [MANAGEMENT_INTERFACE_1],
            'order': 7,
            'editable': False,
        },
    }

    try:
        # Check current bridging state
        is_bridged = check_if_bridged()
        
        # Read netplan configuration to get actual DHCP status
        try:
            netplan_file_path = BASE_NETPLAN
            with open(netplan_file_path, "r") as file:
                current_content = file.read()
            
            current_config = yaml.safe_load(current_content)
            
            # Update DHCP status and safety for each interface
            # Use the actual interface names from the interfaces dict, not the environment variables
            for interface_name in list(interfaces.keys()):
                # Only process ethernet/bridge interfaces (skip STATIC, WARHAMMER, etc.)
                if interface_name in [BRIDGE_INTERFACE, PORT_1_INTERFACE, PORT_2_INTERFACE]:
                    # Determine if this is a bridge or ethernet interface
                    is_bridge = interface_name == BRIDGE_INTERFACE
                    config_section = "bridges" if is_bridge else "ethernets"
                    
                    # Get DHCP status from netplan
                    interface_config = current_config.get("network", {}).get(config_section, {}).get(interface_name, {})
                    if interface_config:
                        if interface_config.get("dhcp4") is False:
                            interfaces[interface_name]['dhcp_enabled'] = False
                        elif interface_config.get("dhcp4") is True:
                            interfaces[interface_name]['dhcp_enabled'] = True
                    
                    # Update safety based on current bridging state
                    # When not bridged, individual ports are safe to modify
                    # When bridged, only the bridge interface is safe to modify
                    if is_bridged:
                        interfaces[interface_name]['is_safe_to_modify'] = interface_name == BRIDGE_INTERFACE
                    else:
                        # For unbridged mode, any ethernet interface (not bridge) is safe to modify
                        interfaces[interface_name]['is_safe_to_modify'] = interface_name != BRIDGE_INTERFACE
                    

                    
                    # Add warning message if unsafe to modify
                    if not interfaces[interface_name]['is_safe_to_modify']:
                        interfaces[interface_name]['warning'] = (
                            f"⚠️  Modifying {interface_name} DHCP settings while in {'bridged' if is_bridged else 'unbridged'} mode may break your network. "
                            f"Use {'the bridge interface' if is_bridged else 'individual port interfaces'} instead."
                        )
                    else:
                        interfaces[interface_name]['warning'] = None
                        
        except Exception as e:
            print(f"Warning: Could not read netplan configuration for DHCP status: {e}")
            # Keep default values if netplan read fails

        # Get IP addresses from system interfaces
        for interface in netifaces.interfaces():
            if interface == 'lo':
                continue

            addresses = netifaces.ifaddresses(interface).get(netifaces.AF_INET)
            if addresses:
                ip_addresses = [addr_info['addr'] for addr_info in addresses]
                
                # Try to find a matching interface in our dict
                # First try exact match
                if interface in interfaces:
                    interfaces[interface]['addresses'] = ip_addresses
                else:
                    # Try to find by interface type (bridge vs ethernet)
                    if interface == BRIDGE_INTERFACE:
                        # This is the bridge interface
                        if BRIDGE_INTERFACE in interfaces:
                            interfaces[BRIDGE_INTERFACE]['addresses'] = ip_addresses
                    elif interface.startswith('enp'):
                        # This is an ethernet port - find which one it should be
                        # Check if it's PORT_1_INTERFACE or PORT_2_INTERFACE
                        if PORT_1_INTERFACE in interfaces and PORT_1_INTERFACE.startswith('enp'):
                            # If PORT_1_INTERFACE is also an enp interface, this might be it
                            interfaces[PORT_1_INTERFACE]['addresses'] = ip_addresses
                        elif PORT_2_INTERFACE in interfaces and PORT_2_INTERFACE.startswith('enp'):
                            # If PORT_2_INTERFACE is also an enp interface, this might be it
                            interfaces[PORT_2_INTERFACE]['addresses'] = ip_addresses
                        else:
                            # Fallback: try to assign to any available ethernet interface
                            for key, iface_data in interfaces.items():
                                if key.startswith('enp') and 'addresses' not in iface_data:
                                    iface_data['addresses'] = ip_addresses
                                    break
        


        return interfaces

    except Exception as e:
        print(f"Error in get_network_interfaces(): {e}")
        return []

def run_command(command):
    """Run a shell command and return its output."""
    try:
        result = subprocess.run(shlex.split(command), capture_output=True, text=True)
        if result.returncode != 0:
            logger.error(f"Command failed: {command}\nError: {result.stderr}")
            return None
        return result.stdout
    except Exception as e:
        logger.error(f"Error running command {command}: {e}")
        return None

def create_user_token(user_id):
    user = user_datastore.find_user(id=user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    roles = [role.name for role in user.roles]
    access_token = create_access_token(identity=user.id, additional_claims={ "un": user.username, "roles": roles})
    return access_token

@app.route("/api/login", methods=["POST"])
def verify_login_issue_token():
    username = request.json.get('username')
    password = request.json.get('password')

    user = user_datastore.find_user(username=username)

    if user and verify_and_update_password(password, user):
        user.last_login_at = time.time()
        db.session.commit()

        if not user.active:
            return jsonify({"message": "Invalid credentials"}), 401

        access_token = create_user_token(user.id)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401

@app.route('/api/users', methods=['GET'])
@admin_required
def list_users():
    
    users = User.query.all()
    users_list = []
    for user in users:
        roles = [role.name for role in user.roles]
        users_list.append({
            'id': user.id,
            'username': user.username,
            'roles': roles,
            'active': user.active,
            'last_login_at': user.last_login_at
        })
    return jsonify(users_list), 200
    
@app.route('/api/users', methods=['POST'])
@admin_required
def create_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User(username=username, password=hash_password(password), active=True)
    db.session.add(user)
    db.session.commit()

    #add user role
    user_role = Role.query.filter_by(name='user').first()
    user_datastore.add_role_to_user(user, user_role)
    db.session.commit()

    return jsonify({"message": "User created"}), 201

@app.route('/api/users/<userid>', methods=['DELETE'])
@admin_required
def delete_user(userid):
    user = User.query.filter_by(id=userid).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "User deleted"}), 200
    else:
        return jsonify({"message": "User not found"}), 404

@app.route('/api/users/<userid>/password', methods=['PATCH'])
@protected_route
def update_password_route(userid):
    # admin can update any user's password but user can only update their own password
    identity = get_jwt_identity()

    if not identity:
        return jsonify({"message": "Invalid token"}), 400
    user = User.query.filter_by(id=identity).first()

    if not user.has_role('admin') and str(identity) != str(userid):
        return jsonify({"message": "Invalid role"}), 400

    data = request.json
    new_password = data.get('new_password')

    if user.has_role('admin'):
        # Admin user doesn't need to provide current password
        user = User.query.filter_by(id=userid).first()
        if user:
            user.password = hash_password(new_password)
            db.session.commit()
            return jsonify({"message": "Password changed"}), 200
        else:
            return jsonify({"message": "Invalid user"}), 404
    else:
        # Non-admin user must provide existing password
        current_password = data.get('current_password')
        if not verify_and_update_password(current_password, user):
            return jsonify({"message": "Invalid credentials"}), 400

        user.password = hash_password(new_password)
        db.session.commit()
        return jsonify({"message": "Password changed"}), 200

@app.route('/api/users/<userid>/status', methods=['DELETE'])
@admin_required
def deactivate_user(userid):
    user = User.query.filter_by(id=userid).first()
    if user:
        user.active = False
        db.session.commit()
        return jsonify({"message": "User deactivated"}), 200
    else:
        return jsonify({"message": "User not found"}), 404

@app.route('/api/users/<userid>/status', methods=['POST'])
@admin_required
def activate_user(userid):
    user = User.query.filter_by(id=userid).first()
    if user:
        user.active = True
        db.session.commit()
        return jsonify({"message": "User Activated"}), 200
    else:
        return jsonify({"message": "User not found"}), 404

@app.route('/api/users/<userid>/roles', methods=['POST'])
@admin_required
def add_role(userid):    
    data = request.json
    role_name = data.get('role')
    user = User.query.filter_by(id=userid).first()
    role = Role.query.filter_by(name=role_name).first()
    if user and role:
        user_datastore.add_role_to_user(user, role)
        db.session.commit()
        return jsonify({"message": "Role added to user"}), 200
    else:
        return jsonify({"message": "User or role not found"}), 404

@app.route('/api/users/<userid>/roles', methods=['DELETE'])
@admin_required
def remove_role(userid):    
    data = request.json
    role_name = data.get('role')
    user = User.query.filter_by(id=userid).first()
    role = Role.query.filter_by(name=role_name).first()
    if user and role:
        user_datastore.remove_role_from_user(user, role)
        db.session.commit()
        return jsonify({"message": "Role removed from user"}), 200
    else:
        return jsonify({"message": "User or role not found"}), 404

@app.route('/api/roles', methods=['GET'])
@admin_required
def list_roles():
    roles = Role.query.all()
    roles_list = []
    for role in roles:
        roles_list.append({
            'id': role.id,
            'name': role.name
        })
    return jsonify(roles_list), 200

@app.route('/api/info')
def get_warhammer_info():
    """Returns system information including location data."""
    try:
        with gps_data_lock:
            latitude = gps_data_cache.get('latitude')
            longitude = gps_data_cache.get('longitude')
            last_update = gps_data_cache.get('last_update')

        # Convert GPS coordinates to float if they're valid numbers
        try:
            lat = float(latitude) if latitude and latitude != 'n/a' else None
            lon = float(longitude) if longitude and longitude != 'n/a' else None
        except (ValueError, TypeError):
            lat = None
            lon = None

        info = {
            'version': VERSION,
            'name': WARHAMMER_NAME,
            'location': {
                'latitude': lat,
                'longitude': lon,
                'last_update': last_update
            }
        }
        return jsonify(info)
    except Exception as e:
        logger.error(f"Error getting system info: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/interfaces', methods=['GET'])
@protected_route
def get_network_interfaces_endpoint():
    return jsonify(get_network_interfaces())

@app.route('/api/ip', methods=['POST'])
@protected_route
def update_ip():
    # can only update bridge interface
    interface = BRIDGE_INTERFACE
    new_ip = request.json.get('ip')

    # Validate interface
    interfaces = netifaces.interfaces()
    if interface not in interfaces:
        return jsonify({'error': f'Interface {interface} not found'}), 400

    # Validate IP address
    try:
        ipaddress.ip_address(new_ip)
    except ValueError:
        return jsonify({'error': 'Invalid IP address'}), 400

    # Check if IP already exists in database
    existing_ip = IPAddress.query.filter_by(ip_address=new_ip, interface=interface).first()
    if existing_ip:
        return jsonify({'error': 'IP address already exists'}), 400

    # Create new IP address record
    current_user_id = get_jwt_identity()
    ip_record = IPAddress(
        ip_address=new_ip,
        interface=interface,
        created_by=current_user_id
    )
    db.session.add(ip_record)
    db.session.commit()

    # Update IP address using system commands
    cmd = f'sudo netplan set bridges.{interface}.addresses=[{new_ip}/24] && sudo ip addr add {new_ip}/24 dev {BRIDGE_INTERFACE}'
    result = os.system(cmd)

    if result == 0:
        return jsonify({'message': 'IP address updated successfully'}), 200
    else:
        # Rollback database changes if system command fails
        db.session.delete(ip_record)
        db.session.commit()
        return jsonify({'error': 'Failed to update IP address'}), 500

@app.route('/api/ip', methods=['DELETE'])
@protected_route
def delete_ip():
    # can only update bridge interface
    interface = BRIDGE_INTERFACE
    ip_to_delete = request.json.get('ip')
    print(f"ip_to_delete {ip_to_delete}")

    # Validate interface
    interfaces = netifaces.interfaces()
    if interface not in interfaces:
        return jsonify({'error': f'Interface {interface} not found'}), 400

    # Find IP record in database
    ip_record = IPAddress.query.filter_by(ip_address=ip_to_delete, interface=interface).first()
    if not ip_record:
        return jsonify({'error': 'IP address not found'}), 404

    try:
        # Fetch the current configuration
        netplan_file_path = BASE_NETPLAN
        with open(netplan_file_path, "r") as file:
            current_content = file.read()

        # Parse the current YAML content
        current_config = yaml.safe_load(current_content)

        addresses = current_config["network"]["bridges"][interface].get('addresses', [])
        updated_addresses = [addr for addr in addresses if addr != f"{ip_to_delete}/24"]

        # Update the Netplan YAML configuration for Ethernet
        if "network" not in current_config:
            current_config["network"] = {}
        if "bridges" not in current_config["network"]:
            current_config["network"]["bridges"] = {}

        current_config["network"]["bridges"][interface]["addresses"] = updated_addresses

        # Convert the updated configuration back to YAML
        updated_content = yaml.dump(current_config, default_flow_style=False)

        # Write the updated Netplan configuration back to the file
        with open(netplan_file_path, "w") as file:
            file.write(updated_content)
        
        remove_cmd = f'sudo ip addr del {ip_to_delete}/24 dev {BRIDGE_INTERFACE}'
        subprocess.check_output(remove_cmd, shell=True)

        # Delete IP record from database
        db.session.delete(ip_record)
        db.session.commit()

        return jsonify({"message": f"IP {ip_to_delete} successfully removed."}), 200

    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Failed to apply Netplan configuration: {e}"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# create route to set interface to bridged
@app.route('/api/bridge', methods=['POST'])
@protected_route
def bridge_interface():
    # if bridged, return error
    if check_if_bridged():
        return jsonify({"error": "Bridge interface is already up"}), 400

    # Get all IPs from database for this interface
    ip_records = IPAddress.query.filter_by(interface=BRIDGE_INTERFACE).all()
    custom_ips = [f"{ip.ip_address}/24" for ip in ip_records]

    # Read the bridged template file
    with open(BRIDGED_TEMPLATE, 'r') as f:
        bridged_template = f.read()

    # Parse the template
    config = yaml.safe_load(bridged_template)
    
    # Add custom IPs to the configuration
    if custom_ips:
        if "network" not in config:
            config["network"] = {}
        if "bridges" not in config["network"]:
            config["network"]["bridges"] = {}
        if BRIDGE_INTERFACE not in config["network"]["bridges"]:
            config["network"]["bridges"][BRIDGE_INTERFACE] = {}
        if "addresses" not in config["network"]["bridges"][BRIDGE_INTERFACE]:
            config["network"]["bridges"][BRIDGE_INTERFACE]["addresses"] = []
        
        # Add custom IPs while preserving existing ones
        existing_ips = config["network"]["bridges"][BRIDGE_INTERFACE]["addresses"]
        config["network"]["bridges"][BRIDGE_INTERFACE]["addresses"] = list(set(existing_ips + custom_ips))

    # Write the updated configuration back to the Netplan file
    with open(BASE_NETPLAN, 'w') as f:
        f.write(yaml.dump(config, default_flow_style=False))

    try:
        # Apply the Netplan configuration
        subprocess.run(["sudo", "netplan", "apply"], check=True)
        
        # Reset VPN after network changes
        bring_vpn_down()
        subprocess.run(["systemctl", "restart", "NetworkManager"], check=True)
        bring_vpn_up()
        
        return jsonify({"message": "Interface successfully bridged"}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Failed to apply network changes: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# create route to set interface to unbridged
@app.route('/api/bridge', methods=['DELETE'])
@protected_route
def unbridge_interface():
    # if not bridged, return error
    if not check_if_bridged():
        return jsonify({"error": "Bridge interface is not up"}), 400

    # Get all IPs from database for this interface
    ip_records = IPAddress.query.filter_by(interface=BRIDGE_INTERFACE).all()
    custom_ips = [f"{ip.ip_address}/24" for ip in ip_records]

    # Read the unbridged template file
    with open(UNBRIDGED_TEMPLATE, 'r') as f:
        unbridged_template = f.read()

    # Parse the template
    config = yaml.safe_load(unbridged_template)
    
    # Add custom IPs to the configuration
    if custom_ips:
        if "network" not in config:
            config["network"] = {}
        if "bridges" not in config["network"]:
            config["network"]["bridges"] = {}
        if BRIDGE_INTERFACE not in config["network"]["bridges"]:
            config["network"]["bridges"][BRIDGE_INTERFACE] = {}
        if "addresses" not in config["network"]["bridges"][BRIDGE_INTERFACE]:
            config["network"]["bridges"][BRIDGE_INTERFACE]["addresses"] = []
        
        # Add custom IPs while preserving existing ones
        existing_ips = config["network"]["bridges"][BRIDGE_INTERFACE]["addresses"]
        config["network"]["bridges"][BRIDGE_INTERFACE]["addresses"] = list(set(existing_ips + custom_ips))

    # Write the updated configuration back to the Netplan file
    with open(BASE_NETPLAN, 'w') as f:
        f.write(yaml.dump(config, default_flow_style=False))

    try:
        # Apply the Netplan configuration
        subprocess.run(["sudo", "netplan", "apply"], check=True)
        
        # Reset VPN after network changes
        bring_vpn_down()
        subprocess.run(["systemctl", "restart", "NetworkManager"], check=True)
        bring_vpn_up()
        
        return jsonify({"message": "Interface successfully unbridged"}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Failed to apply network changes: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/bridge', methods=['GET'])
@protected_route
def get_bridge_status():
    return jsonify({"bridged": check_if_bridged()}), 200

def enable_wifi():
    # Execute command to enable Wi-Fi
    subprocess.run(['sudo', 'rfkill', 'unblock', 'wifi'], check=True)

def disable_wifi():
    # Execute command to disable Wi-Fi
    subprocess.run(['sudo', 'rfkill', 'block', 'wifi'], check=True)

@app.route('/api/wifi', methods=['GET'])
@protected_route
def list_wifi_ssids():
    # Use nmcli to list available Wi-Fi SSIDs
    command_output = run_command("nmcli -t -f ssid,mode,chan,rate,signal,bars,security,active,bssid device wifi list")
    lines = command_output.strip().split('\n')

    if len(lines[0]) > 0:
        networks = []

        for line in lines:
            unescapedLine = line.replace('\:', '_')
            network_info = unescapedLine.split(':')
            network = {
                'ssid': '**SSID HIDDEN**' if not network_info[0] else network_info[0],
                'mode': network_info[1],
                'channel': network_info[2],
                'rate': network_info[3],
                'signal': network_info[4],
                'bars': network_info[5],
                'security': "NONE" if not network_info[6] else network_info[6],
                'active': network_info[7] == 'yes',
                'bssid': network_info[8].replace('_', ':')
            }

            networks.append(network)

        return jsonify(networks)
    else:
        # No Ethernet connection information
        return jsonify([])

@app.route('/api/wifi/status', methods=['GET'])
@protected_route
def get_wifi_status():
    # Use nmcli to get detailed information about the current Wi-Fi connection
    connection_info = run_command("nmcli -t -f active,ssid,signal,rate,security device wifi")
    radio_info = run_command("nmcli radio wifi")

    radio_status = radio_info.strip()

    # Process the output to extract Wi-Fi status details
    lines = connection_info.split('\n')

    # Loop through the lines to find the active Wi-Fi network
    connected_wifi = None
    for line in lines:
        fields = line.split(':')
        if len(fields) == 5 and fields[0] == 'yes':
            connected_wifi = {
                'ssid': fields[1],
                'signal_strength': int(fields[2]),
                'data_rate': fields[3],
                'security': "NONE" if not fields[4] else fields[4]
            }
            break

    # Check if connected to a Wi-Fi network
    if connected_wifi:
        status = {
            'connected': True,
            'radio_status': radio_status,
            **connected_wifi
        }
    else:
        # Not connected to a Wi-Fi network
        status = {
            'connected': False,
            'radio_status': radio_status
        }

    return jsonify(status)

@app.route('/api/wifi/status', methods=['POST', 'DELETE'])
@protected_route
def control_wifi():
    if request.method == 'POST':
        enable_wifi()
        return jsonify({'message': 'Wi-Fi enabled successfully'})

    elif request.method == 'DELETE':
        disable_wifi()
        return jsonify({'message': 'Wi-Fi disabled successfully'})

    else:
        return jsonify({'error': 'Invalid method'}), 405

@app.route("/api/wifi", methods=["PATCH", "DELETE"])
@protected_route
def configure_wifi():
    try:
        if request.method == "PATCH":
            # Extract necessary information from the request for PATCH
            ssid = request.json.get("ssid")
            password = request.json.get("password")

            # Generate the Netplan YAML configuration for WiFi
            netplan_config = f"""network:
  version: 2
  wifis:
    {WIFI_INTERFACE}:
      dhcp4: true
      optional: true
      access-points:
        "{ssid}":
          password: "{password}"
""" if password else f"""network:
  version: 2
  wifis:
    {WIFI_INTERFACE}:
      dhcp4: true
      optional: true
      access-points:
        "{ssid}": {{}}
"""

            # Write the Netplan configuration to a temporary file
            with open(WIFI_NETPLAN, "w") as file:
                file.write(netplan_config)

        elif request.method == "DELETE":
            # Handle DELETE request to remove the netplan file
            subprocess.run(["sudo", "rm", WIFI_NETPLAN])

        # Apply the Netplan configuration
        subprocess.run(["sudo", "netplan", "apply"], check=True)

        return jsonify({"message": "WiFi configuration successful"}), 200

    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Failed to apply Netplan configuration: {e.stderr.decode()}"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500

def read_hostapd_settings():
    settings = {}
    if os.path.exists(HOSTAPD_CONFIG_PATH):
        with open(HOSTAPD_CONFIG_PATH, 'r') as f:
            for line in f:
                line = line.strip()
                if not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    settings[key] = value

    # check if hostabp is running and add the status to the settings
    hostapd_status = run_command("systemctl is-active hostapd")
    settings['status'] = hostapd_status.strip()

    return settings

def write_hostapd_settings(settings):
    # First, read the existing settings
    existing_settings = read_hostapd_settings()

    # remove status from existing settings
    existing_settings.pop('status', None)

    # Update the existing settings with the new settings
    existing_settings.update(settings)

    # Write the updated settings back to the file
    with open(HOSTAPD_CONFIG_PATH, 'w') as f:
        for key, value in existing_settings.items():
            f.write(f'{key}={value}\n')

def start_hostapd_service():
    subprocess.run(['systemctl', 'start', 'hostapd'], check=True)
    subprocess.run(['ip', 'addr', 'add', '10.42.0.1/24', 'dev', 'wlo1'], check=True)

def stop_hostapd_service():
    subprocess.run(['systemctl', 'stop', 'hostapd'], check=True)

@app.route('/api/wifi/hostapd/settings', methods=['GET'])
@protected_route
def get_wifi_settings():
    settings = read_hostapd_settings()
    return jsonify(settings), 200

@app.route('/api/wifi/hostapd/settings', methods=['POST'])
@protected_route
def set_wifi_settings():
    write_hostapd_settings(request.json)
    return jsonify({'status': 'success'}), 200

@app.route('/api/wifi/hostapd', methods=['POST'])
@protected_route
def start_wifi():
    try:
        start_hostapd_service()
        return jsonify({'status': 'success'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/wifi/hostapd', methods=['DELETE'])
@protected_route
def stop_wifi():
    try:
        stop_hostapd_service()
        return jsonify({'status': 'success'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def get_connections(connection_type=None):
    # Use nmcli to get detailed information about the current Ethernet connection
    command_output = run_command("nmcli -t -f device,state,uuid,autoconnect,timestamp,type,name connection show")

    # Process the output to extract Ethernet status details
    lines = command_output.strip().split('\n')

    if lines:
        # Ethernet connection information is available
        connections = []

        for line in lines:
            connection_info = line.split(':')
            connection = {
                'connected': connection_info[1] == 'activated',
                'state': connection_info[1],
                'device': connection_info[0],
                'connection_id': connection_info[2],
                'autoconnect': connection_info[3] == 'yes',
                'timestamp': connection_info[4],
                'type': connection_info[5],
                'name': connection_info[6],
            }

            # Filter by connection type if specified
            if connection_type is None or connection['type'] == connection_type:
                connections.append(connection)

        return jsonify(connections)
    else:
        # No Ethernet connection information
        return jsonify([])

def update_gsm_connection(connection_name, setting, new_value):
    return run_command(f"nmcli connection modify {shlex.quote(connection_name)} {shlex.quote(setting)} {shlex.quote(new_value)}")

def create_gsm_connection(name, apn, username, password):
    return run_command(f"nmcli connection add type gsm con-name {shlex.quote(name)} ifname '*' apn {shlex.quote(apn)} user {shlex.quote(username)} password {shlex.quote(password)} autoconnect yes")

def activate_connection(connection_name):
    return run_command(f"nmcli connection up {shlex.quote(connection_name)}")

def deactivate_connection(connection_name):
    return run_command(f"nmcli connection down {shlex.quote(connection_name)}")

def delete_connection(connection_name):
    return run_command(f"nmcli connection delete {shlex.quote(connection_name)}")

@app.route('/api/gsm-connections', methods=['GET'])
@protected_route
def get_gsm_connections_endpoint():
    return get_connections('gsm')

@app.route('/api/gsm-connections/<connection_name>', methods=['PATCH'])
@protected_route
def update_gsm_connection_endpoint(connection_name):
    data = request.get_json()
    setting = data.get('setting')
    new_value = data.get('new_value')
    update_gsm_connection(connection_name, setting, new_value)
    return jsonify({"message": f"GSM connection {connection_name} updated successfully"})

@app.route('/api/gsm-connections', methods=['POST'])
@protected_route
def create_gsm_connection_endpoint():
    data = request.get_json()
    name = data.get('name')
    apn = data.get('apn')
    username = data.get('username')
    password = data.get('password')
    create_gsm_connection(name, apn, username, password)
    return jsonify({"message": f"GSM connection {name} created successfully"})

@app.route('/api/gsm-connections/<connection_name>/status', methods=['POST'])
@protected_route
def activate_connection_endpoint(connection_name):
    activate_connection(connection_name)
    return jsonify({"message": f"Connection {connection_name} activated successfully"})

@app.route('/api/gsm-connections/<connection_name>/status', methods=['DELETE'])
@protected_route
def deactivate_connection_endpoint(connection_name):
    deactivate_connection(connection_name)
    return jsonify({"message": f"Connection {connection_name} deactivated successfully"})

@app.route('/api/gsm-connections/<connection_name>', methods=['DELETE'])
@protected_route
def delete_connection_endpoint(connection_name):
    delete_connection(connection_name)
    return jsonify({"message": f"Connection {connection_name} deleted successfully"})

# Function to extract and clean a field value from mmcli output
def extract_mmcli_field(mmcli_output, field_name):
    field_value = re.search(fr"{field_name}:\s*(\S+)", mmcli_output)
    return field_value.group(1) if field_value else None

def extract_mmcli_field_with_spaces(mmcli_output, field_name):
    """Extract field value that may contain spaces"""
    field_value = re.search(fr"{field_name}:\s*(.+)", mmcli_output)
    return field_value.group(1).strip() if field_value else None

def extract_signal_quality_dbm(mmcli_output, access_tech):
    if mmcli_output and access_tech:
        if access_tech == "lte":
            rsrp = re.search(r"rsrp:\s*(-\d+)", mmcli_output)
            return rsrp.group(1) if rsrp else None
        elif access_tech == "umts":
            rscp = re.search(r"rscp:\s*(-\d+)", mmcli_output)
            return rscp.group(1) if rscp else None
        elif access_tech == "gsm":
            rssi = re.search(r"rssi:\s*(-\d+)", mmcli_output)
            return rssi.group(1) if rssi else None
    return None

def parse_mmcli_signal_data(mmcli_signal_output):
    """Parse detailed signal information from mmcli signal output"""
    if not mmcli_signal_output:
        return {}
    
    signal_data = {}
    
    # Extract LTE signal data
    lte_patterns = {
        'rssi': r"rssi:\s*(-\d+\.\d+)",
        'rsrq': r"rsrq:\s*(-\d+\.\d+)",
        'rsrp': r"rsrp:\s*(-\d+\.\d+)",
        'sn': r"s/n:\s*(-\d+\.\d+)"
    }
    
    for key, pattern in lte_patterns.items():
        match = re.search(pattern, mmcli_signal_output)
        if match:
            signal_data[key] = float(match.group(1))
    
    return signal_data

def parse_mmcli_modem_data(mmcli_m_output):
    """Parse comprehensive modem information from mmcli -m 0 output"""
    if not mmcli_m_output:
        return {}
    
    modem_data = {}
    
    # General section
    modem_data['device_id'] = extract_mmcli_field(mmcli_m_output, "device id")
    modem_data['path'] = extract_mmcli_field(mmcli_m_output, "path")
    
    # Hardware section
    modem_data['manufacturer'] = extract_mmcli_field_with_spaces(mmcli_m_output, "manufacturer")
    modem_data['model'] = extract_mmcli_field_with_spaces(mmcli_m_output, "model")
    modem_data['firmware_revision'] = extract_mmcli_field_with_spaces(mmcli_m_output, "firmware revision")
    modem_data['carrier_config'] = extract_mmcli_field_with_spaces(mmcli_m_output, "carrier config")
    modem_data['carrier_config_revision'] = extract_mmcli_field(mmcli_m_output, "carrier config revision")
    modem_data['hw_revision'] = extract_mmcli_field(mmcli_m_output, "h/w revision")
    modem_data['equipment_id'] = extract_mmcli_field(mmcli_m_output, "equipment id")
    
    # System section
    modem_data['device'] = extract_mmcli_field_with_spaces(mmcli_m_output, "device")
    modem_data['drivers'] = extract_mmcli_field_with_spaces(mmcli_m_output, "drivers")
    modem_data['plugin'] = extract_mmcli_field(mmcli_m_output, "plugin")
    modem_data['primary_port'] = extract_mmcli_field(mmcli_m_output, "primary port")
    modem_data['ports'] = extract_mmcli_field_with_spaces(mmcli_m_output, "ports")
    
    # Numbers section
    modem_data['phone_number'] = extract_mmcli_field(mmcli_m_output, "own")
    
    # Status section
    modem_data['lock'] = extract_mmcli_field(mmcli_m_output, "lock")
    modem_data['state'] = extract_mmcli_field(mmcli_m_output, "state")
    modem_data['power_state'] = extract_mmcli_field(mmcli_m_output, "power state")
    modem_data['access_tech'] = extract_mmcli_field(mmcli_m_output, "access tech")
    modem_data['signal_quality'] = extract_mmcli_field(mmcli_m_output, "signal quality")
    
    # 3GPP section
    modem_data['imei'] = extract_mmcli_field(mmcli_m_output, "imei")
    modem_data['operator_id'] = extract_mmcli_field(mmcli_m_output, "operator id")
    modem_data['operator_name'] = extract_mmcli_field_with_spaces(mmcli_m_output, "operator name")
    modem_data['registration'] = extract_mmcli_field(mmcli_m_output, "registration")
    modem_data['packet_service_state'] = extract_mmcli_field_with_spaces(mmcli_m_output, "packet service state")
    
    # 3GPP EPS section
    modem_data['ue_mode'] = extract_mmcli_field_with_spaces(mmcli_m_output, "ue mode of operation")
    modem_data['initial_bearer_path'] = extract_mmcli_field(mmcli_m_output, "initial bearer path")
    modem_data['initial_bearer_apn'] = extract_mmcli_field_with_spaces(mmcli_m_output, "initial bearer apn")
    modem_data['initial_bearer_ip_type'] = extract_mmcli_field(mmcli_m_output, "initial bearer ip type")
    
    # SIM section
    modem_data['primary_sim_path'] = extract_mmcli_field(mmcli_m_output, "primary sim path")
    modem_data['sim_slot_paths'] = extract_mmcli_field_with_spaces(mmcli_m_output, "sim slot paths")
    
    # Bearer section
    modem_data['bearer_paths'] = extract_mmcli_field_with_spaces(mmcli_m_output, "paths")
    
    return modem_data

def parse_mmcli_sim_data(mmcli_i_output):
    """Parse SIM information from mmcli -i 0 output"""
    if not mmcli_i_output:
        return {}
    
    sim_data = {}
    
    # General section
    sim_data['path'] = extract_mmcli_field(mmcli_i_output, "path")
    
    # Properties section
    sim_data['active'] = extract_mmcli_field(mmcli_i_output, "active")
    sim_data['imsi'] = extract_mmcli_field(mmcli_i_output, "imsi")
    sim_data['iccid'] = extract_mmcli_field(mmcli_i_output, "iccid")
    sim_data['operator_id'] = extract_mmcli_field(mmcli_i_output, "operator id")
    sim_data['operator_name'] = extract_mmcli_field_with_spaces(mmcli_i_output, "operator name")
    sim_data['emergency_numbers'] = extract_mmcli_field_with_spaces(mmcli_i_output, "emergency numbers")
    sim_data['gid1'] = extract_mmcli_field(mmcli_i_output, "gid1")
    
    return sim_data

# Flask endpoint to retrieve cellular status
@app.route('/api/gsm-connections/status', methods=['GET'])
@protected_route
def get_cellular_status():
    try:
        # Get the output from mmcli commands
        mmcli_m_output = run_command("mmcli -m 0")
        mmcli_i_output = run_command("mmcli -i 0")
        mmcli_signal_output = run_command("mmcli -m 0 --signal-get")

        # Parse comprehensive data from all commands
        modem_data = parse_mmcli_modem_data(mmcli_m_output)
        sim_data = parse_mmcli_sim_data(mmcli_i_output)
        signal_data = parse_mmcli_signal_data(mmcli_signal_output)

        # Format the state for text display
        state_overrides = {
            "\u001b[31mfailed\u001b[0m": "SIM Missing",
            "\u001b[32mconnected\u001b[0m": "CONNECTED",
            "\u001b[33mconnecting\u001b[0m": "CONNECTING",
        }

        formatted_state = state_overrides.get(modem_data.get('state'), modem_data.get('state'))

        # Build comprehensive cellular status response
        cellular_status = {
            # Core status information
            "status": {
                "state": formatted_state,
                "power_state": modem_data.get('power_state'),
                "lock": modem_data.get('lock'),
                "registration": modem_data.get('registration'),
                "packet_service_state": modem_data.get('packet_service_state')
            },
            
            # Hardware information
            "hardware": {
                "manufacturer": modem_data.get('manufacturer'),
                "model": modem_data.get('model'),
                "firmware_revision": modem_data.get('firmware_revision'),
                "carrier_config": modem_data.get('carrier_config'),
                "carrier_config_revision": modem_data.get('carrier_config_revision'),
                "hw_revision": modem_data.get('hw_revision'),
                "equipment_id": modem_data.get('equipment_id'),
                "imei": modem_data.get('imei')
            },
            
            # Network information
            "network": {
                "access_tech": modem_data.get('access_tech'),
                "operator_name": modem_data.get('operator_name'),
                "operator_id": modem_data.get('operator_id'),
                "phone_number": modem_data.get('phone_number'),
                "ue_mode": modem_data.get('ue_mode'),
                "initial_bearer_apn": modem_data.get('initial_bearer_apn'),
                "initial_bearer_ip_type": modem_data.get('initial_bearer_ip_type')
            },
            
            # Signal information
            "signal": {
                "quality": modem_data.get('signal_quality'),
                "lte": signal_data
            },
            
            # SIM information
            "sim": {
                "active": sim_data.get('active'),
                "imsi": sim_data.get('imsi'),
                "iccid": sim_data.get('iccid'),
                "operator_name": sim_data.get('operator_name'),
                "operator_id": sim_data.get('operator_id'),
                "emergency_numbers": sim_data.get('emergency_numbers'),
                "gid1": sim_data.get('gid1')
            },
            
            # System information
            "system": {
                "device": modem_data.get('device'),
                "drivers": modem_data.get('drivers'),
                "plugin": modem_data.get('plugin'),
                "primary_port": modem_data.get('primary_port'),
                "ports": modem_data.get('ports')
            }
        }

        return jsonify(cellular_status)

    except Exception as e:
        logger.error(f"Error getting cellular status: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/ethernet', methods=['GET'])
@protected_route
def get_ethernet_endpoint():
    return get_connections('bridge')

@app.route("/api/ethernet/<interface_name>", methods=["PATCH"])
@protected_route
def configure_ethernet_interface(interface_name):
    try:
        # Extract necessary information from the request
        mode = request.json.get("mode")
        static_ips = request.json.get("static_ips", [])  # List of static IP addresses

        # Validate mode
        if mode not in ["static", "dhcp"]:
            return jsonify({"error": "Invalid mode. Use 'static' or 'dhcp'"}), 400

        # Validate static IPs if provided
        if mode == "static" and static_ips:
            for ip in static_ips:
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    return jsonify({"error": f"Invalid IP address: {ip}"}), 400

        # Validate interface name
        valid_interfaces = [BRIDGE_INTERFACE, PORT_1_INTERFACE, PORT_2_INTERFACE]
        if interface_name not in valid_interfaces:
            return jsonify({"error": f"Invalid interface. Must be one of: {', '.join(valid_interfaces)}"}), 400

        # Check current bridging state
        is_bridged = check_if_bridged()
        
        # Prevent dangerous DHCP changes based on bridging state
        if is_bridged:
            # In bridged mode, physical ports are bonded - changing their DHCP could break the network
            if interface_name in [PORT_1_INTERFACE, PORT_2_INTERFACE]:
                return jsonify({
                    "error": f"Cannot modify DHCP settings for {interface_name} while in bridged mode",
                    "detail": "Physical ports are bonded to the bridge interface. Use the bridge interface DHCP settings instead.",
                    "current_mode": "bridged",
                    "safe_interface": BRIDGE_INTERFACE
                }), 400
        else:
            # In unbridged mode, prevent bridge interface DHCP changes that could break the network
            if interface_name == BRIDGE_INTERFACE:
                return jsonify({
                    "error": f"Cannot modify DHCP settings for {interface_name} while in unbridged mode",
                    "detail": "Bridge interface is not active. Use individual port DHCP settings instead.",
                    "current_mode": "unbridged",
                    "safe_interfaces": [PORT_1_INTERFACE, PORT_2_INTERFACE]
                }), 400

        # Read the current content of the Netplan file
        netplan_file_path = BASE_NETPLAN
        with open(netplan_file_path, "r") as file:
            current_content = file.read()

        # Parse the current YAML content
        current_config = yaml.safe_load(current_content)

        # Determine if this is a bridge or ethernet interface
        is_bridge = interface_name == BRIDGE_INTERFACE
        config_section = "bridges" if is_bridge else "ethernets"

        # Update the Netplan YAML configuration
        if "network" not in current_config:
            current_config["network"] = {}
        if config_section not in current_config["network"]:
            current_config["network"][config_section] = {}
        if interface_name not in current_config["network"][config_section]:
            current_config["network"][config_section][interface_name] = {}

        # Set DHCP configuration
        if mode == "dhcp":
            current_config["network"][config_section][interface_name]["dhcp4"] = True
            # Remove static addresses if they exist
            if "addresses" in current_config["network"][config_section][interface_name]:
                del current_config["network"][config_section][interface_name]["addresses"]
        else:
            # Static mode - disable DHCP
            current_config["network"][config_section][interface_name]["dhcp4"] = False
            
            # Set static IP addresses if provided
            if static_ips:
                current_config["network"][config_section][interface_name]["addresses"] = static_ips

        # Convert the updated configuration back to YAML
        updated_content = yaml.dump(current_config, default_flow_style=False)

        # Write the updated Netplan configuration back to the file
        with open(netplan_file_path, "w") as file:
            file.write(updated_content)

        # Apply the Netplan configuration
        subprocess.run(["sudo", "netplan", "apply"], check=True)

        return jsonify({
            "message": f"{interface_name} configuration successful",
            "current_bridge_mode": "bridged" if is_bridged else "unbridged",
            "safe_interfaces": [BRIDGE_INTERFACE] if is_bridged else [PORT_1_INTERFACE, PORT_2_INTERFACE]
        }), 200

    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Failed to apply Netplan configuration: {e.stderr.decode()}"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Remove the old configure_ethernet function and replace with a backward-compatible alias
@app.route("/api/ethernet/", methods=["PATCH"])
@protected_route
def configure_ethernet():
    # Backward compatibility - redirect to bridge interface
    return configure_ethernet_interface(BRIDGE_INTERFACE)

@app.route("/api/ethernet/<interface_name>/status", methods=["GET"])
@protected_route
def get_ethernet_interface_status(interface_name):
    try:
        # Validate interface name
        valid_interfaces = [BRIDGE_INTERFACE, PORT_1_INTERFACE, PORT_2_INTERFACE]
        if interface_name not in valid_interfaces:
            return jsonify({"error": f"Invalid interface. Must be one of: {', '.join(valid_interfaces)}"}), 400
        
        # Check current bridging state
        is_bridged = check_if_bridged()
        
        # Read the current content of the Netplan file
        netplan_file_path = BASE_NETPLAN
        with open(netplan_file_path, "r") as file:
            current_content = file.read()

        # Parse the current YAML content
        current_config = yaml.safe_load(current_content)

        # Determine if this is a bridge or ethernet interface
        is_bridge = interface_name == BRIDGE_INTERFACE
        config_section = "bridges" if is_bridge else "ethernets"

        # Check if the interface exists and get its DHCP status
        # Default to DHCP enabled if no explicit configuration is found
        dhcp_enabled = True
        interface_config = current_config.get("network", {}).get(config_section, {}).get(interface_name, {})
        
        if interface_config:
            # If dhcp4 is explicitly set to False, then DHCP is disabled
            if interface_config.get("dhcp4") is False:
                dhcp_enabled = False
            # If dhcp4 is explicitly set to True, then DHCP is enabled
            elif interface_config.get("dhcp4") is True:
                dhcp_enabled = True
            # If dhcp4 is not set, default to True (DHCP enabled)
            # This handles the case where interface config is {} or doesn't exist

        # Determine if this interface is safe to modify based on bridging state
        is_safe_to_modify = False
        if is_bridged:
            # In bridged mode, only the bridge interface is safe to modify
            is_safe_to_modify = interface_name == BRIDGE_INTERFACE
        else:
            # In unbridged mode, only physical ports are safe to modify
            is_safe_to_modify = interface_name in [PORT_1_INTERFACE, PORT_2_INTERFACE]

        return jsonify({
            "interface": interface_name,
            "interface_type": "bridge" if is_bridge else "ethernet",
            "dhcp_enabled": dhcp_enabled,
            "mode": "dhcp" if dhcp_enabled else "static",
            "current_bridge_mode": "bridged" if is_bridged else "unbridged",
            "is_safe_to_modify": is_safe_to_modify,
            "safe_interfaces": [BRIDGE_INTERFACE] if is_bridged else [PORT_1_INTERFACE, PORT_2_INTERFACE],
            "warning": None if is_safe_to_modify else (
                f"⚠️  Modifying {interface_name} DHCP settings while in {'bridged' if is_bridged else 'unbridged'} mode may break your network. "
                f"Use {'the bridge interface' if is_bridged else 'individual port interfaces'} instead."
            )
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

def get_netbird_status():
    """Get and parse the output of netbird status."""
    try:
        output = run_command("netbird status --json")
        if not output:
            logger.error("Failed to get netbird status output")
            return {'error': 'netbird_status_failed', 'peers': []}

        try:
            parsed_output = json.loads(output)
            # Check if the parsed output has the expected structure
            if not isinstance(parsed_output, dict):
                logger.error(f"Unexpected netbird status format: {type(parsed_output)}")
                return {'error': 'invalid_status_format', 'peers': []}
            
            # If we have a valid response but no peers, that's still a successful response
            # (the service is up but there are no peers)
            return parsed_output
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse netbird status JSON: {e}")
            return {'error': 'json_parse_error', 'peers': []}
            
    except Exception as e:
        logger.error(f"Error getting netbird status: {e}")
        return {'error': 'netbird_command_failed', 'peers': []}

def bring_vpn_up():
    try:
        subprocess.run(["systemctl", "restart", "NetworkManager"], check=True)
        subprocess.run(["netbird", "up"], check=True)
        return True
    except subprocess.CalledProcessError as e:
        error_message = f"Failed to bring VPN up: {e.stderr}"
        raise Exception(error_message)

def bring_vpn_down():
    try:
        subprocess.run(["netbird", "down"], check=True)
        return True
    except subprocess.CalledProcessError as e:
        error_message = f"Failed to bring VPN down: {e.stderr}"
        raise Exception(error_message)

def reset_vpn():
    try:
        bring_vpn_down()
        bring_vpn_up()
        response_message = "VPN has been reset."
        return jsonify({"message": response_message}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/vpn", methods=["POST", "DELETE"])
@protected_route
@admin_required
@license_required()  # No specific features required, just needs valid license
def manage_vpn_status():
    """Manage VPN status - requires admin role"""
    if request.method == "POST":
        try:
            bring_vpn_up()
            response_message = "VPN has been brought up."
            return jsonify({"message": response_message}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    elif request.method == "DELETE":
        try:
            bring_vpn_down()
            response_message = "VPN has been brought down."
            return jsonify({"message": response_message}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    else:
        return jsonify({"error": "Invalid HTTP method"}), 400

@app.route("/api/vpn", methods=["GET"])
@protected_route
@license_required()  # No specific features required, just needs valid license
def get_vpn_status():
    return jsonify(get_netbird_status()), 200

@app.route("/api/vpn/reset", methods=["POST"])
@protected_route
@admin_required
@license_required()  # No specific features required, just needs valid license
def reset_vpn_handler():
    """Reset VPN connection - requires admin role"""
    return reset_vpn()

@app.route("/api/vpn/key", methods=["POST"])
@protected_route
def set_vpn_key():
    try:
        key = request.json.get("key")
        url = request.json.get("url")
        token = request.json.get("token")
        if not key:
            return jsonify({"error": "Key is required"}), 400
        if not url:
            return jsonify({"error": "URL is required"}), 400
        if not token:
            return jsonify({"error": "Token is required"}), 400

        command = ["netbird", "up", "--management-url", url, "--admin-url", url, "--enable-rosenpass", "--setup-key", key]
        subprocess.run(command, check=True)

        # update env.sh with token
        with open(ENV_SH, "r") as file:
            lines = file.readlines()
        with open(ENV_SH, "w") as file:
            for line in lines:
                if "NETBIRD_TOKEN" in line:
                    file.write(f"export NETBIRD_TOKEN={token}\n")
                elif "NETBIRD_DOMAIN" in line:
                    # remove http:// or https:// and trailing slashes
                    url = url.replace("http://", "").replace("https://", "").rstrip("/")
                    file.write(f"export NETBIRD_DOMAIN={url}\n")
                else:
                    file.write(line)

        #schedule a reboot in 10 seconds with a thread
        threading.Timer(10, subprocess.run(["shutdown", "-r", "now"])).start()

        return jsonify({"message": "VPN key set successfully. Rebooting node in 10 seconds."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route("/api/vpn/<peer_id>", methods=["DELETE"])
@protected_route
@admin_required
@license_required()  # No specific features required, just needs valid license
def delete_vpn_peer(peer_id):
    """Delete VPN peer - requires admin role"""
    try:
        # rest request to netbird api to delete peer
        response = requests.delete(f"https://{NETBIRD_FQDN}/api/peers/{peer_id}", headers=netbird_headers)
        if response.status_code == 200:
            return jsonify({"message": "VPN peer deleted successfully"}), 200
        else:
            return jsonify({"error": response.json()}), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/gps')
def get_gps():
    """Returns the current GPS coordinates."""
    with gps_data_lock:
        latitude = gps_data_cache.get('latitude')
        longitude = gps_data_cache.get('longitude')
        last_update = gps_data_cache.get('last_update')
    return jsonify({'latitude': latitude, 'longitude': longitude, 'last_update': last_update})

@app.route('/api/location')
@protected_route
def get_location():
    """Returns the current location information."""
    try:
        with gps_data_lock:
            latitude = gps_data_cache.get('latitude')
            longitude = gps_data_cache.get('longitude')
            last_update = gps_data_cache.get('last_update')

        return jsonify({
            'latitude': latitude,
            'longitude': longitude,
            'last_update': last_update
        })

    except Exception as e:
        logger.error(f"Error in GPS location endpoint: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/diagnostics/iperf", methods=["POST"])
@protected_route
def ping_warhammer_node():
    try:
        # Extract IP address from the request
        ip_address = request.json.get("ip_address")

        if not ip_address:
            return jsonify({"error": "IP address is required"}), 400

        # Run iperf3 command
        command = ["iperf3", "-c", shlex.quote(ip_address), "--json"]
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode == 0:
            # Successful execution, parse and return JSON
            iperf_data = result.stdout
            return iperf_data, 200, {"Content-Type": "application/json"}
        else:
            # Error in execution, return error message
            error_message = result.stderr
            return jsonify({"error": f"Failed to run iperf3: {error_message}"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
def validate_checksum(file, provided_checksum):
    if not provided_checksum:
        # If no checksum is provided, return True (validation passes)
        return True

    # Calculate the checksum of the uploaded file
    hasher = hashlib.md5()
    for chunk in iter(lambda: file.read(4096), b""):
        hasher.update(chunk)
    file_checksum = hasher.hexdigest()

    return file_checksum == provided_checksum

def list_files_from_request(request):
    files = request.files.getlist('file')
    return [file.filename for file in files]

@app.route('/api/upload', methods=['POST'])
@protected_route
def upload_file():
    try:
        # Check if the POST request has the file part
        if 'file' not in request.files:
            return jsonify({'error': 'No file part', 'files': []}), 400

        file = request.files['file']

        # If the user does not select a file, the browser submits an empty file without a filename
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        # Optionally, check the checksum if provided
        checksum = request.form.get('checksum')
        if not validate_checksum(file, checksum):
            return jsonify({'error': 'Checksum validation failed'}), 400
        
        # Save the file to the upload directory
        file_path = os.path.join(UPLOAD_LOCATION, file.filename)
        file.save(file_path)

        # return 200 and kick off update script
        if not os.path.exists(SCRIPT_LOCATION):
            return jsonify({'error': 'Script not found'}), 500

        # Execute the script and redirect output to a log file
        with open(UPDATE_LOG_LOCATION, 'a') as log_file:
            subprocess.Popen(["sudo", "bash", SCRIPT_LOCATION], stdout=log_file, stderr=subprocess.STDOUT)
        return jsonify({'message': 'File uploaded successfully', 'file': file.filename}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
def get_bluetooth_status():
    try:
        output = subprocess.check_output(['rfkill', 'list', 'bluetooth'], text=True)
        lines = [line.strip() for line in output.split('\n')]
        soft_blocked = 'Soft blocked: yes' in lines
        hard_blocked = 'Hard blocked: yes' in lines
        # return yes/no for soft and hard blocked
        return {'soft_blocked': 'yes' if soft_blocked else 'no', 'hard_blocked': 'yes' if hard_blocked else 'no'}
    except subprocess.CalledProcessError:
        return {'soft_blocked': 'no', 'hard_blocked': 'no'}

def parse_bluetoothctl_show(output):
    pattern = r"(Name|Alias|Powered|Discoverable|Pairable|Discovering):\s+(.*)"
    matches = re.findall(pattern, output)
    return {key.lower(): value for key, value in matches}

def parse_devices(output):
    # Parse the output to get the addresses and names of the devices
    devices = re.findall(r'Device ([0-9A-F:]+) (.*)', output)
    return [{'address': address, 'name': name} for address, name in devices]

@app.route('/api/bluetooth', methods=['GET'])
@protected_route
def get_bluetooth():
    result = subprocess.run(['bluetoothctl', 'show'], capture_output=True, text=True)
    fields = parse_bluetoothctl_show(result.stdout)
    return jsonify({**get_bluetooth_status(), **fields}), 200

@app.route('/api/bluetooth', methods=['POST'])
@protected_route
def enable_bluetooth():
    try:
        subprocess.run(['rfkill', 'unblock', 'bluetooth'])
        return jsonify({'status': 'success'}), 200
    except subprocess.CalledProcessError:
        return jsonify({'status': 'failed'}), 500

@app.route('/api/bluetooth', methods=['DELETE'])
@protected_route
def disable_bluetooth():
    try:
        subprocess.run(['rfkill', 'block', 'bluetooth'])
        return jsonify({'status': 'success'}), 200
    except subprocess.CalledProcessError:
        return jsonify({'status': 'failed'}), 500

@app.route('/api/bluetooth/devices', methods=['GET'])
@protected_route
def get_devices():
    scan_time = request.args.get('scan_time', default=2, type=int)

    # Start the scan process
    scan_process = subprocess.Popen(['bluetoothctl', 'scan', 'on'])

    # Wait for the specified amount of time
    time.sleep(scan_time)

    # Stop the scan process
    scan_process.terminate()

    # Get the list of devices
    result = subprocess.run(['bluetoothctl', 'devices'], capture_output=True, text=True)

    devices = parse_devices(result.stdout)

    return jsonify({'devices': devices}), 200

@app.route('/api/bluetooth/paired-devices', methods=['GET'])
@protected_route
def get_paired_devices():
    try:
        output = subprocess.check_output(['bluetoothctl', 'paired-devices'], text=True)
        devices = parse_devices(output)
        return jsonify({'devices': devices}), 200
    except subprocess.CalledProcessError:
        return jsonify({'status': 'failed'}), 500

@app.route('/api/bluetooth/paired-devices/<address>', methods=['POST'])
@protected_route
def pair_device(address):
    if address:
        result = subprocess.run(['bluetoothctl', 'pair', address], capture_output=True, text=True)
        if "Failed to pair" in result.stdout:
            return jsonify({'status': 'failed', 'message': 'Failed to pair'}), 500
        else:
            return jsonify({'status': 'success'}), 200
    else:
        return jsonify({'status': 'invalid request'}), 400

@app.route('/api/bluetooth/paired-devices/<address>', methods=['DELETE'])
@protected_route
def forget_device(address):
    if address:
        try:
            subprocess.run(['bluetoothctl', 'remove', address])
            return jsonify({'status': 'success'}), 200
        except subprocess.CalledProcessError:
            return jsonify({'status': 'failed'}), 500
    else:
        return jsonify({'status': 'invalid request'}), 400

@app.route('/api/bluetooth/discoverable', methods=['POST'])
@protected_route
def set_bluetooth_discoverable():
    discoverable = request.json.get('discoverable', None)
    if discoverable is not None:
        try:
            if discoverable:
                subprocess.run(['bluetoothctl', 'discoverable', 'on'], check=True)
            else:
                subprocess.run(['bluetoothctl', 'discoverable', 'off'], check=True)
            return jsonify({'status': 'success'}), 200
        except subprocess.CalledProcessError:
            return jsonify({'status': 'failed'}), 500
    else:
        return jsonify({'status': 'failed', 'message': 'Missing discoverable parameter'}), 400
    
@app.route('/api/bluetooth/pairable', methods=['POST'])
@protected_route
def set_bluetooth_pairable():
    pairable = request.json.get('pairable', None)
    if pairable is not None:
        try:
            if pairable:
                subprocess.run(['bluetoothctl', 'pairable', 'on'], check=True)
            else:
                subprocess.run(['bluetoothctl', 'pairable', 'off'], check=True)
            return jsonify({'status': 'success'}), 200
        except subprocess.CalledProcessError:
            return jsonify({'status': 'failed'}), 500
    else:
        return jsonify({'status': 'failed', 'message': 'Missing pairable parameter'}), 400

netbird_headers = {
    'Authorization': f'Token {NETBIRD_TOKEN}',
    'Content-Type': 'application/json'
}

# NETBIRD PROXY ROUTES
@app.route('/api/routes', methods=['GET'])
@protected_route
@license_required()  # No specific features required, just needs valid license
def get_routes():
    """Get network routes"""
    try: 
        response = requests.get(f"https://{NETBIRD_FQDN}/api/routes", headers=netbird_headers)
        routes = response.json()
        return jsonify(routes)
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f"Failed to get routes"}), 500

@app.route('/api/routes', methods=['POST'])
@protected_route
def create_route():
    data = request.json
    try:# Log the data being sent to create a route
        response = requests.post(f"https://{NETBIRD_FQDN}/api/routes", headers=netbird_headers, json=data)
        return jsonify(response.json()), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f"Failed to create route"}), 500

@app.route('/api/routes/<route_id>', methods=['DELETE'])
@protected_route
def delete_route(route_id):
    try:
        response = requests.delete(f"https://{NETBIRD_FQDN}/api/routes/{route_id}", headers=netbird_headers)
        return jsonify(response.json()), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f"Failed to delete route with ID: {route_id}"}), 500

@app.route('/api/routes/<route_id>', methods=['PUT'])
@protected_route
def update_route(route_id):
    data = request.json
    try:
        response = requests.put(f"https://{NETBIRD_FQDN}/api/routes/{route_id}", headers=netbird_headers, json=data)
        return jsonify(response.json()), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f"Failed to update route with ID: {route_id}"}), 500

async def get_peer_info_async(session, peer_ip):
    """Asynchronously fetches peer info including GPS data from a remote peer."""
    if not peer_ip:
        return None
        
    try:
        async with session.get(f'http://{peer_ip}/api/info', timeout=2) as response:
            response.raise_for_status()
            return await response.json()
    except Exception as e:
        logger.warning(f"Failed to fetch peer info from {peer_ip}: {e}")
        return None

async def get_peers_async():
    """Get list of peers with their status and location information asynchronously."""
    try:
        # Get peers from Netbird API
        response = requests.get(f"https://{NETBIRD_FQDN}/api/peers", headers=netbird_headers)
        response.raise_for_status()
        peers = response.json()

        if not isinstance(peers, list):
            logger.error(f"Invalid peers format from API: {type(peers)}")
            return []

        # Get local GPS data
        with gps_data_lock:
            local_latitude = gps_data_cache.get('latitude')
            local_longitude = gps_data_cache.get('longitude')
            local_last_update = gps_data_cache.get('last_update')

        processed_peers = []
        async with aiohttp.ClientSession() as session:
            # Create list of tasks for concurrent execution
            tasks = []
            
            for peer in peers:
                if not isinstance(peer, dict):
                    continue

                processed_peer = {
                    # spread the peer object into the processed_peer object
                    **peer,
                    'id': peer.get('id'),
                    'name': peer.get('name', '').upper(),
                    'ip': peer.get('ip'),
                    'connected': peer.get('connected', False),
                    'location': {
                        'latitude': None,
                        'longitude': None,
                        'last_update': None
                    },
                    'groups': peer.get('groups', []),
                    'last_seen': peer.get('last_seen', None),
                }

                # Add location data
                management_interfaces = [MANAGEMENT_INTERFACE_1, MANAGEMENT_INTERFACE_2]
                if peer.get('ip') in management_interfaces:
                    # Local peer - use cached GPS data
                    processed_peer['location'] = {
                        'latitude': local_latitude,
                        'longitude': local_longitude,
                        'last_update': local_last_update
                    }
                    processed_peers.append(processed_peer)
                else:
                    # Only fetch location for connected peers
                    if peer.get('connected'):
                        tasks.append((get_peer_info_async(session, peer.get('ip')), processed_peer))
                    else:
                        # Add disconnected peer without attempting location fetch
                        processed_peers.append(processed_peer)

            # Wait for all tasks to complete
            if tasks:
                results = await asyncio.gather(*[task[0] for task in tasks])
                for result, (_, processed_peer) in zip(results, tasks):
                    if result and isinstance(result, dict) and 'location' in result:
                        processed_peer['location'] = result['location']
                    processed_peers.append(processed_peer)

        return processed_peers

    except Exception as e:
        logger.error(f"Error getting peers: {e}")
        return []

@app.route('/api/peers', methods=['GET'])
@protected_route
@license_required()  # No specific features required, just needs valid license
def get_peers_handler():
    """Returns list of peers with their status and location."""
    try:
        # Create event loop and run the async function
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        peers = loop.run_until_complete(get_peers_async())
        loop.close()
        return jsonify(peers)
    except Exception as e:
        logger.error(f"Error in peers endpoint: {e}")
        return jsonify({"error": str(e)}), 500

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Add cache variables
network_settings_cache = {}
network_settings_lock = threading.Lock()

gps_data_cache = {'latitude': None, 'longitude': None, 'last_update': None}
gps_data_lock = threading.Lock()

# Add after cache variables
def fetch_gps_data_periodically(interval=2):
    """
    Background thread function to fetch and cache GPS data from gpsd every `interval` seconds.
    """
    global gps_data_cache
    last_update = 0
    
    gps_socket = gps3.GPSDSocket()
    data_stream = gps3.DataStream()
    gps_socket.connect()
    gps_socket.watch()

    for new_data in gps_socket:
        if getattr(threading.current_thread(), "stop_flag", False):
            break
            
        current_time = time.time()
        if current_time - last_update < interval:
            continue
            
        if new_data:
            data_stream.unpack(new_data)
            latitude = data_stream.TPV.get('lat', None)
            longitude = data_stream.TPV.get('lon', None)

            # if either lat or lng is not a number, set both to None
            if not isinstance(latitude, (int, float)) or not isinstance(longitude, (int, float)):
                latitude = None
                longitude = None

            # if cached gps data was a number, but now is None, don't update the cache
            if (isinstance(gps_data_cache['latitude'], (int, float)) and latitude is None) or (isinstance(gps_data_cache['longitude'], (int, float)) and longitude is None):
                continue
            
            with gps_data_lock:
                gps_data_cache['latitude'] = latitude
                gps_data_cache['longitude'] = longitude
                gps_data_cache['last_update'] = current_time
                
            last_update = current_time
            logger.debug(f"GPS data updated: lat={latitude}, lon={longitude}")

def start_background_threads():
    """
    Starts the background threads for GPS data.
    """
    gps_thread = threading.Thread(target=fetch_gps_data_periodically, daemon=True)
    gps_thread.start()
    return [gps_thread]

background_threads = start_background_threads()

# Ensure background threads stop gracefully on application exit
def stop_background_threads():
    for thread in background_threads:
        thread.stop_flag = True

atexit.register(stop_background_threads)

# Update the existing get_signal_quality function
def get_signal_quality():
    try:
        result = subprocess.run("mmcli -m 0 | grep 'signal quality'", 
                              shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            quality = int(result.stdout.split(':')[1].split('%')[0].strip())
            return quality
        logger.warning("Signal quality command failed.")
        return 0
    except (IndexError, ValueError) as e:
        logger.error(f"Error parsing signal quality: {e}")
        return 0
    except Exception as e:
        logger.error(f"Error getting signal quality: {e}")
        return 0

@app.route('/api/refresh-token', methods=['POST'])
@protected_route
def refresh_token():
    current_user_id = get_jwt_identity()
    access_token = create_user_token(current_user_id)
    return jsonify({'access_token': access_token}), 200

@app.route("/api/vpn/kill", methods=["DELETE"])
@protected_route
def kill_network():
    try:
        #get first netbird account id from netbird api
        response = requests.get(f"https://{NETBIRD_FQDN}/api/accounts", headers=netbird_headers)
        accounts = response.json()
        account_id = accounts[0]['id']

        #delete the account
        response = requests.delete(f"https://{NETBIRD_FQDN}/api/accounts/{account_id}", headers=netbird_headers)
        return jsonify(response.json()), response.status_code

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/ssl/certificate", methods=["GET"])
@protected_route
def download_ssl_certificate():
    """Download SSL certificate and README for browser installation (SSL terminated at nginx level)."""
    try:
        cert_path = os.environ.get('SSL_CERT_PATH', '/etc/warhammer/ssl/warhammer.crt')
        readme_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'SSL_SETUP_README.md')

        if not os.path.exists(cert_path):
            return jsonify({"error": "SSL certificate not found"}), 404
        
        # Create a ZIP file containing certificate and README
        import zipfile
        import tempfile
        
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp_file:
            with zipfile.ZipFile(tmp_file.name, 'w') as zipf:
                # Add certificate
                zipf.write(cert_path, 'warhammer.crt')
                
                # Add README if it exists
                if os.path.exists(readme_path):
                    zipf.write(readme_path, 'SSL_SETUP_README.md')
                else:
                    # Create a simple README if the file doesn't exist
                    readme_content = """# SSL Certificate Installation Guide

## What is this?
This is a self-signed SSL certificate for your Warhammer Node application.

## How to install:

### Chrome/Edge:
1. Open chrome://settings/certificates
2. Click "Authorities" tab
3. Click "Import"
4. Select warhammer.crt from this ZIP
5. Check "Trust this certificate for identifying websites"
6. Click "OK"

### Firefox:
1. Open about:preferences#privacy
2. Click "View Certificates"
3. Click "Import"
4. Select warhammer.crt from this ZIP
5. Check "Trust this CA to identify websites"
6. Click "OK"

### Safari:
1. Open "Keychain Access" app
2. File → Import Items
3. Select warhammer.crt from this ZIP
4. Double-click the imported certificate
5. Expand "Trust" section
6. Set "When using this certificate" to "Always Trust"

## After installation:
- Access your app via HTTPS: https://your-ip:8080
- You may still see warnings (this is normal)
- Traffic will be encrypted even with warnings
"""
                    zipf.writestr('SSL_SETUP_README.md', readme_content)
            
            # Read the ZIP file and return it
            with open(tmp_file.name, 'rb') as f:
                zip_data = f.read()
            
            # Clean up temp file
            os.unlink(tmp_file.name)
            
            return zip_data, 200, {
                'Content-Type': 'application/zip',
                'Content-Disposition': 'attachment; filename=warhammer-ssl-certificate.zip',
                'Content-Length': len(zip_data)
            }
    
    except Exception as e:
        return jsonify({"error": f"Failed to create certificate package: {str(e)}"}), 500

@app.route("/api/ssl/status", methods=["GET"])
@protected_route
def get_ssl_status():
    """Get SSL status information (SSL now terminated at nginx level)."""
    try:
        cert_path = os.environ.get('SSL_CERT_PATH', '/etc/warhammer/ssl/warhammer.crt')
        key_path = os.environ.get('SSL_KEY_PATH', '/etc/warhammer/ssl/warhammer.key')

        certificate_exists = os.path.exists(cert_path)
        key_exists = os.path.exists(key_path)

        status = {
            "ssl_enabled": certificate_exists and key_exists,
            "ssl_termination": "nginx",
            "message": "SSL is terminated at nginx level. Flask app runs on HTTP internally.",
            "internal_access": f"http://{HOST_IP}:{HOST_PORT}",
            "external_access": "https://[management_interface]",
            "note": "Download and install the SSL certificate in your browser to avoid security warnings",
            "certificate_exists": certificate_exists,
            "key_exists": key_exists,
            "certificate_path": cert_path,
            "download_available": certificate_exists,
        }

        return jsonify(status), 200

    except Exception as e:
        return jsonify({"error": f"Failed to get SSL status: {str(e)}"}), 500

# @app.route('/api/gsm-connections/modem', methods=['POST', 'DELETE'])
# @protected_route
# def control_modem():
#     try:
#         if request.method == 'POST':
#             # Enable the modem
#             subprocess.run(['mmcli', '-m', '0', '--enable'], check=True)
#             return jsonify({'message': 'Modem enabled successfully'}), 200
#         elif request.method == 'DELETE':
#             # Disable the modem
#             subprocess.run(['mmcli', '-m', '0', '--disable'], check=True)
#             return jsonify({'message': 'Modem disabled successfully'}), 200
#     except subprocess.CalledProcessError as e:
#         return jsonify({'error': f'Failed to control modem: {str(e)}'}), 500
#     except Exception as e:
#         return jsonify({'error': str(e)}), 500

# # Add modem state to GSM status endpoint
# def get_modem_state():
#     try:
#         result = subprocess.run(['mmcli', '-m', '0'], capture_output=True, text=True)
#         if 'disabled' in result.stdout.lower():
#             return 'disabled'
#         elif 'enabled' in result.stdout.lower():
#             return 'enabled'
#         return 'unknown'
#     except:
#         return 'unknown'



if __name__ == "__main__":
    print(f"🌐 Starting Warhammer Node (HTTP only)")
    print(f"   SSL terminated at nginx level")
    print(f"   Internal access via: http://{HOST_IP}:{HOST_PORT}")
    print(f"   External access via: nginx proxy (HTTPS)")
    
    socketio.run(app, host=HOST_IP, port=HOST_PORT, debug=SERVER_DEBUG)
