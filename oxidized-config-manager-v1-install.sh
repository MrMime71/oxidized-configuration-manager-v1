#!/bin/bash

# Installation script for Oxidized Configuration Manager
# Sets up the Flask app on Ubuntu, checks dependencies, creates a virtual environment,
# installs Python modules, configures the app with user-provided paths and credentials,
# sets up a systemd service, and configures the firewall for port 5000.
# Includes backup functionality for raw config and router.db saves.
# Run as root or with sudo.

# Exit on error
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print info
info() {
  echo -e "${GREEN}[INFO] $1${NC}"
}

# Function to print warning
warn() {
  echo -e "${YELLOW}[WARN] $1${NC}"
}

# Function to print error and exit
error() {
  echo -e "${RED}[ERROR] $1${NC}"
  exit 1
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  error "Please run this script as root or with sudo."
fi

# Check Ubuntu version
UBUNTU_VERSION=$(lsb_release -rs)
info "Detected Ubuntu version: $UBUNTU_VERSION"

if [[ $UBUNTU_VERSION != "24.04" ]]; then
  warn "This script is optimized for Ubuntu 24.04. Other versions may require adjustments."
  read -p "Continue? (y/n): " continue_choice
  if [[ $continue_choice != "y" ]]; then
    exit 0
  fi
fi

# Install system dependencies
info "Installing system dependencies..."
apt update
apt install -y python3 python3-venv python3-pip gunicorn ufw

# Check if Oxidized is installed
info "Checking if Oxidized is installed..."
if systemctl is-active --quiet oxidized; then
  info "Oxidized service is running."
elif systemctl is-enabled --quiet oxidized; then
  info "Oxidized is installed but not running. Starting it..."
  systemctl start oxidized
else
  warn "Oxidized is not installed or not configured as a service."
  read -p "Do you want to install Oxidized? (y/n): " install_oxidized
  if [[ $install_oxidized == "y" ]]; then
    apt install -y ruby ruby-dev libsqlite3-dev libssl-dev pkg-config cmake libssh2-1-dev libicu-dev zlib1g-dev libgpgme-dev
    gem install oxidized oxidized-web oxidized-script
    mkdir -p ~/.config/oxidized
    echo "Please configure Oxidized manually in ~/.config/oxidized/config and router.db."
  else
    warn "Proceeding without Oxidized installation. The app may not function fully."
  fi
fi

# Prompt for installation details
read -p "Enter the app installation directory (default: /home/$(whoami)/oxidized_manager): " app_dir
app_dir=${app_dir:-/home/$(whoami)/oxidized_manager}
mkdir -p "$app_dir"

read -p "Enter the Oxidized config path (default: ~/.config/oxidized/config): " config_path
config_path=${config_path:-~/.config/oxidized/config}

read -p "Enter the Oxidized router.db path (default: ~/.config/oxidized/router.db): " router_db_path
router_db_path=${router_db_path:-~/.config/oxidized/router.db}

read -p "Enter basic auth username (default: admin): " auth_username
auth_username=${auth_username:-admin}

read -s -p "Enter basic auth password: " auth_password
echo
if [ -z "$auth_password" ]; then
  error "Basic auth password cannot be empty."
fi

# Validate variable substitution
info "Verifying input values..."
echo "App directory: $app_dir"
echo "Config path: $config_path"
echo "Router DB path: $router_db_path"
echo "Auth username: $auth_username"
echo "Auth password: [hidden for security]"
if [[ "$config_path" == *"\$config_path"* || "$router_db_path" == *"\$router_db_path"* || "$auth_username" == *"\$auth_username"* || "$auth_password" == *"\$auth_password"* ]]; then
  error "Variable substitution failed. Please check script execution environment."
fi

# Create virtual environment
info "Creating virtual environment..."
python3 -m venv "$app_dir/venv"
source "$app_dir/venv/bin/activate"

# Install Python modules
info "Installing Python modules..."
pip install flask pyyaml gunicorn

# Generate the Python script
info "Generating app script..."
cat << EOF > "$app_dir/oxidized_config_manager.py"
"""
Oxidized Configuration Manager

A Flask web app to manage Oxidized config and router.db files.
Features:
- Edit config (username, password, interval, groups) with read-only prompt regex (toggleable).
- Editable group names in config, displayed in a three-column layout.
- Edit router.db (devices) with static model dropdown, group dropdown (restricted to defined groups, 1.5x wider column), and doubled-width input fields.
- Raw editors for config (YAML) and router.db (CSV) with automatic backups.
- Button to restart the Oxidized service with sudo password input.
- Blue color scheme with Tailwind CSS.
- Basic auth for security.
"""

import csv
import os
import shutil
from datetime import datetime
import subprocess
from functools import wraps

import yaml
from flask import Flask, Response, flash, redirect, render_template_string, request, url_for

# Configuration
app = Flask(__name__)
app.secret_key = "supersecretkey"  # TODO: Replace with environment variable in production

CONFIG_PATH = "$config_path"
ROUTER_DB_PATH = "$router_db_path"
AUTH_USERNAME = "$auth_username"
AUTH_PASSWORD = "$auth_password"

# YAML Custom Constructor
def ruby_regexp_constructor(loader, node):
    """Handle !ruby/regexp tags by returning the regex as a string."""
    return loader.construct_scalar(node)

yaml.SafeLoader.add_constructor("!ruby/regexp", ruby_regexp_constructor)

# File Handling Functions
def read_yaml_config():
    """Read and parse the Oxidized config YAML file."""
    try:
        with open(CONFIG_PATH, "r") as file:
            return yaml.safe_load(file) or {}
    except FileNotFoundError:
        flash("Config file not found.")
        return {}
    except yaml.YAMLError as e:
        flash(f"Error parsing config file: {e}")
        return {}

def write_yaml_config(config):
    """Write the config to the YAML file, preserving !ruby/regexp tags."""
    def clean_config(data):
        if isinstance(data, dict):
            return {key: clean_config(value) for key, value in data.items()}
        if isinstance(data, list):
            return [clean_config(item) for item in data]
        if isinstance(data, str) and data.startswith("/^"):
            return f"!ruby/regexp {data}"
        return data

    try:
        cleaned_config = clean_config(config)
        with open(CONFIG_PATH, "w") as file:
            yaml.safe_dump(cleaned_config, file, default_flow_style=False)
        return True
    except Exception as e:
        flash(f"Error saving config: {e}")
        return False

def read_router_db():
    """Read and parse the router.db CSV file."""
    devices = []
    try:
        if os.path.exists(ROUTER_DB_PATH):
            with open(ROUTER_DB_PATH, "r") as file:
                reader = csv.reader(file, delimiter=":")
                for row in reader:
                    if len(row) >= 6:
                        devices.append(
                            {
                                "name": row[0],
                                "ip": row[1],
                                "model": row[2],
                                "username": row[3],
                                "password": row[4],
                                "group": row[5],
                                "enable": row[6] if len(row) > 6 else "",
                            }
                        )
    except Exception as e:
        flash(f"Error reading router.db: {e}")
    return devices

def write_router_db(devices):
    """Write devices to the router.db CSV file."""
    try:
        with open(ROUTER_DB_PATH, "w", newline="") as file:
            writer = csv.writer(file, delimiter=":")
            for device in devices:
                writer.writerow(
                    [
                        device["name"],
                        device["ip"],
                        device["model"],
                        device["username"],
                        device["password"],
                        device["group"],
                        device["enable"],
                    ]
                )
        return True
    except Exception as e:
        flash(f"Error saving router.db: {e}")
        return False

def read_raw_file(file_path):
    """Read raw content of a file."""
    try:
        with open(file_path, "r") as file:
            return file.read()
    except Exception as e:
        flash(f"Error reading file {file_path}: {e}")
        return ""

def write_raw_config(content):
    """Write raw content to config file after validating YAML and creating a backup."""
    try:
        # Validate YAML
        yaml.safe_load(content)

        # Create backup if file exists
        if os.path.exists(CONFIG_PATH):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"{CONFIG_PATH}.{timestamp}.bak"
            shutil.copy2(CONFIG_PATH, backup_path)
            flash(f"Backup created: {backup_path}")

        # Write content
        with open(CONFIG_PATH, "w") as file:
            file.write(content)
        return True
    except yaml.YAMLError as e:
        flash(f"Error saving config: Invalid YAML - {e}")
        return False
    except Exception as e:
        flash(f"Error saving config: {e}")
        return False

def write_raw_router_db(content):
    """Write raw content to router.db after basic CSV validation and creating a backup."""
    try:
        # Validate CSV
        lines = content.strip().split("\n")
        for line in lines:
            if line.strip() and len(line.split(":")) < 6:
                raise ValueError(
                    "Each line must have at least 6 fields (name:ip:model:username:password:group[:enable])"
                )

        # Create backup if file exists
        if os.path.exists(ROUTER_DB_PATH):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"{ROUTER_DB_PATH}.{timestamp}.bak"
            shutil.copy2(ROUTER_DB_PATH, backup_path)
            flash(f"Backup created: {backup_path}")

        # Write content
        with open(ROUTER_DB_PATH, "w") as file:
            file.write(content)
        return True
    except Exception as e:
        flash(f"Error saving router.db: {e}")
        return False

# Authentication
def check_auth(username, password):
    """Verify basic auth credentials."""
    return username == AUTH_USERNAME and password == AUTH_PASSWORD

def authenticate():
    """Return a 401 response for authentication."""
    return Response(
        "Login required", 401, {"WWW-Authenticate": 'Basic realm="Login Required"'}
    )

def requires_auth(f):
    """Decorator to enforce basic auth."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# HTML Template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Oxidized Config Manager</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        function togglePromptEdit() {
            const display = document.getElementById("prompt-display");
            const edit = document.getElementById("prompt-edit");
            if (display.style.display === "none") {
                display.style.display = "block";
                edit.style.display = "none";
            } else {
                display.style.display = "none";
                edit.style.display = "block";
                document.getElementById("prompt-input").focus();
            }
        }
    </script>
</head>
<body class="bg-blue-50 font-sans min-h-screen">
    <div class="container mx-auto p-6 max-w-6xl">
        <h1 class="text-4xl font-extrabold text-blue-800 mb-6 text-center">
            Oxidized Configuration Manager
        </h1>

        <!-- Flash Messages -->
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                <div class="bg-blue-500 text-white p-4 rounded-xl shadow-md mb-6">
                    {% for message in messages %}
                        <p class="text-lg">{{ message }}</p>
                    {% endfor %}
                </div>
            {% endif %}
        {% endwith %}

        <!-- Restart Oxidized Button -->
        <div class="mb-6">
            <form method="POST" action="{{ url_for('restart_oxidized') }}">
                <div class="flex items-center space-x-4">
                    <input type="password" name="sudo_password" placeholder="Sudo Password"
                           class="w-64 p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none transition">
                    <button type="submit"
                            class="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition shadow-md">
                        Restart Oxidized Service
                    </button>
                </div>
            </form>
        </div>

        <!-- Config Editor -->
        <div class="bg-white p-6 rounded-xl shadow-lg mb-8">
            <h2 class="text-2xl font-semibold text-blue-700 mb-4">Edit Config</h2>
            <form method="POST" action="{{ url_for('save_config') }}">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                    <div>
                        <label class="block text-blue-600 font-medium mb-1">Username</label>
                        <input type="text" name="username" value="{{ config.username or '' }}"
                               class="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none transition">
                    </div>
                    <div>
                        <label class="block text-blue-600 font-medium mb-1">Password</label>
                        <input type="password" name="password" value="{{ config.password or '' }}"
                               class="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none transition">
                    </div>
                    <div>
                        <label class="block text-blue-600 font-medium mb-1">Interval (seconds)</label>
                        <input type="number" name="interval" value="{{ config.interval or 3600 }}"
                               class="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none transition">
                    </div>
                    <div>
                        <label class="block text-blue-600 font-medium mb-1">Prompt Regex</label>
                        <p id="prompt-display" class="w-full p-3 bg-gray-100 rounded-lg">{{ config.prompt or '' }}</p>
                        <div id="prompt-edit" style="display: none;">
                            <input type="text" id="prompt-input" name="prompt" value="{{ config.prompt or '' }}"
                                   class="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none transition">
                        </div>
                        <button type="button" onclick="togglePromptEdit()"
                                class="mt-2 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition">
                            Enable Edit
                        </button>
                    </div>
                </div>
                <h3 class="text-xl font-semibold text-blue-700 mb-3">Groups</h3>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                    {% for group, settings in config.groups.items() %}
                        <div class="mb-4 p-4 bg-blue-100 rounded-lg shadow-sm">
                            <label class="block text-blue-600 font-medium mb-1">Group Name</label>
                            <input type="text" name="groups[{{ group }}][name]" value="{{ group }}"
                                   class="w-full p-3 border border-gray-300 rounded-lg mb-2 focus:ring-2 focus:ring-blue-500 focus:outline-none transition">
                            <input type="text" name="groups[{{ group }}][username]" value="{{ settings.username or '' }}"
                                   class="w-full p-3 border border-gray-300 rounded-lg mb-2 focus:ring-2 focus:ring-blue-500 focus:outline-none transition"
                                   placeholder="Group Username">
                            <input type="password" name="groups[{{ group }}][password]" value="{{ settings.password or '' }}"
                                   class="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none transition"
                                   placeholder="Group Password">
                        </div>
                    {% endfor %}
                </div>
                <div class="mb-4 p-4 bg-blue-100 rounded-lg shadow-sm col-span-1 md:col-span-3">
                    <label class="block text-blue-600 font-medium mb-1">New Group Name</label>
                    <input type="text" name="new_group_name"
                           class="w-full p-3 border border-gray-300 rounded-lg mb-2 focus:ring-2 focus:ring-blue-500 focus:outline-none transition">
                    <input type="text" name="new_group_username"
                           class="w-full p-3 border border-gray-300 rounded-lg mb-2 focus:ring-2 focus:ring-blue-500 focus:outline-none transition"
                           placeholder="New Group Username">
                    <input type="password" name="new_group_password"
                           class="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none transition"
                           placeholder="New Group Password">
                </div>
                <button type="submit"
                        class="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition shadow-md">
                    Save Config
                </button>
            </form>
        </div>

        <!-- Router.db Editor -->
        <div class="bg-white p-6 rounded-xl shadow-lg mb-8">
            <h2 class="text-2xl font-semibold text-blue-700 mb-4">Edit router.db</h2>
            <form method="POST" action="{{ url_for('save_router_db') }}">
                <div class="overflow-x-auto">
                    <table class="w-full mb-6 border-collapse">
                        <thead>
                            <tr class="bg-blue-600 text-white">
                                <th class="p-3 text-left">Name</th>
                                <th class="p-3 text-left w-40 min-w-[10rem]">IP</th>
                                <th class="p-3 text-left">Model</th>
                                <th class="p-3 text-left">Username</th>
                                <th class="p-3 text-left">Password</th>
                                <th class="p-3 text-left w-48 min-w-[12rem]">Group</th>
                                <th class="p-3 text-left">Enable</th>
                                <th class="p-3 text-left">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for device in devices %}
                                <tr class="border-b border-gray-200 hover:bg-blue-100">
                                    <td class="p-3">
                                        <input type="text" name="devices[{{ loop.index0 }}][name]" value="{{ device.name }}"
                                               class="w-full p-4 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none transition">
                                    </td>
                                    <td class="p-3 w-40 min-w-[10rem]">
                                        <input type="text" name="devices[{{ loop.index0 }}][ip]" value="{{ device.ip }}"
                                               class="w-full p-4 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none transition">
                                    </td>
                                    <td class="p-3">
                                        <input type="text" name="devices[{{ loop.index0 }}][model]" value="{{ device.model }}" list="model-options"
                                               class="w-full p-4 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none transition">
                                        <datalist id="model-options">
                                            <option value="ios">Cisco IOS</option>
                                            <option value="junos">Juniper JunOS</option>
                                            <option value="nxos">Cisco Nexus</option>
                                            <option value="eos">Arista EOS</option>
                                            <option value="asa">Cisco ASA</option>
                                            <option value="fortios">Fortinet</option>
                                            <option value="vyos">VyOS</option>
                                            <option value="routeros">MikroTik RouterOS</option>
                                        </datalist>
                                    </td>
                                    <td class="p-3">
                                        <input type="text" name="devices[{{ loop.index0 }}][username]" value="{{ device.username }}"
                                               class="w-full p-4 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none transition">
                                    </td>
                                    <td class="p-3">
                                        <input type="password" name="devices[{{ loop.index0 }}][password]" value="{{ device.password }}"
                                               class="w-full p-4 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none transition">
                                    </td>
                                    <td class="p-3 w-48 min-w-[12rem]">
                                        <select name="devices[{{ loop.index0 }}][group]"
                                                class="w-full p-4 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none transition">
                                            <option value="">-- None --</option>
                                            {% for group in config.groups.keys()|default([]) %}
                                                <option value="{{ group }}" {% if device.group == group %}selected{% endif %}>{{ group }}</option>
                                            {% endfor %}
                                        </select>
                                    </td>
                                    <td class="p-3">
                                        <input type="text" name="devices[{{ loop.index0 }}][enable]" value="{{ device.enable }}"
                                               class="w-full p-4 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none transition">
                                    </td>
                                    <td class="p-3">
                                        <a href="{{ url_for('delete_device', index=loop.index0) }}"
                                           class="text-red-500 hover:text-red-700 font-medium transition">Delete</a>
                                    </td>
                                </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                <h3 class="text-xl font-semibold text-blue-700 mb-3">Add New Device</h3>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                    <input type="text" name="new_device[name]" placeholder="Name"
                           class="w-full p-6 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none transition">
                    <input type="text" name="new_device[ip]" placeholder="IP"
                           class="w-full p-6 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none transition">
                    <div>
                        <input type="text" name="new_device[model]" placeholder="Model" list="model-options"
                               class="w-full p-6 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none transition">
                        <datalist id="model-options">
                            <option value="ios">Cisco IOS</option>
                            <option value="junos">Juniper JunOS</option>
                            <option value="nxos">Cisco Nexus</option>
                            <option value="eos">Arista EOS</option>
                            <option value="asa">Cisco ASA</option>
                            <option value="fortios">Fortinet</option>
                            <option value="vyos">VyOS</option>
                            <option value="routeros">MikroTik RouterOS</option>
                        </datalist>
                    </div>
                    <input type="text" name="new_device[username]" placeholder="Username"
                           class="w-full p-6 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none transition">
                    <input type="password" name="new_device[password]" placeholder="Password"
                           class="w-full p-6 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none transition">
                    <div>
                        <select name="new_device[group]"
                                class="w-full p-6 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none transition">
                            <option value="">-- None --</option>
                            {% for group in config.groups.keys()|default([]) %}
                                <option value="{{ group }}">{{ group }}</option>
                            {% endfor %}
                        </select>
                    </div>
                    <input type="text" name="new_device[enable]" placeholder="Enable Password"
                           class="w-full p-6 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none transition">
                </div>
                <button type="submit"
                        class="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition shadow-md">
                    Save router.db
                </button>
            </form>
        </div>

        <!-- Raw Config Editor -->
        <div class="bg-white p-6 rounded-xl shadow-lg mb-8">
            <h2 class="text-2xl font-semibold text-blue-700 mb-4">Raw Config Editor</h2>
            <form method="POST" action="{{ url_for('save_raw_config') }}">
                <div class="mb-4">
                    <label class="block text-blue-600 font-medium mb-1">Raw config file (YAML)</label>
                    <textarea name="raw_config" rows="10"
                              class="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none transition font-mono">{{ raw_config }}</textarea>
                </div>
                <button type="submit"
                        class="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition shadow-md">
                    Save Raw Config
                </button>
            </form>
        </div>

        <!-- Raw router.db Editor -->
        <div class="bg-white p-6 rounded-xl shadow-lg">
            <h2 class="text-2xl font-semibold text-blue-700 mb-4">Raw router.db Editor</h2>
            <form method="POST" action="{{ url_for('save_raw_router_db') }}">
                <div class="mb-4">
                    <label class="block text-blue-600 font-medium mb-1">Raw router.db file (CSV)</label>
                    <textarea name="raw_router_db" rows="10"
                              class="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none transition font-mono">{{ raw_router_db }}</textarea>
                </div>
                <button type="submit"
                        class="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition shadow-md">
                    Save Raw router.db
                </button>
            </form>
        </div>
    </div>
</body>
</html>
"""

# Routes
@app.route("/")
@requires_auth
def index():
    """Render the main page with config and router.db editors."""
    config = read_yaml_config()
    devices = read_router_db()
    raw_config = read_raw_file(CONFIG_PATH)
    raw_router_db = read_raw_file(ROUTER_DB_PATH)
    return render_template_string(
        HTML_TEMPLATE,
        config=config,
        devices=devices,
        raw_config=raw_config,
        raw_router_db=raw_router_db,
    )

@app.route("/save_config", methods=["POST"])
@requires_auth
def save_config():
    """Save changes to the config file, including renamed groups."""
    config = read_yaml_config()
    config["username"] = request.form.get("username", "")
    config["password"] = request.form.get("password", "")
    config["interval"] = int(request.form.get("interval", 3600))
    config["prompt"] = request.form.get("prompt", "")

    # Update existing groups with potential new names
    new_groups = {}
    for old_group in config.get("groups", {}):
        new_group_name = request.form.get(f"groups[{old_group}][name]", old_group).strip()
        if new_group_name:
            new_groups[new_group_name] = {
                "username": request.form.get(f"groups[{old_group}][username]", ""),
                "password": request.form.get(f"groups[{old_group}][password]", ""),
            }
    config["groups"] = new_groups

    # Add new group if provided
    new_group_name = request.form.get("new_group_name", "").strip()
    if new_group_name:
        config["groups"][new_group_name] = {
            "username": request.form.get("new_group_username", ""),
            "password": request.form.get("new_group_password", ""),
        }

    if write_yaml_config(config):
        flash("Config saved successfully!")
    return redirect(url_for("index"))

@app.route("/save_router_db", methods=["POST"])
@requires_auth
def save_router_db():
    """Save changes to the router.db file."""
    devices = []
    i = 0
    while f"devices[{i}][name]" in request.form:
        devices.append(
            {
                "name": request.form.get(f"devices[{i}][name]", ""),
                "ip": request.form.get(f"devices[{i}][ip]", ""),
                "model": request.form.get(f"devices[{i}][model]", ""),
                "username": request.form.get(f"devices[{i}][username]", ""),
                "password": request.form.get(f"devices[{i}][password]", ""),
                "group": request.form.get(f"devices[{i}][group]", ""),
                "enable": request.form.get(f"devices[{i}][enable]", ""),
            }
        )
        i += 1

    # Add new device if provided
    if request.form.get("new_device[name]", "").strip():
        devices.append(
            {
                "name": request.form.get("new_device[name]", ""),
                "ip": request.form.get("new_device[ip]", ""),
                "model": request.form.get("new_device[model]", ""),
                "username": request.form.get("new_device[username]", ""),
                "password": request.form.get("new_device[password]", ""),
                "group": request.form.get("new_device[group]", ""),
                "enable": request.form.get("new_device[enable]", ""),
            }
        )

    if write_router_db(devices):
        flash("router.db saved successfully!")
    return redirect(url_for("index"))

@app.route("/delete_device/<int:index>")
@requires_auth
def delete_device(index):
    """Delete a device from router.db by index."""
    devices = read_router_db()
    if 0 <= index < len(devices):
        devices.pop(index)
        if write_router_db(devices):
            flash("Device deleted successfully!")
    else:
        flash("Invalid device index.")
    return redirect(url_for("index"))

@app.route("/save_raw_config", methods=["POST"])
@requires_auth
def save_raw_config():
    """Save raw config file content."""
    raw_content = request.form.get("raw_config", "")
    if write_raw_config(raw_content):
        flash("Raw config saved successfully!")
    return redirect(url_for("index"))

@app.route("/save_raw_router_db", methods=["POST"])
@requires_auth
def save_raw_router_db():
    """Save raw router.db file content."""
    raw_content = request.form.get("raw_router_db", "")
    if write_raw_router_db(raw_content):
        flash("Raw router.db saved successfully!")
    return redirect(url_for("index"))

@app.route("/restart_oxidized", methods=["POST"])
@requires_auth
def restart_oxidized():
    """Restart the Oxidized service using systemctl with sudo password."""
    sudo_password = request.form.get("sudo_password", "")
    if not sudo_password:
        flash("Sudo password is required.")
        return redirect(url_for("index"))

    try:
        # Use sudo -S to read password from stdin
        process = subprocess.run(
            ["/usr/bin/sudo", "-S", "systemctl", "restart", "oxidized"],
            input=sudo_password + "\n",
            capture_output=True,
            text=True,
            check=True,
        )
        flash("Oxidized service restarted successfully!")
    except subprocess.CalledProcessError as e:
        flash(f"Error restarting Oxidized service: {e.stderr}")
    except Exception as e:
        flash(f"Unexpected error restarting Oxidized: {str(e)}")
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
EOF

# Verify script content
info "Verifying generated script..."
if grep -q "\$auth_username" "$app_dir/oxidized_config_manager.py"; then
  error "Variable substitution failed in $app_dir/oxidized_config_manager.py. Check script for placeholders."
fi
info "Generated script looks good."

# Set permissions for app directory and files
chown -R $(whoami):$(whoami) "$app_dir"
chmod 755 "$app_dir/oxidized_config_manager.py"
chmod -R 664 "$app_dir/venv"

# Set up systemd service
info "Setting up systemd service..."
cat << EOF > /etc/systemd/system/oxidized-manager.service
[Unit]
Description=Oxidized Config Manager Flask App
After=network.target

[Service]
User=$(whoami)
WorkingDirectory=$app_dir
Environment="PATH=$app_dir/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$app_dir/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:5000 oxidized_config_manager:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable oxidized-manager
systemctl start oxidized-manager

# Configure firewall
info "Configuring firewall for port 5000..."
ufw allow 5000
ufw reload

# Final instructions
info "Installation complete!"
info "App is running at http://<your-ip>:5000"
info "Login with username: $auth_username and the password you set."
info "Oxidized config: $config_path"
info "router.db: $router_db_path"
info "To restart the app service: sudo systemctl restart oxidized-manager"
info "To check status: sudo systemctl status oxidized-manager"
info "If Oxidized is not running, configure and start it manually: sudo systemctl start oxidized"