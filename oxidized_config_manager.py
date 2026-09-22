"""Oxidized Configuration Manager."""

import csv
import os
import shutil
import subprocess
from datetime import datetime
from functools import wraps

import yaml
from flask import Flask, Response, flash, redirect, render_template_string, request, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("OXIDIZED_MANAGER_SECRET", "supersecretkey")

CONFIG_PATH = "/home/pal/.config/oxidized/config"
ROUTER_DB_PATH = "/home/pal/.config/oxidized/router.db"
AUTH_USERNAME = os.environ.get("OXIDIZED_MANAGER_USER", "admin")
AUTH_PASSWORD = os.environ.get("OXIDIZED_MANAGER_PASSWORD", "sodeX*ho123")


class RubyRegexp(str):
    """Value that must retain Oxidized's !ruby/regexp YAML tag."""


class OxidizedLoader(yaml.SafeLoader):
    pass


class OxidizedDumper(yaml.SafeDumper):
    pass


def ruby_regexp_constructor(loader, node):
    return RubyRegexp(loader.construct_scalar(node))


def ruby_regexp_representer(dumper, value):
    return dumper.represent_scalar("!ruby/regexp", str(value), style=None)


OxidizedLoader.add_constructor("!ruby/regexp", ruby_regexp_constructor)
OxidizedDumper.add_representer(RubyRegexp, ruby_regexp_representer)


def strip_regexp_tag(value):
    value = str(value).strip()
    if value.startswith("!ruby/regexp"):
        value = value[len("!ruby/regexp"):].strip()
    return value


def create_backup(path):
    if not os.path.exists(path):
        return None
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = f"{path}.{stamp}.bak"
    shutil.copy2(path, backup)
    return backup


def read_yaml_config():
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as file:
            return yaml.load(file, Loader=OxidizedLoader) or {}
    except FileNotFoundError:
        flash("Config file not found.")
    except yaml.YAMLError as error:
        flash(f"Error parsing config file: {error}")
    except Exception as error:
        flash(f"Error reading config file: {error}")
    return {}


def normalise_regexps(config):
    if config.get("prompt") is not None:
        config["prompt"] = RubyRegexp(strip_regexp_tag(config["prompt"]))

    source = config.get("source")
    if isinstance(source, dict):
        csv_config = source.get("csv")
        if isinstance(csv_config, dict) and csv_config.get("delimiter") is not None:
            csv_config["delimiter"] = RubyRegexp(strip_regexp_tag(csv_config["delimiter"]))
    return config


def write_yaml_config(config):
    temp_path = f"{CONFIG_PATH}.tmp"
    try:
        normalise_regexps(config)
        backup = create_backup(CONFIG_PATH)
        if backup:
            flash(f"Backup created: {backup}")

        with open(temp_path, "w", encoding="utf-8") as file:
            yaml.dump(
                config,
                file,
                Dumper=OxidizedDumper,
                default_flow_style=False,
                sort_keys=False,
                allow_unicode=True,
                explicit_start=True,
            )
        os.replace(temp_path, CONFIG_PATH)
        return True
    except Exception as error:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        flash(f"Error saving config: {error}")
        return False


def read_router_db():
    devices = []
    try:
        if os.path.exists(ROUTER_DB_PATH):
            with open(ROUTER_DB_PATH, "r", encoding="utf-8", newline="") as file:
                for row in csv.reader(file, delimiter=":"):
                    if len(row) >= 6:
                        devices.append({
                            "name": row[0], "ip": row[1], "model": row[2],
                            "username": row[3], "password": row[4], "group": row[5],
                            "enable": row[6] if len(row) > 6 else "",
                        })
    except Exception as error:
        flash(f"Error reading router.db: {error}")
    return devices


def write_router_db(devices):
    temp_path = f"{ROUTER_DB_PATH}.tmp"
    try:
        grouped = {}
        for device in devices:
            grouped.setdefault(device["group"] or "default", []).append(device)

        backup = create_backup(ROUTER_DB_PATH)
        if backup:
            flash(f"Backup created: {backup}")

        with open(temp_path, "w", encoding="utf-8", newline="") as file:
            writer = csv.writer(file, delimiter=":", lineterminator="\n")
            for group_number, group_devices in enumerate(grouped.values()):
                if group_number:
                    file.write("\n")
                for device in group_devices:
                    row = [device[key] for key in ("name", "ip", "model", "username", "password", "group")]
                    if device["enable"]:
                        row.append(device["enable"])
                    writer.writerow(row)
        os.replace(temp_path, ROUTER_DB_PATH)
        return True
    except Exception as error:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        flash(f"Error saving router.db: {error}")
        return False


def read_raw_file(path):
    try:
        with open(path, "r", encoding="utf-8") as file:
            return file.read()
    except Exception as error:
        flash(f"Error reading {path}: {error}")
        return ""


def write_raw_config(content):
    temp_path = f"{CONFIG_PATH}.tmp"
    try:
        parsed = yaml.load(content, Loader=OxidizedLoader)
        if not isinstance(parsed, dict):
            raise ValueError("Config must contain a YAML mapping.")
        backup = create_backup(CONFIG_PATH)
        if backup:
            flash(f"Backup created: {backup}")
        with open(temp_path, "w", encoding="utf-8") as file:
            file.write(content)
            if content and not content.endswith("\n"):
                file.write("\n")
        os.replace(temp_path, CONFIG_PATH)
        return True
    except (yaml.YAMLError, ValueError) as error:
        flash(f"Error saving config: Invalid YAML - {error}")
    except Exception as error:
        flash(f"Error saving config: {error}")
    if os.path.exists(temp_path):
        os.remove(temp_path)
    return False


def write_raw_router_db(content):
    temp_path = f"{ROUTER_DB_PATH}.tmp"
    try:
        for line in content.splitlines():
            if line.strip() and len(line.split(":")) < 6:
                raise ValueError("Each non-empty line needs at least 6 colon-separated fields.")
        backup = create_backup(ROUTER_DB_PATH)
        if backup:
            flash(f"Backup created: {backup}")
        with open(temp_path, "w", encoding="utf-8") as file:
            file.write(content)
            if content and not content.endswith("\n"):
                file.write("\n")
        os.replace(temp_path, ROUTER_DB_PATH)
        return True
    except Exception as error:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        flash(f"Error saving router.db: {error}")
        return False


def check_auth(username, password):
    return username == AUTH_USERNAME and password == AUTH_PASSWORD


def authenticate():
    return Response("Login required", 401, {"WWW-Authenticate": 'Basic realm="Login Required"'})


def requires_auth(function):
    @wraps(function)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return function(*args, **kwargs)
    return decorated


HTML_TEMPLATE = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Oxidized Config Manager</title>
<script src="https://cdn.tailwindcss.com"></script>
<script>
function togglePromptEdit() {
    const display = document.getElementById('prompt-display');
    const edit = document.getElementById('prompt-edit');
    const button = document.getElementById('prompt-button');
    if (edit.style.display === 'none') {
        display.style.display = 'none'; edit.style.display = 'block';
        button.textContent = 'Disable Edit'; document.getElementById('prompt-input').focus();
    } else {
        display.style.display = 'block'; edit.style.display = 'none'; button.textContent = 'Enable Edit';
    }
}
</script>
</head>
<body class="bg-blue-50 font-sans min-h-screen">
<div class="container mx-auto p-6 max-w-7xl">
<h1 class="text-4xl font-extrabold text-blue-800 mb-6 text-center">Oxidized Configuration Manager</h1>

{% with messages = get_flashed_messages() %}{% if messages %}
<div class="bg-blue-600 text-white p-4 rounded-xl shadow-md mb-6">
{% for message in messages %}<p>{{ message }}</p>{% endfor %}
</div>{% endif %}{% endwith %}

<div class="mb-6"><form method="POST" action="{{ url_for('restart_oxidized') }}" class="flex gap-4">
<input type="password" name="sudo_password" placeholder="Sudo Password" class="w-64 p-3 border rounded-lg">
<button class="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700">Restart Oxidized Service</button>
</form></div>

<section class="bg-white p-6 rounded-xl shadow-lg mb-8">
<h2 class="text-2xl font-semibold text-blue-700 mb-4">Edit Config</h2>
<form method="POST" action="{{ url_for('save_config') }}">
<div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
<label>Username<input name="username" value="{{ config.get('username', '') }}" class="block w-full p-3 border rounded-lg"></label>
<label>Password<input type="password" name="password" value="{{ config.get('password', '') }}" class="block w-full p-3 border rounded-lg"></label>
<label>Interval<input type="number" name="interval" value="{{ config.get('interval', 3600) }}" class="block w-full p-3 border rounded-lg"></label>
<div><label>Prompt Regex</label><p id="prompt-display" class="p-3 bg-gray-100 rounded-lg font-mono">{{ config.get('prompt', '') }}</p>
<div id="prompt-edit" style="display:none"><input id="prompt-input" name="prompt" value="{{ config.get('prompt', '') }}" class="w-full p-3 border rounded-lg font-mono"></div>
<button id="prompt-button" type="button" onclick="togglePromptEdit()" class="mt-2 bg-blue-600 text-white px-4 py-2 rounded-lg">Enable Edit</button></div>
</div>
<h3 class="text-xl font-semibold text-blue-700 mb-3">Groups</h3>
<div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
{% for group, settings in config.get('groups', {}).items() %}
<div class="p-4 bg-blue-100 rounded-lg">
<input name="groups[{{ group }}][name]" value="{{ group }}" class="w-full p-3 border rounded-lg mb-2">
<input name="groups[{{ group }}][username]" value="{{ settings.get('username', '') }}" placeholder="Username" class="w-full p-3 border rounded-lg mb-2">
<input type="password" name="groups[{{ group }}][password]" value="{{ settings.get('password', '') }}" placeholder="Password" class="w-full p-3 border rounded-lg">
</div>{% endfor %}
</div>
<div class="p-4 bg-blue-100 rounded-lg mb-4">
<input name="new_group_name" placeholder="New Group Name" class="w-full p-3 border rounded-lg mb-2">
<input name="new_group_username" placeholder="New Group Username" class="w-full p-3 border rounded-lg mb-2">
<input type="password" name="new_group_password" placeholder="New Group Password" class="w-full p-3 border rounded-lg">
</div>
<button class="bg-blue-600 text-white px-6 py-3 rounded-lg">Save Config</button>
</form></section>

<datalist id="model-options"><option value="ios"><option value="junos"><option value="nxos"><option value="eos"><option value="asa"><option value="fortios"><option value="vyos"><option value="routeros"></datalist>
<section class="bg-white p-6 rounded-xl shadow-lg mb-8">
<h2 class="text-2xl font-semibold text-blue-700 mb-4">Edit router.db</h2>
<form method="POST" action="{{ url_for('save_router_db') }}"><div class="overflow-x-auto"><table class="w-full mb-6">
<thead><tr class="bg-blue-600 text-white"><th>Name</th><th>IP</th><th>Model</th><th>Username</th><th>Password</th><th>Group</th><th>Enable</th><th>Action</th></tr></thead><tbody>
{% for device in devices %}{% set device_index = loop.index0 %}<tr class="border-b">
{% for key in ['name','ip','model','username','password'] %}<td class="p-1"><input {% if key == 'password' %}type="password"{% endif %} name="devices[{{ device_index }}][{{ key }}]" value="{{ device[key] }}" class="w-full p-2 border rounded"></td>{% endfor %}
<td class="p-1"><select name="devices[{{ device_index }}][group]" class="w-full p-2 border rounded"><option value="">-- None --</option>{% for group in config.get('groups', {}) %}<option value="{{ group }}" {% if device.group == group %}selected{% endif %}>{{ group }}</option>{% endfor %}</select></td>
<td class="p-1"><input name="devices[{{ device_index }}][enable]" value="{{ device.enable }}" class="w-full p-2 border rounded"></td>
<td class="p-1"><a href="{{ url_for('delete_device', index=device_index) }}" class="text-red-600">Delete</a></td></tr>{% endfor %}
</tbody></table></div>
<h3 class="text-xl font-semibold text-blue-700 mb-3">Add New Device</h3><div class="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4">
{% for key in ['name','ip','model','username','password','enable'] %}<input {% if key == 'password' %}type="password"{% endif %} name="new_device[{{ key }}]" placeholder="{{ key|capitalize }}" class="p-3 border rounded-lg">{% endfor %}
<select name="new_device[group]" class="p-3 border rounded-lg"><option value="">-- None --</option>{% for group in config.get('groups', {}) %}<option>{{ group }}</option>{% endfor %}</select>
</div><button class="bg-blue-600 text-white px-6 py-3 rounded-lg">Save router.db</button></form></section>

<section class="bg-white p-6 rounded-xl shadow-lg mb-8"><h2 class="text-2xl font-semibold text-blue-700 mb-4">Raw Config Editor</h2>
<form method="POST" action="{{ url_for('save_raw_config') }}"><textarea name="raw_config" rows="18" class="w-full p-3 border rounded-lg font-mono mb-4">{{ raw_config }}</textarea><button class="bg-blue-600 text-white px-6 py-3 rounded-lg">Save Raw Config</button></form></section>
<section class="bg-white p-6 rounded-xl shadow-lg"><h2 class="text-2xl font-semibold text-blue-700 mb-4">Raw router.db Editor</h2>
<form method="POST" action="{{ url_for('save_raw_router_db') }}"><textarea name="raw_router_db" rows="18" class="w-full p-3 border rounded-lg font-mono mb-4">{{ raw_router_db }}</textarea><button class="bg-blue-600 text-white px-6 py-3 rounded-lg">Save Raw router.db</button></form></section>
</div></body></html>'''


@app.route("/")
@requires_auth
def index():
    config = read_yaml_config()
    return render_template_string(HTML_TEMPLATE, config=config, devices=read_router_db(), raw_config=read_raw_file(CONFIG_PATH), raw_router_db=read_raw_file(ROUTER_DB_PATH))


@app.route("/save_config", methods=["POST"])
@requires_auth
def save_config():
    config = read_yaml_config()
    config["username"] = request.form.get("username", "").strip()
    config["password"] = request.form.get("password", "")
    try:
        config["interval"] = int(request.form.get("interval", 3600))
    except (TypeError, ValueError):
        flash("Interval must be a valid number.")
        return redirect(url_for("index"))

    prompt = request.form.get("prompt")
    if prompt and prompt.strip():
        config["prompt"] = RubyRegexp(strip_regexp_tag(prompt))

    groups = {}
    for old_name in config.get("groups", {}):
        new_name = request.form.get(f"groups[{old_name}][name]", old_name).strip()
        if new_name:
            groups[new_name] = {
                "username": request.form.get(f"groups[{old_name}][username]", ""),
                "password": request.form.get(f"groups[{old_name}][password]", ""),
            }
    config["groups"] = groups
    new_name = request.form.get("new_group_name", "").strip()
    if new_name:
        config["groups"][new_name] = {"username": request.form.get("new_group_username", ""), "password": request.form.get("new_group_password", "")}
    if write_yaml_config(config):
        flash("Config saved successfully.")
    return redirect(url_for("index"))


@app.route("/save_router_db", methods=["POST"])
@requires_auth
def save_router_db():
    devices = []
    index = 0
    keys = ("name", "ip", "model", "username", "password", "group", "enable")
    while f"devices[{index}][name]" in request.form:
        devices.append({key: request.form.get(f"devices[{index}][{key}]", "") for key in keys})
        index += 1
    if request.form.get("new_device[name]", "").strip():
        devices.append({key: request.form.get(f"new_device[{key}]", "") for key in keys})
    if write_router_db(devices):
        flash("router.db saved successfully.")
    return redirect(url_for("index"))


@app.route("/delete_device/<int:index>")
@requires_auth
def delete_device(index):
    devices = read_router_db()
    if 0 <= index < len(devices):
        devices.pop(index)
        if write_router_db(devices):
            flash("Device deleted successfully.")
    else:
        flash("Invalid device index.")
    return redirect(url_for("index"))


@app.route("/save_raw_config", methods=["POST"])
@requires_auth
def save_raw_config():
    if write_raw_config(request.form.get("raw_config", "")):
        flash("Raw config saved successfully.")
    return redirect(url_for("index"))


@app.route("/save_raw_router_db", methods=["POST"])
@requires_auth
def save_raw_router_db():
    if write_raw_router_db(request.form.get("raw_router_db", "")):
        flash("Raw router.db saved successfully.")
    return redirect(url_for("index"))


@app.route("/restart_oxidized", methods=["POST"])
@requires_auth
def restart_oxidized():
    password = request.form.get("sudo_password", "")
    if not password:
        flash("Sudo password is required.")
        return redirect(url_for("index"))
    try:
        subprocess.run(["/usr/bin/sudo", "-S", "systemctl", "restart", "oxidized"], input=password + "\n", capture_output=True, text=True, check=True)
        flash("Oxidized service restarted successfully.")
    except subprocess.CalledProcessError as error:
        flash(f"Error restarting Oxidized service: {error.stderr.strip()}")
    except Exception as error:
        flash(f"Unexpected error restarting Oxidized: {error}")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
