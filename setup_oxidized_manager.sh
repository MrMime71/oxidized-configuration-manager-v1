#!/usr/bin/env bash
set -Eeuo pipefail

info(){ printf '\033[0;32m[INFO]\033[0m %s\n' "$*"; }
warn(){ printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
die(){ printf '\033[0;31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -ne 0 ]] || die "Run as the normal application user, not root."
sudo -v || die "Sudo authentication failed."
USER_NAME=$(id -un); GROUP_NAME=$(id -gn); USER_HOME=$HOME

sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip ufw

read -r -p "App directory [$USER_HOME/oxidized_manager]: " APP_DIR
APP_DIR=${APP_DIR:-$USER_HOME/oxidized_manager}
read -r -p "Oxidized config [$USER_HOME/.config/oxidized/config]: " CONFIG_PATH
CONFIG_PATH=${CONFIG_PATH:-$USER_HOME/.config/oxidized/config}
read -r -p "router.db [$USER_HOME/.config/oxidized/router.db]: " ROUTER_DB_PATH
ROUTER_DB_PATH=${ROUTER_DB_PATH:-$USER_HOME/.config/oxidized/router.db}
read -r -p "Web username [admin]: " WEB_USER
WEB_USER=${WEB_USER:-admin}
read -r -s -p "Web password: " WEB_PASSWORD; echo
[[ -n $WEB_PASSWORD ]] || die "Web password cannot be empty."
APP_SECRET=$(python3 -c 'import secrets; print(secrets.token_hex(32))')

mkdir -p "$APP_DIR" "$(dirname "$CONFIG_PATH")" "$(dirname "$ROUTER_DB_PATH")"
touch "$CONFIG_PATH" "$ROUTER_DB_PATH"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip
"$APP_DIR/venv/bin/pip" install flask pyyaml gunicorn

cat > "$APP_DIR/oxidized_config_manager.py" <<'PYAPP'
import csv, os, shutil, subprocess
from datetime import datetime
from functools import wraps
import yaml
from flask import Flask, Response, flash, redirect, render_template_string, request, url_for

app=Flask(__name__)
app.secret_key=os.environ["OXIDIZED_MANAGER_SECRET"]
CONFIG_PATH=os.environ["OXIDIZED_CONFIG_PATH"]
ROUTER_DB_PATH=os.environ["OXIDIZED_ROUTER_DB_PATH"]
AUTH_USERNAME=os.environ["OXIDIZED_MANAGER_USER"]
AUTH_PASSWORD=os.environ["OXIDIZED_MANAGER_PASSWORD"]

class RubyRegexp(str): pass
class OxidizedLoader(yaml.SafeLoader): pass
class OxidizedDumper(yaml.SafeDumper): pass
OxidizedLoader.add_constructor("!ruby/regexp",lambda loader,node: RubyRegexp(loader.construct_scalar(node)))
OxidizedDumper.add_representer(RubyRegexp,lambda dumper,value: dumper.represent_scalar("!ruby/regexp",str(value)))

def clean_regex(value):
    value=str(value).strip()
    return value[len("!ruby/regexp"):].strip() if value.startswith("!ruby/regexp") else value

def backup(path):
    if os.path.exists(path):
        target=f"{path}.{datetime.now():%Y%m%d_%H%M%S}.bak"
        shutil.copy2(path,target); return target

def read_config():
    try:
        with open(CONFIG_PATH,encoding="utf-8") as f: return yaml.load(f,Loader=OxidizedLoader) or {}
    except Exception as e: flash(f"Config read error: {e}"); return {}

def save_config_file(config):
    temp=CONFIG_PATH+".tmp"
    try:
        if config.get("prompt") is not None: config["prompt"]=RubyRegexp(clean_regex(config["prompt"]))
        csv_cfg=config.get("source",{}).get("csv",{})
        if csv_cfg.get("delimiter") is not None: csv_cfg["delimiter"]=RubyRegexp(clean_regex(csv_cfg["delimiter"]))
        old=backup(CONFIG_PATH)
        if old: flash(f"Backup created: {old}")
        with open(temp,"w",encoding="utf-8") as f:
            yaml.dump(config,f,Dumper=OxidizedDumper,sort_keys=False,default_flow_style=False,explicit_start=True)
        os.replace(temp,CONFIG_PATH); return True
    except Exception as e:
        if os.path.exists(temp): os.remove(temp)
        flash(f"Config save error: {e}"); return False

def read_devices():
    result=[]
    try:
        with open(ROUTER_DB_PATH,encoding="utf-8",newline="") as f:
            for row in csv.reader(f,delimiter=":"):
                if len(row)>=6: result.append(dict(name=row[0],ip=row[1],model=row[2],username=row[3],password=row[4],group=row[5],enable=row[6] if len(row)>6 else ""))
    except FileNotFoundError: pass
    except Exception as e: flash(f"router.db read error: {e}")
    return result

def save_devices(devices):
    temp=ROUTER_DB_PATH+".tmp"
    try:
        old=backup(ROUTER_DB_PATH)
        if old: flash(f"Backup created: {old}")
        with open(temp,"w",encoding="utf-8",newline="") as f:
            writer=csv.writer(f,delimiter=":",lineterminator="\n")
            for d in devices:
                row=[d[x] for x in ("name","ip","model","username","password","group")]
                if d["enable"]: row.append(d["enable"])
                writer.writerow(row)
        os.replace(temp,ROUTER_DB_PATH); return True
    except Exception as e:
        if os.path.exists(temp): os.remove(temp)
        flash(f"router.db save error: {e}"); return False

def auth_ok(user,password): return user==AUTH_USERNAME and password==AUTH_PASSWORD
def protected(fn):
    @wraps(fn)
    def wrapped(*a,**k):
        auth=request.authorization
        return fn(*a,**k) if auth and auth_ok(auth.username,auth.password) else Response("Login required",401,{"WWW-Authenticate":'Basic realm="Login"'})
    return wrapped

PAGE='''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Oxidized Manager</title><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-blue-50"><main class="max-w-7xl mx-auto p-6"><h1 class="text-3xl font-bold text-blue-800 mb-6">Oxidized Configuration Manager</h1>
{% for m in get_flashed_messages() %}<div class="bg-blue-600 text-white p-3 mb-3 rounded">{{m}}</div>{% endfor %}
<section class="bg-white p-5 rounded shadow mb-6"><h2 class="text-xl font-bold mb-3">Config</h2><form method="post" action="{{url_for('save_config')}}">
<div class="grid md:grid-cols-2 gap-3"><input class="border p-2" name="username" value="{{config.get('username','')}}" placeholder="Username"><input class="border p-2" type="password" name="password" value="{{config.get('password','')}}" placeholder="Password"><input class="border p-2" type="number" name="interval" value="{{config.get('interval',3600)}}"><input class="border p-2 font-mono" name="prompt" value="{{config.get('prompt','')}}"></div>
<h3 class="font-bold mt-4">Groups</h3><div class="grid md:grid-cols-3 gap-3">{% for name,s in config.get('groups',{}).items() %}<div class="bg-blue-100 p-3"><input class="border p-2 w-full" name="groups[{{name}}][name]" value="{{name}}"><input class="border p-2 w-full mt-2" name="groups[{{name}}][username]" value="{{s.get('username','')}}"><input class="border p-2 w-full mt-2" type="password" name="groups[{{name}}][password]" value="{{s.get('password','')}}"></div>{% endfor %}</div>
<div class="grid md:grid-cols-3 gap-3 mt-3"><input class="border p-2" name="new_group_name" placeholder="New group"><input class="border p-2" name="new_group_username" placeholder="Username"><input class="border p-2" type="password" name="new_group_password" placeholder="Password"></div><button class="bg-blue-600 text-white p-3 mt-4 rounded">Save Config</button></form></section>
<section class="bg-white p-5 rounded shadow mb-6"><h2 class="text-xl font-bold mb-3">router.db</h2><form method="post" action="{{url_for('save_router')}}"><div class="overflow-x-auto"><table class="w-full"><tr>{% for h in ['Name','IP','Model','Username','Password','Group','Enable',''] %}<th>{{h}}</th>{% endfor %}</tr>{% for d in devices %}{% set i=loop.index0 %}<tr>{% for key in ['name','ip','model','username','password','group','enable'] %}<td><input class="border p-2 w-full" {% if key=='password' %}type="password"{% endif %} name="devices[{{i}}][{{key}}]" value="{{d[key]}}"></td>{% endfor %}<td><a class="text-red-600" href="{{url_for('delete_device',index=i)}}">Delete</a></td></tr>{% endfor %}</table></div>
<h3 class="font-bold mt-4">New device</h3><div class="grid md:grid-cols-4 gap-2">{% for key in ['name','ip','model','username','password','group','enable'] %}<input class="border p-2" {% if key=='password' %}type="password"{% endif %} name="new[{{key}}]" placeholder="{{key}}">{% endfor %}</div><button class="bg-blue-600 text-white p-3 mt-4 rounded">Save router.db</button></form></section>
<section class="bg-white p-5 rounded shadow mb-6"><h2 class="font-bold">Raw config</h2><form method="post" action="{{url_for('save_raw_config')}}"><textarea class="border w-full p-2 font-mono" rows="15" name="content">{{raw_config}}</textarea><button class="bg-blue-600 text-white p-3 mt-2 rounded">Save Raw Config</button></form></section>
<section class="bg-white p-5 rounded shadow"><form method="post" action="{{url_for('restart')}}"><input class="border p-2" type="password" name="sudo_password" placeholder="Sudo password"><button class="bg-blue-600 text-white p-3 rounded">Restart Oxidized</button></form></section></main></body></html>'''

@app.route('/')
@protected
def index():
    with open(CONFIG_PATH,encoding='utf-8') as f: raw=f.read()
    return render_template_string(PAGE,config=read_config(),devices=read_devices(),raw_config=raw)

@app.post('/save_config')
@protected
def save_config():
    c=read_config(); c['username']=request.form.get('username',''); c['password']=request.form.get('password','')
    try: c['interval']=int(request.form.get('interval','3600'))
    except ValueError: flash('Interval must be numeric.'); return redirect(url_for('index'))
    if request.form.get('prompt','').strip(): c['prompt']=RubyRegexp(clean_regex(request.form['prompt']))
    groups={}
    for old in c.get('groups',{}):
        new=request.form.get(f'groups[{old}][name]',old).strip()
        if new: groups[new]={'username':request.form.get(f'groups[{old}][username]',''),'password':request.form.get(f'groups[{old}][password]','')}
    new=request.form.get('new_group_name','').strip()
    if new: groups[new]={'username':request.form.get('new_group_username',''),'password':request.form.get('new_group_password','')}
    c['groups']=groups
    if save_config_file(c): flash('Config saved successfully.')
    return redirect(url_for('index'))

@app.post('/save_router')
@protected
def save_router():
    keys=('name','ip','model','username','password','group','enable'); devices=[]; i=0
    while f'devices[{i}][name]' in request.form:
        devices.append({k:request.form.get(f'devices[{i}][{k}]','') for k in keys}); i+=1
    if request.form.get('new[name]','').strip(): devices.append({k:request.form.get(f'new[{k}]','') for k in keys})
    if save_devices(devices): flash('router.db saved successfully.')
    return redirect(url_for('index'))

@app.get('/delete/<int:index>')
@protected
def delete_device(index):
    devices=read_devices()
    if 0<=index<len(devices): devices.pop(index); save_devices(devices)
    return redirect(url_for('index'))

@app.post('/save_raw_config')
@protected
def save_raw_config():
    content=request.form.get('content','')
    try:
        yaml.load(content,Loader=OxidizedLoader)
        old=backup(CONFIG_PATH)
        if old: flash(f'Backup created: {old}')
        with open(CONFIG_PATH,'w',encoding='utf-8') as f: f.write(content if content.endswith('\n') else content+'\n')
        flash('Raw config saved successfully.')
    except Exception as e: flash(f'Invalid config: {e}')
    return redirect(url_for('index'))

@app.post('/restart')
@protected
def restart():
    password=request.form.get('sudo_password','')
    try:
        subprocess.run(['/usr/bin/sudo','-S','systemctl','restart','oxidized'],input=password+'\n',text=True,capture_output=True,check=True); flash('Oxidized restarted.')
    except Exception as e: flash(f'Restart failed: {e}')
    return redirect(url_for('index'))
PYAPP

"$APP_DIR/venv/bin/python" -m py_compile "$APP_DIR/oxidized_config_manager.py" || die "Generated Python failed validation."
chmod 750 "$APP_DIR/oxidized_config_manager.py"

ENV_FILE="$APP_DIR/oxidized-manager.env"
umask 077
cat > "$ENV_FILE" <<EOF
OXIDIZED_MANAGER_SECRET=$APP_SECRET
OXIDIZED_MANAGER_USER=$WEB_USER
OXIDIZED_MANAGER_PASSWORD=$WEB_PASSWORD
OXIDIZED_CONFIG_PATH=$CONFIG_PATH
OXIDIZED_ROUTER_DB_PATH=$ROUTER_DB_PATH
EOF
chmod 600 "$ENV_FILE"

sudo tee /etc/systemd/system/oxidized-manager.service >/dev/null <<EOF
[Unit]
Description=Oxidized Config Manager
After=network-online.target
Wants=network-online.target
[Service]
User=$USER_NAME
Group=$GROUP_NAME
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$APP_DIR/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:5000 oxidized_config_manager:app
Restart=on-failure
RestartSec=5
PrivateTmp=true
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
EOF

sudo chown -R "$USER_NAME:$GROUP_NAME" "$APP_DIR" "$(dirname "$CONFIG_PATH")"
sudo systemctl daemon-reload
sudo systemctl enable --now oxidized-manager
sudo ufw allow 5000/tcp
sleep 2
sudo systemctl is-active --quiet oxidized-manager || { sudo journalctl -u oxidized-manager -b -n 50 --no-pager; die "Service failed."; }
sudo ss -ltn | grep -q ':5000 ' || die "Port 5000 is not listening."
info "Installed successfully at http://$(hostname -I | awk '{print $1}'):5000"
info "Save Config preserves !ruby/regexp for prompt and CSV delimiter."
