#!/bin/bash
# install.sh - GPSJOTS v13.0 - Secure Installer for Armbian 25.5.2
# This script self-destructs and reboots after installation. Run once per device.

set -euo pipefail
echo "🔐 GPSJOTS v13.0 - Secure Automotive Tracker Installer"
echo "⚠️  This script will self-destruct and reboot the system."

# === 1. Set Hostname ===
echo "jotstracker" > /etc/hostname
hostname jotstracker
groupadd gpio
grep -q "127.0.1.1" /etc/hosts && sed -i 's/127.0.1.1.*/127.0.1.1 jotstracker/' /etc/hosts
if ! grep -q "127.0.1.1 jotstracker" /etc/hosts; then
  echo "127.0.1.1 jotstracker" >> /etc/hosts
fi
echo "✅ Hostname set to: jotstracker"

# === 2. Detect Platform ===
PLATFORM="unknown"
if grep -qi "orange" /proc/device-tree/model; then PLATFORM="orangepi"
elif grep -qi "radxa" /proc/device-tree/model; then PLATFORM="radxa"
elif grep -qi "raspberry" /proc/device-tree/model; then PLATFORM="raspberrypi"; fi

if [ "$PLATFORM" = "unknown" ]; then
  echo "❌ Unsupported platform"
  exit 1
fi

# === 3. Create User ===
if ! id gpsjots &>/dev/null; then
  adduser --disabled-password --gecos "" gpsjots
  echo "gpsjots:gpsjots" | chpasswd
  usermod -aG gpio,sudo gpsjots
fi

# === 4. Create Directories ===
mkdir -p /opt/iotindonesia/gpsjots/{web,ota,firmware,data}
mkdir -p /var/log/gpsjots
chown -R gpsjots:gpsjots /opt/iotindonesia/gpsjots
chown -R gpsjots:gpsjots /var/log/gpsjots
ln -sf /var/log/gpsjots /opt/iotindonesia/gpsjots/logs 2>/dev/null || true

# === 5. Hardware Fingerprint (Serial + Model Only - No MAC) ===
SERIAL=$(grep Serial /proc/cpuinfo | cut -d':' -f2 | tr -d ' ' | head -1)
MODEL=$(cat /proc/device-tree/model 2>/dev/null || echo "unknown")
FINGERPRINT=$(echo -n "$SERIAL$MODEL" | sha256sum | cut -d' ' -f1)

echo "$FINGERPRINT" > /opt/iotindonesia/gpsjots/data/.device_id
chown gpsjots:gpsjots /opt/iotindonesia/gpsjots/data/.device_id
echo "🔐 Device locked to: ${FINGERPRINT:0:16}... (Serial + Model)"

# === 6. Install APT Packages (Safe System Packages) ===
apt update
apt install -y \
    python3-requests \
    python3-flask \
    python3-psutil \
    python3-serial \
    python3-rpi.gpio \
    python3-full \
    gpsd gpsd-clients \
    i2c-tools \
    sqlite3 \
    libgpiod2

# === 7. Create Virtual Environment for Missing Packages ===
python3 -m venv /opt/iotindonesia/gpsjots/venv
source /opt/iotindonesia/gpsjots/venv/bin/activate

# Upgrade pip
pip3 install --upgrade pip

# Install missing packages (not in APT)
pip3 install \
    requests \
    gpsd-py3 \
    pytz \
    schedule \
    adafruit-circuitpython-ads1x15 \
    flask \
    psutil

echo "✅ Python packages installed in virtual environment"

# === 8. Enable OverlayFS ===
echo 'overlay_prefix=armbian' >> /boot/armbianEnv.txt
echo 'rootoverlay=yes' >> /boot/armbianEnv.txt

# === 9. Bind Mount Data & Logs (Survive OverlayFS) ===
cat >> /etc/fstab << 'EOF'
/opt/iotindonesia/gpsjots/data /overlay/upper/opt/iotindonesia/gpsjots/data none bind,nofail 0 0
/var/log/gpsjots /overlay/upper/var/log/gpsjots none bind,nofail 0 0
EOF

# === 10. Configure GPSD (Now using /dev/ttyS0) ===
cat > /etc/default/gpsd << 'EOF'
START_DAEMON="true"
DEVICES="/dev/ttyS0"
USBAUTO="false"
EOF
systemctl enable gpsd

# === 11. config.json (GPS device = /dev/ttyS0) ===
cat > /opt/iotindonesia/gpsjots/data/config.json << 'EOF'
{
  "device": { "id": "vehicle_01", "name": "GPSJOTS Tracker" },
  "traccar": {
    "base_url": "http://iot.josuatristan.com",
    "email": "gpsjots@josuatristan.com",
    "password": "gpsjots",
    "upload_interval_min": 5,
    "geofence_sync_interval_min": 30
  },
  "gps": { "device": "/dev/ttyS0", "check_interval_sec": 30 },
  "storage": { "max_days": 5, "data_dir": "/opt/iotindonesia/gpsjots/data" },
  "alert": { "buzzer_gpio": 17, "beep_times": 2, "beep_delay": 0.3 },
  "ignition": { "gpio": 27, "active_high": true },
  "battery": { "adc_i2c_address": 72, "channel": 0, "voltage_divider_ratio": 0.333 },
  "shutdown": { "enabled": true, "delay_minutes": 5 },
  "hourmeter": {
    "enabled": true,
    "storage_file": "/opt/iotindonesia/gpsjots/data/hourmeter.txt",
    "alternator_adc_channel": 1,
    "voltage_threshold": 2.0,
    "last_value": 0.00
  },
  "web": { 
    "host": "0.0.0.0", 
    "port": 8080,
    "username": "gpsjots",
    "password": "gpsjots"
  },
  "ota": { "enabled": true, "url": "http://yourdomain.com/firmware/latest.py", "check_interval_min": 60 },
  "immobilizer": { 
    "enabled": true, 
    "relay_gpio": 18, 
    "active_low": true,
    "grace_period_sec": 60,
    "warning_beep_count": 3
  }
}
EOF

# === 12. Main Script (Obfuscated Name) ===
cat > /opt/iotindonesia/gpsjots/main.bin << 'EOF'
#!/usr/bin/env python3
import time, gpsd, requests, schedule, json, logging, os, sqlite3, subprocess
from datetime import datetime, timedelta
from threading import Thread
import hashlib

# === Anti-Copy Check: Serial + Model Only (No MAC) ===
def get_hardware_fingerprint():
    try:
        serial = subprocess.getoutput("grep Serial /proc/cpuinfo | cut -d':' -f2 | tr -d ' '").strip()
        model = subprocess.getoutput("cat /proc/device-tree/model 2>/dev/null || echo 'unknown'").strip()
        return hashlib.sha256(f"{serial}{model}".encode()).hexdigest()
    except Exception as e:
        logging.critical(f"Error generating fingerprint: {e}")
        return ""

def is_authorized():
    try:
        with open('/opt/iotindonesia/gpsjots/data/.device_id') as f:
            stored = f.read().strip()
        current = get_hardware_fingerprint()
        return stored == current
    except Exception as e:
        logging.critical(f"Auth error: {e}")
        return False

if not is_authorized():
    logging.critical("❌ Unauthorized device! This software is locked to one device.")
    exit(1)

# === Load Config ===
CONFIG_FILE = "/opt/iotindonesia/gpsjots/data/config.json"
with open(CONFIG_FILE) as f:
    cfg = json.load(f)

# === Logging ===
os.makedirs("/var/log/gpsjots", exist_ok=True)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler("/var/log/gpsjots/gpsjots.log"), logging.StreamHandler()])
logger = logging.getLogger()

# === GPIO & ADS1115 ===
try:
    import RPi.GPIO as GPIO
    GPIO.setmode(GPIO.BCM)
    GPIO.setwarnings(False)
except: pass

try:
    import board, busio
    from adafruit_ads1x15.ads1115 import ADS1115
    from adafruit_ads1x15.analog_in import AnalogIn
    i2c = busio.I2C(board.SCL, board.SDA)
    ads = ADS1115(i2c, address=cfg['battery']['adc_i2c_address'])
    batt_chan = AnalogIn(ads, getattr(AnalogIn, f"P{cfg['battery']['channel']}"))
    alt_chan = AnalogIn(ads, getattr(AnalogIn, f"P{cfg['hourmeter']['alternator_adc_channel']}"))
except Exception as e:
    logger.error(f"ADC error: {e}")

# === DB Init ===
DB = f"{cfg['storage']['data_dir']}/positions.db"
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS positions (
        id INTEGER PRIMARY KEY, lat REAL, lon REAL, alt REAL, speed REAL,
        time TEXT, ignition INT, battery REAL, hourmeter REAL, uploaded INT
    )''')
    conn.commit(); conn.close()
init_db()

# === Battery Read ===
def read_battery():
    try:
        return batt_chan.voltage / cfg['battery']['voltage_divider_ratio']
    except: return 12.0

# === Ignition ===
def is_ignition():
    try:
        pin = cfg['ignition']['gpio']
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_DOWN)
        return bool(GPIO.input(pin)) == cfg['ignition']['active_high']
    except: return False

# === Beep Patterns ===
def beep_warning():
    pin = cfg['alert']['buzzer_gpio']
    GPIO.setup(pin, GPIO.OUT)
    for _ in range(cfg['immobilizer']['warning_beep_count']):
        GPIO.output(pin, GPIO.HIGH)
        time.sleep(2.0)
        GPIO.output(pin, GPIO.LOW)
        time.sleep(1.0)

def beep_alert():
    pin = cfg['alert']['buzzer_gpio']
    GPIO.setup(pin, GPIO.OUT)
    for _ in range(3):
        GPIO.output(pin, GPIO.HIGH)
        time.sleep(0.3)
        GPIO.output(pin, GPIO.LOW)
        time.sleep(0.3)

# === Hour Meter ===
def read_hm():
    try:
        with open(cfg['hourmeter']['storage_file'], 'r') as f:
            return float(f.read().strip())
    except:
        return cfg['hourmeter']['last_value']

def save_hm(value):
    with open(cfg['hourmeter']['storage_file'], 'w') as f:
        f.write(f"{value:.2f}")

engine_running = False
start_time = None
current_hm = read_hm()

def update_hourmeter():
    global engine_running, start_time, current_hm
    try:
        voltage = alt_chan.voltage
        now_running = voltage > cfg['hourmeter']['voltage_threshold']

        if now_running and not engine_running:
            start_time = time.time()
            engine_running = True
            logger.info(f"⏱️  Engine ON – HM: {current_hm:.2f} h")

        elif not now_running and engine_running:
            elapsed = time.time() - start_time
            hours = elapsed / 3600.0
            current_hm += hours
            save_hm(current_hm)
            engine_running = False
            logger.info(f"⏸️  Engine OFF – +{hours:.2f}h, Total: {current_hm:.2f}h")

    except Exception as e:
        logger.error(f"HM error: {e}")

# === Maintenance Mode Check ===
def is_maintenance():
    return os.path.exists('/opt/iotindonesia/gpsjots/data/.maintenance_mode')

# === Auto-Shutdown ===
def monitor_shutdown():
    while True:
        try:
            if not is_maintenance() and cfg['shutdown']['enabled']:
                if not is_ignition():
                    logger.info("🛑 Ignition OFF detected")
                    time.sleep(cfg['shutdown']['delay_minutes'] * 60)
                    if not is_ignition():
                        logger.info("🖥️ Shutting down...")
                        os.system("sudo poweroff")
        except Exception as e:
            logger.error(f"Shutdown monitor: {e}")
        time.sleep(5)

# === Immobilization System ===
immobilize_pending = False
immobilize_start_time = None

def activate_immobilizer():
    pin = cfg['immobilizer']['relay_gpio']
    active_low = cfg['immobilizer']['active_low']
    GPIO.setup(pin, GPIO.OUT)
    GPIO.output(pin, 0 if active_low else 1)
    logger.warning("🛑 ENGINE CUT – Vehicle immobilized")
    beep_alert()

def handle_immobilization():
    global immobilize_pending, immobilize_start_time
    
    if os.path.exists('/opt/iotindonesia/gpsjots/data/.immobilize_request') and not immobilize_pending:
        logger.warning("⚠️ Remote immobilization REQUESTED – Starting safety grace period")
        beep_warning()
        immobilize_pending = True
        immobilize_start_time = time.time()
        return
    
    if immobilize_pending:
        elapsed = time.time() - immobilize_start_time
        
        if not is_ignition():
            logger.info("✅ Vehicle stopped – Immobilization canceled")
            immobilize_pending = False
            os.remove('/opt/iotindonesia/gpsjots/data/.immobilize_request')
            return
        
        if elapsed >= cfg['immobilizer']['grace_period_sec']:
            logger.warning(f"🛑 Grace period ended ({cfg['immobilizer']['grace_period_sec']}s) – Activating immobilizer")
            activate_immobilizer()
            immobilize_pending = False

# === GPS Collect ===
def collect():
    try:
        packet = gpsd.get_current()
        if packet.mode >= 2:
            lat, lon, speed = packet.lat, packet.lon, packet.hspeed
            battery = read_battery()
            ignition = is_ignition()
            conn = sqlite3.connect(DB)
            c = conn.cursor()
            c.execute('''INSERT INTO positions (lat,lon,speed,time,ignition,battery,hourmeter,uploaded)
                         VALUES (?,?,?,?,?,?,?,0)''', (lat, lon, speed, packet.time, ignition, battery, current_hm))
            conn.commit(); conn.close()
            logger.info(f"Logged: {lat:.6f},{lon:.6f} | Speed: {speed*3.6:.1f} | Batt: {battery:.2f}V | HM: {current_hm:.2f}h")
    except Exception as e:
        logger.error(f"GPS error: {e}")

# === Web & OTA ===
def start_web():
    try:
        subprocess.Popen(["python3", "/opt/iotindonesia/gpsjots/web/app.py"])
    except Exception as e:
        logger.error(f"Web failed: {e}")

# === Main ===
gpsd.connect()
schedule.every(cfg['gps']['check_interval_sec']).seconds.do(collect)
schedule.every(1).seconds.do(update_hourmeter)
schedule.every(5).seconds.do(handle_immobilization)
schedule.every(5).seconds.do(monitor_shutdown)
schedule.every(cfg['traccar']['upload_interval_min']*60).seconds.do(lambda: logger.info("Uploading..."))
schedule.every(cfg['ota']['check_interval_min']*60).seconds.do(lambda: logger.info("Checking OTA..."))

Thread(target=start_web, daemon=True).start()
logger.info("🚀 GPSJOTS v13.0 Running")

while True:
    schedule.run_pending()
    time.sleep(1)
EOF

# === 13. Web App ===
mkdir -p /opt/iotindonesia/gpsjots/web
cat > /opt/iotindonesia/gpsjots/web/app.py << 'EOF'
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, Response
import json
import os
import subprocess
import sqlite3
from datetime import datetime

app = Flask(__name__)
app.secret_key = "gpsjots_secure_key_2025_v13"

USERNAME = "gpsjots"
PASSWORD = "gpsjots"

CONFIG_FILE = "/opt/iotindonesia/gpsjots/data/config.json"
MAINT_FILE = "/opt/iotindonesia/gpsjots/data/.maintenance_mode"
IMMO_REQUEST = "/opt/iotindonesia/gpsjots/data/.immobilize_request"
DB_PATH = os.path.join(json.load(open(CONFIG_FILE))['storage']['data_dir'], 'positions.db')

def login_required(f):
    def decorated(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == USERNAME and password == PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

@app.route('/')
@login_required
def dashboard():
    try:
        with open(CONFIG_FILE) as f:
            config = json.load(f)
    except:
        config = {}

    status = {
        "maintenance_active": os.path.exists(MAINT_FILE),
        "immobilize_pending": os.path.exists(IMMO_REQUEST),
        "current_hm": read_current_hourmeter()
    }
    return render_template('dashboard.html', config=config, status=status)

def read_current_hourmeter():
    try:
        config = json.load(open(CONFIG_FILE))
        hm_file = config['hourmeter']['storage_file']
        with open(hm_file, 'r') as f:
            return float(f.read().strip())
    except:
        return 0.0

@app.route('/save_config', methods=['POST'])
@login_required
def save_config():
    try:
        new_config = request.json
        subprocess.run(["cp", CONFIG_FILE, CONFIG_FILE + ".backup"], stderr=subprocess.DEVNULL)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(new_config, f, indent=2)
        os.system('logger -t gpsjots "🔧 Config updated via web"')
        return jsonify(status="saved")
    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route('/apply_config', methods=['POST'])
@login_required
def apply_config():
    os.system('logger -t gpsjots "🔄 Config applied: restarting gpsjots"')
    subprocess.run(["sudo", "systemctl", "restart", "gpsjots"])
    return jsonify(status="restarted")

@app.route('/maintenance', methods=['POST'])
@login_required
def maintenance():
    action = request.json.get('action')
    if action == 'enable':
        open(MAINT_FILE, 'w').write('active')
        os.system('logger -t gpsjots "🔧 MAINTENANCE MODE ENABLED"')
        os.system('python3 -c "import os; os.system(\'beep -f 1000 -l 200 & beep -f 1000 -l 200\')"')
        return jsonify(status="Maintenance ON")
    elif action == 'disable':
        if os.path.exists(MAINT_FILE):
            os.remove(MAINT_FILE)
        os.system('logger -t gpsjots "🔧 MAINTENANCE MODE DISABLED"')
        return jsonify(status="Maintenance OFF")
    return jsonify(error="Invalid action"), 400

@app.route('/reset_immobilize', methods=['POST'])
@login_required
def reset_immobilize():
    if os.path.exists(IMMO_REQUEST):
        os.remove(IMMO_REQUEST)
        os.system('logger -t gpsjots "🔄 Immobilization request reset"')
        return jsonify(status="Immobilization reset")
    return jsonify(status="No request found")

@app.route('/generate_report')
@login_required
def generate_report():
    days = request.args.get('days', default=30, type=int)
    days = max(1, min(365, days))
    
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            SELECT date(time), MIN(hourmeter), MAX(hourmeter)
            FROM positions
            WHERE hourmeter IS NOT NULL
            AND date(time) >= date('now', ? || ' days')
            GROUP BY date(time)
            ORDER BY date(time) DESC
        """, (f"-{days}",))
        
        rows = c.fetchall()
        conn.close()
        
        csv = "Date,Start HM,End HM,Total Hours\n"
        total = 0.0
        
        for date, start, end in rows:
            if start is None or end is None:
                continue
            daily = round(end - start, 2)
            total += daily
            csv += f"{date},{start:.2f},{end:.2f},{daily:.2f}\n"
        
        if rows:
            csv += f"\nTotal Period Hours,{total:.2f}"
        
        return Response(
            csv,
            mimetype="text/csv",
            headers={"Content-disposition": f"attachment; filename=hour_meter_{datetime.now().strftime('%Y%m%d')}.csv"}
        )
    except Exception as e:
        app.logger.error(f"Report generation failed: {e}")
        return jsonify(error="Failed to generate report"), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
EOF

# === 14. Web Templates ===
mkdir -p /opt/iotindonesia/gpsjots/web/templates
cat > /opt/iotindonesia/gpsjots/web/templates/login.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
  <title>GPSJOTS Login</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light d-flex align-items-center" style="height: 100vh;">
  <div class="container">
    <div class="row justify-content-center">
      <div class="col-md-4">
        <div class="card">
          <div class="card-header text-center">
            <h5>🔐 GPSJOTS Login</h5>
          </div>
          <div class="card-body">
            {% if error %}
              <div class="alert alert-danger">{{ error }}</div>
            {% endif %}
            <form method="post">
              <div class="mb-3">
                <label>Username</label>
                <input type="text" name="username" class="form-control" required>
              </div>
              <div class="mb-3">
                <label>Password</label>
                <input type="password" name="password" class="form-control" required>
              </div>
              <button type="submit" class="btn btn-primary w-100">Login</button>
            </form>
          </div>
        </div>
      </div>
    </div>
  </div>
</body>
</html>
EOF

cat > /opt/iotindonesia/gpsjots/web/templates/dashboard.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
  <title>GPSJOTS Control</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    .config-section { margin-bottom: 2rem; padding-bottom: 1.5rem; border-bottom: 1px solid #eee; }
    .form-label { font-weight: bold; }
  </style>
</head>
<body class="p-4">
  <div class="d-flex justify-content-between align-items-center mb-4">
    <h2>GPSJOTS Web Control Panel</h2>
    <a href="/logout" class="btn btn-outline-danger">Logout</a>
  </div>

  <!-- Current Status -->
  <div class="row mb-4">
    <div class="col-md-4">
      <div class="card">
        <div class="card-body">
          <h5 class="card-title">Current Hour Meter</h5>
          <p class="card-text display-4" id="current-hm">Loading...</p>
        </div>
      </div>
    </div>
    <div class="col-md-4">
      <div class="card">
        <div class="card-body">
          <h5 class="card-title">Maintenance Mode</h5>
          <p class="card-text h4" id="maint-status">Checking...</p>
          <div>
            <button id="enable-maint" class="btn btn-warning">Enable</button>
            <button id="disable-maint" class="btn btn-secondary">Disable</button>
          </div>
        </div>
      </div>
    </div>
    <div class="col-md-4">
      <div class="card">
        <div class="card-body">
          <h5 class="card-title">Immobilization</h5>
          <p class="card-text h4" id="immobilize-status">Checking...</p>
          <button id="reset-immobilize" class="btn btn-danger">Reset Request</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Hour Meter Report -->
  <div class="card mb-4 config-section">
    <div class="card-body">
      <h3>📊 Hour Meter Report</h3>
      <div class="row mb-3">
        <div class="col-md-6">
          <label class="form-label">Days to Include</label>
          <input type="number" id="report-days" class="form-control" value="30" min="1" max="365">
        </div>
      </div>
      <button id="generate-report" class="btn btn-primary">Generate CSV Report</button>
      <a id="download-link" class="btn btn-success mt-3" style="display:none">Download CSV</a>
    </div>
  </div>

  <!-- Configuration -->
  <div class="card mb-4 config-section">
    <div class="card-body">
      <h3>⚙️ Configuration</h3>
      <div id="config-form">
        <!-- Form will be populated dynamically -->
      </div>
      <div class="mt-3">
        <button id="save-config" class="btn btn-success">💾 Save Config</button>
        <button id="apply-config" class="btn btn-danger">🔁 Apply & Restart</button>
      </div>
    </div>
  </div>

  <!-- System Info -->
  <div class="card">
    <div class="card-body">
      <h3>ℹ️ System Information</h3>
      <p>GPSJOTS v13.0 • Anti-Copy Protected • OverlayFS Enabled</p>
    </div>
  </div>

</body>
<script>
// Helper functions
function setDeep(obj, path, value) {
  path.split('.').slice(0,-1).reduce((a, k) => a[k] = a[k] || {}, obj)[path.split('.').pop()] = value;
}

function getDeep(obj, path) {
  return path.split('.').reduce((o, i) => o?.[i], obj);
}

function updateStatus() {
  fetch('/')
    .then(r => r.json())
    .then(data => {
      // Update status displays
      document.getElementById('current-hm').textContent = data.status.current_hm.toFixed(2) + ' h';
      document.getElementById('maint-status').textContent = data.status.maintenance_active ? 'ACTIVE' : 'OFF';
      document.getElementById('immobilize-status').textContent = data.status.immobilize_pending ? 'PENDING' : 'CLEAN';
      
      // Update config form
      renderConfigForm(data.config);
    })
    .catch(e => console.error('Status update failed:', e));
}

function renderConfigForm(config) {
  const container = document.getElementById('config-form');
  container.innerHTML = '';
  
  // Device section
  addSection(container, 'Device Settings', [
    {key: 'device.id', label: 'Device ID', type: 'text', value: config.device?.id},
    {key: 'device.name', label: 'Device Name', type: 'text', value: config.device?.name}
  ]);
  
  // Traccar section
  addSection(container, 'Traccar Settings', [
    {key: 'traccar.base_url', label: 'Base URL', type: 'text', value: config.traccar?.base_url},
    {key: 'traccar.email', label: 'Email', type: 'text', value: config.traccar?.email},
    {key: 'traccar.password', label: 'Password', type: 'password', value: config.traccar?.password},
    {key: 'traccar.upload_interval_min', label: 'Upload Interval (min)', type: 'number', value: config.traccar?.upload_interval_min}
  ]);
  
  // GPS section
  addSection(container, 'GPS Settings', [
    {key: 'gps.device', label: 'GPS Device', type: 'text', value: config.gps?.device},
    {key: 'gps.check_interval_sec', label: 'Check Interval (sec)', type: 'number', value: config.gps?.check_interval_sec}
  ]);
  
  // Hour Meter section
  addSection(container, 'Hour Meter Settings', [
    {key: 'hourmeter.alternator_adc_channel', label: 'ADC Channel', type: 'number', value: config.hourmeter?.alternator_adc_channel},
    {key: 'hourmeter.voltage_threshold', label: 'Voltage Threshold', type: 'number', step: '0.1', value: config.hourmeter?.voltage_threshold}
  ]);
  
  // Immobilizer section
  addSection(container, 'Immobilizer Settings', [
    {key: 'immobilizer.grace_period_sec', label: 'Grace Period (sec)', type: 'number', value: config.immobilizer?.grace_period_sec},
    {key: 'immobilizer.warning_beep_count', label: 'Warning Beep Count', type: 'number', value: config.immobilizer?.warning_beep_count}
  ]);
}

function addSection(container, title, fields) {
  const section = document.createElement('div');
  section.className = 'mb-4';
  
  const h4 = document.createElement('h4');
  h4.textContent = title;
  h4.className = 'mb-3';
  section.appendChild(h4);
  
  const row = document.createElement('div');
  row.className = 'row';
  
  fields.forEach(field => {
    const col = document.createElement('div');
    col.className = 'col-md-6 mb-3';
    
    const label = document.createElement('label');
    label.className = 'form-label';
    label.textContent = field.label;
    col.appendChild(label);
    
    const input = document.createElement('input');
    input.type = field.type || 'text';
    input.className = 'form-control';
    input.dataset.key = field.key;
    input.value = field.value || '';
    if (field.step) input.step = field.step;
    
    col.appendChild(input);
    row.appendChild(col);
  });
  
  section.appendChild(row);
  container.appendChild(section);
}

// Event handlers
document.getElementById('enable-maint').onclick = () => {
  fetch('/maintenance', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({action:'enable'})})
  .then(() => updateStatus());
};

document.getElementById('disable-maint').onclick = () => {
  fetch('/maintenance', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({action:'disable'})})
  .then(() => updateStatus());
};

document.getElementById('reset-immobilize').onclick = () => {
  fetch('/reset_immobilize', {method:'POST'})
  .then(() => updateStatus());
};

document.getElementById('save-config').onclick = () => {
  const config = {};
  document.querySelectorAll('[data-key]').forEach(el => {
    setDeep(config, el.dataset.key, el.type === 'checkbox' ? el.checked : el.value);
  });
  fetch('/save_config', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config)
  }).then(r => {
    if (r.ok) alert('Config saved! Changes will take effect after restart.');
    else alert('Failed to save config');
  });
};

document.getElementById('apply-config').onclick = () => {
  if (confirm('Restart service to apply changes? This will temporarily stop tracking.')) {
    fetch('/apply_config', { method: 'POST' })
    .then(() => {
      alert('Service restarting... You will be logged out.');
      setTimeout(() => window.location.reload(), 2000);
    });
  }
};

// Report generation
document.getElementById('generate-report').onclick = () => {
  const days = document.getElementById('report-days').value;
  fetch(`/generate_report?days=${days}`)
  .then(r => r.text())
  .then(csv => {
    const blob = new Blob([csv], {type: 'text/csv'});
    const url = URL.createObjectURL(blob);
    const a = document.getElementById('download-link');
    a.href = url;
    a.download = `hour_meter_report_${new Date().toISOString().slice(0,10)}.csv`;
    a.style.display = 'inline-block';
    a.onclick = () => URL.revokeObjectURL(url);
  })
  .catch(e => {
    console.error('Report failed:', e);
    alert('Failed to generate report');
  });
};

// Initial load
updateStatus();
setInterval(updateStatus, 30000); // Update every 30 seconds
</script>
</html>
EOF

# === 15. Systemd Service ===
cat > /etc/systemd/system/gpsjots.service << 'EOF'
[Unit]
Description=GPSJOTS Secure Tracker
After=network.target

[Service]
Type=simple
User=gpsjots
Group=gpsjots
WorkingDirectory=/opt/iotindonesia/gpsjots
ExecStart=/opt/iotindonesia/gpsjots/venv/bin/python main.bin
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# === 16. Passwordless Restart for Web UI ===
echo "gpsjots ALL=(ALL) NOPASSWD: /bin/systemctl restart gpsjots" | sudo tee /etc/sudoers.d/gpsjots

# === 17. Final Setup ===
systemctl daemon-reload
systemctl enable gpsjots gpsd
systemctl start gpsjots

# === 18. Harden & Self-Destruct + Reboot ===
chown -R gpsjots:gpsjots /opt/iotindonesia/gpsjots
chmod -R 700 /opt/iotindonesia/gpsjots
find /opt/iotindonesia/gpsjots -name "*.py" -exec chmod +x {} \;
chmod +x /opt/iotindonesia/gpsjots/main.bin

echo "✅ Installation Complete!"
echo "🌐 Web UI: http://jotstracker.local:8080 or http://$(hostname -I | awk '{print $1}'):8080"
echo "🔧 Login: gpsjots / gpsjots"
echo "🔐 This installer will now self-destruct and reboot the system."
rm -- "$0" && reboot
