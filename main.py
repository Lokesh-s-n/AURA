import os
import threading
import signal
import sys
import json
from queue import Queue
from flask import Flask, jsonify, render_template, request
from scapy.all import sniff, IP
import time

# --- Geofence import (your file) ---
from geofence import GeoFencing, safe_check_geofence

# --- Other services (match your codebase filenames) ---
from anomaly_detection_service import BehavioralAnomalyDetector
from threat_intel_service import ThreatIntel
from firewall_manager import FirewallManager
from geolocation_service import GeoLocator
from integrity_monitor import FileIntegrityMonitor
from honeypot_manager import HoneypotManager

# --------------------------
# Configuration (env / defaults)
# --------------------------
GEO_CONFIG_FILE = os.path.join(os.getcwd(), "geofence_config.json")
GEO_UNKNOWN_ACTION = os.getenv("GEO_UNKNOWN_ACTION", "alert").lower()

# Default geofence values (used if no config file)
DEFAULT_CENTER_LAT = 17.3850
DEFAULT_CENTER_LON = 78.4867
DEFAULT_RADIUS_KM = 50.0

# --------------------------
# Helper to load/save geofence config
# --------------------------
def load_geofence_config():
    if os.path.exists(GEO_CONFIG_FILE):
        try:
            with open(GEO_CONFIG_FILE, "r") as f:
                data = json.load(f)
            lat = float(data.get("center_lat", DEFAULT_CENTER_LAT))
            lon = float(data.get("center_lon", DEFAULT_CENTER_LON))
            radius = float(data.get("radius_km", DEFAULT_RADIUS_KM))
            return {"center_lat": lat, "center_lon": lon, "radius_km": radius}
        except Exception:
            pass
    return {"center_lat": DEFAULT_CENTER_LAT, "center_lon": DEFAULT_CENTER_LON, "radius_km": DEFAULT_RADIUS_KM}

def save_geofence_config(cfg):
    try:
        with open(GEO_CONFIG_FILE, "w") as f:
            json.dump({
                "center_lat": float(cfg.get("center_lat", DEFAULT_CENTER_LAT)),
                "center_lon": float(cfg.get("center_lon", DEFAULT_CENTER_LON)),
                "radius_km": float(cfg.get("radius_km", DEFAULT_RADIUS_KM))
            }, f, indent=2)
        return True
    except Exception as e:
        print("[GEO] Failed to save config:", e)
        return False

# --------------------------
# Queues for UI
# --------------------------
traffic_data_queue = Queue()
integrity_queue = Queue()
honeypot_queue = Queue()

# --------------------------
# Flask app
# --------------------------
app = Flask(__name__, template_folder='templates', static_folder='static')

# --------------------------
# Initialize components
# --------------------------
detector = BehavioralAnomalyDetector()
intel = ThreatIntel()
firewall = FirewallManager()
# Load persisted geofence config (or defaults)
cfg = load_geofence_config()
geofence = GeoFencing(center_lat=cfg["center_lat"], center_lon=cfg["center_lon"], radius_km=cfg["radius_km"])
geolocator = GeoLocator()  # MaxMind reader wrapper
honeypot = HoneypotManager(ui_queue=honeypot_queue)

# File integrity monitor settings (adjust watch_dirs to your environment)
WATCH_DIRS = [os.path.join(os.getcwd())]  # safer default to project dir; change if required
integrity_monitor = FileIntegrityMonitor(
    baseline_path=os.path.join(os.getcwd(), "integrity_baseline.json"),
    watch_dirs=WATCH_DIRS,
    interval=30,
    alert_queue=integrity_queue,
    max_files=20000
)
integrity_monitor.start_monitoring(initial_delay=1)

# --------------------------
# Packet Sniffer Logic
# --------------------------
stop_sniffer = threading.Event()

def process_packet(packet):
    if not packet.haslayer(IP):
        return
    src, dst = packet[IP].src, packet[IP].dst

    try:
        if geolocator._is_private_ip(src) and geolocator._is_private_ip(dst):
            return
    except Exception:
        pass

    external_ip = dst if geolocator._is_private_ip(src) else src

    intel_score = intel.check_ip_reputation(external_ip)
    behavior_score = detector.calculate_threat_score(external_ip)
    final_score = min(1.0, round(float(intel_score) + float(behavior_score), 2))

    location = None
    try:
        location = geolocator.get_location(external_ip)
    except Exception:
        location = None

    location_unknown = (location is None) or (location.get('latitude') is None) or (location.get('longitude') is None)
    geofence_violation = location_unknown  # per your rule: unknown-area => violation

    try:
        if geofence_violation:
            if GEO_UNKNOWN_ACTION == "block":
                firewall.block_ip(external_ip)
            elif GEO_UNKNOWN_ACTION == "honeypot":
                try:
                    honeypot.start_honeypot_for(external_ip, target_port=22)
                except Exception as e:
                    print(f"[HONEYPOT] Error starting honeypot for {external_ip}: {e}")
    except Exception as e:
        print(f"[AURA] Error performing GEO_UNKNOWN_ACTION for {external_ip}: {e}")

    try:
        if final_score >= 0.6:
            firewall.block_ip(external_ip)
    except Exception as e:
        print(f"[FIREWALL] Error blocking {external_ip}: {e}")

    if final_score >= 0.9:
        try:
            honeypot.start_honeypot_for(external_ip, target_port=22)
            print(f"[AURA] {src} → {dst} | Score={final_score} | HONEYPOT")
        except Exception as e:
            print(f"[HONEYPOT] Error starting honeypot for {external_ip}: {e}")
    else:
        print(f"[AURA] {src} → {dst} | Score={final_score} | {'BLOCKED' if final_score>=0.6 else 'OK'}")

    if location:
        country = location.get("country", "Unknown")
        lat = location.get("latitude")
        lon = location.get("longitude")
    else:
        country = "Unknown"
        lat = None
        lon = None

    try:
        traffic_data_queue.put({
            "src_ip": src,
            "dst_ip": dst,
            "external_ip": external_ip,
            "score": final_score,
            "country": country,
            "lat": lat,
            "lon": lon,
            "blocked": final_score >= 0.6,
            "honeypot": final_score >= 0.9,
            "location_unknown": location_unknown,
            "geofence_violation": geofence_violation
        })
    except Exception:
        pass

def start_sniffer():
    print("🔍 Starting live packet capture...")
    sniff(prn=process_packet, store=False, stop_filter=lambda pkt: stop_sniffer.is_set())

sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
sniffer_thread.start()

# --------------------------
# Flask Routes
# --------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/traffic')
def traffic():
    data = []
    while not traffic_data_queue.empty():
        data.append(traffic_data_queue.get())
    return jsonify(data)

@app.route('/status')
def status():
    return jsonify(detector.get_status())

@app.route('/blocked')
def blocked():
    return jsonify(firewall.list_blocked_ips())

@app.route('/integrity')
def integrity():
    events = []
    while not integrity_queue.empty():
        events.append(integrity_queue.get())
    return jsonify(events)

@app.route("/honeypots")
def list_honeypots():
    active = honeypot.list_active()
    result = []
    for key, info in active.items():
        result.append({
            "attacker_ip": info["attacker_ip"],
            "target_port": info["target_port"],
            "local_port": info["local_port"],
            "started_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(info["start_time"])),
            "log_count": info["log_count"]
        })
    return jsonify(result)

@app.route("/honeypot_logs")
def get_honeypot_logs():
    logs = []
    active = honeypot.list_active()
    for (key, info) in active.items():
        ip = info["attacker_ip"]
        tp = info["target_port"]
        logs.extend(honeypot.get_logs_for(ip, tp, limit=50))
    return jsonify(logs)

# GET existing config (already present)
@app.route('/geofence_config', methods=['GET'])
def geofence_config_get():
    return jsonify({
        "center_lat": geofence.center_lat,
        "center_lon": geofence.center_lon,
        "radius_km": geofence.radius_km,
        "geo_unknown_action": GEO_UNKNOWN_ACTION
    })

# POST to update geofence config (new)
@app.route('/geofence_config', methods=['POST'])
def geofence_config_post():
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"status":"error","message":"No JSON payload"}), 400

        # Validate and coerce
        lat = float(data.get("center_lat", geofence.center_lat))
        lon = float(data.get("center_lon", geofence.center_lon))
        radius = float(data.get("radius_km", geofence.radius_km))

        # Basic sanity checks
        if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
            return jsonify({"status":"error","message":"Invalid lat/lon range"}), 400
        if radius < 0 or radius > 20000:
            return jsonify({"status":"error","message":"Invalid radius"}), 400

        # Update runtime geofence
        geofence.center_lat = lat
        geofence.center_lon = lon
        geofence.radius_km = radius

        # Persist config
        ok = save_geofence_config({"center_lat": lat, "center_lon": lon, "radius_km": radius})
        if not ok:
            return jsonify({"status":"error","message":"Failed to save config"}), 500

        return jsonify({"status":"ok","center_lat":lat,"center_lon":lon,"radius_km":radius})
    except Exception as e:
        print("[GEO] POST error:", e)
        return jsonify({"status":"error","message":"Exception occurred"}), 500

@app.route('/force_integrity')
def force_integrity():
    event = integrity_monitor.force_scan()
    if event:
        return jsonify({"status": "changed", "event": event})
    else:
        return jsonify({"status": "ok", "event": None})

# --------------------------
# Graceful Shutdown
# --------------------------
def shutdown_handler(sig, frame):
    print("\n[ AURA ] Shutting down...")
    stop_sniffer.set()
    integrity_monitor.stop_monitoring()
    honeypot.stop_all()
    sys.exit(0)

signal.signal(signal.SIGINT, shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)

# --------------------------
# Start app
# --------------------------
if __name__ == "__main__":
    print("✅ System initialized successfully.")
    print("🌍 Web UI: http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
