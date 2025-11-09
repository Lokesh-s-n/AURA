import os
import time
import json
import hashlib
import threading
from twilio.rest import Client


class FileIntegrityMonitor:
    """
    File Integrity & Configuration Drift Monitor for AURA
    ----------------------------------------------------
    - Creates a secure baseline of system files.
    - Detects file modifications, additions, or deletions.
    - Pushes drift events to the UI.
    - Sends WhatsApp alert via Twilio on drift detection.
    """

    def __init__(self, baseline_path="integrity_baseline.json",
                 watch_dirs=None, interval=60, alert_queue=None, max_files=None):
        self.baseline_path = baseline_path
        self.watch_dirs = watch_dirs or [r"C:/Users/Mailaralainga/Downloads/AURA-CYBER-THREAT-SYSTEM-main"]
        self.interval = interval
        self.alert_queue = alert_queue
        self.running = False
        self.lock = threading.Lock()
        self.max_files = max_files

        # --- Twilio Setup ---
        self.twilio_sid = os.getenv("TWILIO_SID") or "YOUR_SID"
        self.twilio_auth = os.getenv("TWILIO_AUTH") or "YOUR_AUTH_TOKEN"
        self.twilio_from = os.getenv("TWILIO_FROM") or "whatsapp:+14155238886"
        self.alert_to = os.getenv("ALERT_TO") or "whatsapp:+91XXXXXXXXXX"

        self.client = None
        try:
            self.client = Client(self.twilio_sid, self.twilio_auth)
            print("[INTEGRITY] Twilio WhatsApp alert system initialized.")
        except Exception as e:
            print(f"[INTEGRITY] ⚠️ Failed to initialize Twilio client: {e}")

        # --- Baseline load ---
        self.baseline = {}
        if os.path.exists(self.baseline_path):
            self._load_baseline()
        else:
            print("[INTEGRITY] Baseline not found — will create baseline automatically.")

    # ------------------------------------------------
    # Hashing helpers
    # ------------------------------------------------
    def _hash_file(self, path):
        try:
            with open(path, "rb") as f:
                h = hashlib.sha256()
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    # ------------------------------------------------
    # Baseline creation and management
    # ------------------------------------------------
    def create_baseline(self):
        print("[INTEGRITY] Creating baseline...")
        snapshot = {}
        count = 0
        for base in self.watch_dirs:
            if not os.path.exists(base):
                print(f"[INTEGRITY] ⚠️ Watch directory missing: {base}")
                continue
            for root, _, files in os.walk(base):
                for name in files:
                    path = os.path.join(root, name)
                    norm = os.path.normcase(os.path.abspath(path))
                    file_hash = self._hash_file(path)
                    if file_hash:
                        snapshot[norm] = file_hash
                    count += 1
                    if self.max_files and count >= self.max_files:
                        print(f"[INTEGRITY] Baseline capped at {self.max_files} files.")
                        break
                if self.max_files and count >= self.max_files:
                    break

        with open(self.baseline_path, "w") as f:
            json.dump(snapshot, f, indent=2)
        self.baseline = snapshot
        print(f"[INTEGRITY] Baseline created ({len(snapshot)} files).")

    def _load_baseline(self):
        try:
            with open(self.baseline_path, "r") as f:
                data = json.load(f)
            self.baseline = {os.path.normcase(k): v for k, v in data.items()}
            print(f"[INTEGRITY] Baseline loaded ({len(self.baseline)} files).")
        except Exception as e:
            print(f"[INTEGRITY] Failed to load baseline: {e}")

    # ------------------------------------------------
    # Drift detection logic
    # ------------------------------------------------
    def _scan_current(self):
        snapshot = {}
        count = 0
        for base in self.watch_dirs:
            if not os.path.exists(base):
                continue
            for root, _, files in os.walk(base):
                for name in files:
                    path = os.path.join(root, name)
                    norm = os.path.normcase(os.path.abspath(path))
                    h = self._hash_file(path)
                    if h:
                        snapshot[norm] = h
                    count += 1
                    if self.max_files and count >= self.max_files:
                        return snapshot
        return snapshot

    def detect_drift(self):
        with self.lock:
            current = self._scan_current()
            modified, removed, added = [], [], []

            for path, old_hash in self.baseline.items():
                new_hash = current.get(path)
                if new_hash is None:
                    removed.append(path)
                elif new_hash != old_hash:
                    modified.append(path)

            for path in current.keys():
                if path not in self.baseline:
                    added.append(path)

            if modified or removed or added:
                event = {
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "modified": modified,
                    "added": added,
                    "removed": removed,
                    "total_changes": len(modified) + len(added) + len(removed)
                }
                print(f"[INTEGRITY] ⚠️ Drift detected! Modified={len(modified)}, Added={len(added)}, Removed={len(removed)}")

                # Push to UI queue
                if self.alert_queue:
                    try:
                        self.alert_queue.put(event)
                    except Exception:
                        pass

                # Send WhatsApp Alert
                try:
                    if self.client:
                        changed_files = modified + added + removed
                        alert_msg = (
                            f"⚠️ *AURA ALERT: File Drift Detected!* ⚠️\n\n"
                            f"🧩 Modified: {len(modified)}\n"
                            f"➕ Added: {len(added)}\n"
                            f"❌ Removed: {len(removed)}\n"
                        )
                        if changed_files:
                            alert_msg += f"\nExample: {os.path.basename(changed_files[0])}"
                        self.client.messages.create(
                            body=alert_msg,
                            from_=self.twilio_from,
                            to=self.alert_to
                        )
                        print("[INTEGRITY] WhatsApp drift alert sent successfully.")
                except Exception as e:
                    print(f"[INTEGRITY] Failed to send WhatsApp alert: {e}")

                return event

            else:
                print("[INTEGRITY] No drift detected.")
                return None

    # ------------------------------------------------
    # Background monitor thread
    # ------------------------------------------------
    def start_monitoring(self, initial_delay=2):
        if self.running:
            return
        if not self.baseline:
            print("[INTEGRITY] No baseline found — creating one now.")
            self.create_baseline()

        self.running = True

        def _loop():
            time.sleep(initial_delay)
            while self.running:
                try:
                    self.detect_drift()
                except Exception as e:
                    print(f"[INTEGRITY] Error during detect_drift: {e}")
                time.sleep(self.interval)

        t = threading.Thread(target=_loop, daemon=True)
        t.start()
        print(f"[INTEGRITY] Background monitoring started (interval={self.interval}s).")

    def stop_monitoring(self):
        self.running = False
        print("[INTEGRITY] Monitoring stopped.")

    def force_scan(self):
        """Run detect_drift() once immediately."""
        return self.detect_drift()
