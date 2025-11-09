# honeypot_manager.py
import socket
import threading
import time
import ipaddress
from queue import Queue, Empty

# Configurable limits
MAX_ACTIVE_HONEYPOTS = 100
CAPTURE_BYTES = 4096
SERVER_BACKLOG = 5
ACCEPT_TIMEOUT = 1.0  # seconds

class HoneypotManager:
    """
    Robust honeypot manager:
    - start_honeypot_for(attacker_ip, target_port=22)
    - stop_honeypot_for(attacker_ip, target_port=22)
    - list_active() -> { "attacker_ip:target_port": {meta...} }
    - get_logs_for(attacker_ip, target_port, limit=100)
    - stop_all()
    """

    def __init__(self, ui_queue: Queue = None, max_active=MAX_ACTIVE_HONEYPOTS):
        self.ui_queue = ui_queue
        self.max_active = max_active
        self._lock = threading.Lock()
        # key: (attacker_ip, target_port) -> info dict
        self._active = {}
        print("[HONEYPOT] HoneypotManager initialized.")

    # -------------------------
    # Helpers
    # -------------------------
    def _is_unsuitable_target(self, ip):
        """Return True if we should not create honeypot for this ip."""
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback:
                return True
            # multicast (224.0.0.0/4) and broadcast-like addresses are unsuitable
            if addr.is_multicast:
                return True
            return False
        except ValueError:
            return True

    def _alloc_local_port(self):
        """Bind to port 0 to get a free ephemeral port and return it (socket closed)."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        _, port = s.getsockname()
        s.close()
        return port

    # -------------------------
    # Honeypot server thread
    # -------------------------
    def _honeypot_server(self, attacker_ip, target_port, local_port, running_flag):
        server_socket = None
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(("127.0.0.1", local_port))
            server_socket.listen(SERVER_BACKLOG)
            server_socket.settimeout(ACCEPT_TIMEOUT)
            print(f"[HONEYPOT] Server started on 127.0.0.1:{local_port} for {attacker_ip}:{target_port}")

            while running_flag['run']:
                try:
                    client_socket, addr = server_socket.accept()
                except socket.timeout:
                    continue
                except OSError as e:
                    # socket has been closed externally
                    break

                # handle connection in short-lived context
                try:
                    client_socket.settimeout(1.0)
                    try:
                        data = client_socket.recv(CAPTURE_BYTES)
                    except (ConnectionResetError, OSError):
                        data = b""
                    text = data.decode(errors='ignore').strip() if data else ""
                    ts = time.strftime("%Y-%m-%d %H:%M:%S")
                    # record into manager store
                    key = (attacker_ip, target_port)
                    with self._lock:
                        entry = self._active.get(key)
                        if entry:
                            entry['logs'].append({
                                "timestamp": ts,
                                "data": text,
                                "attacker_ip": attacker_ip,
                                "target_port": target_port,
                                "local_port": local_port,
                                "remote_addr": addr
                            })
                            # trim logs to reasonable size
                            if len(entry['logs']) > 500:
                                entry['logs'] = entry['logs'][-500:]
                    # optionally push to UI queue
                    if self.ui_queue:
                        try:
                            self.ui_queue.put({
                                "attacker_ip": attacker_ip,
                                "target_port": target_port,
                                "local_port": local_port,
                                "data": text,
                                "timestamp": ts
                            })
                        except Exception:
                            pass
                    # simulate a fake response so test clients get immediate close
                    try:
                        client_socket.sendall(b"220 AURA honeypot - connection logged\r\n")
                    except Exception:
                        pass
                finally:
                    try:
                        client_socket.close()
                    except Exception:
                        pass

        except Exception as e:
            print(f"[HONEYPOT] Error in server for {attacker_ip}:{target_port}: {e}")
        finally:
            try:
                if server_socket:
                    server_socket.close()
            except Exception:
                pass
            print(f"[HONEYPOT] Server on 127.0.0.1:{local_port} stopped for {attacker_ip}:{target_port}")
            # mark not running and remove from active map (best-effort)
            with self._lock:
                self._active.pop((attacker_ip, target_port), None)

    # -------------------------
    # Public API
    # -------------------------
    def start_honeypot_for(self, attacker_ip, target_port=22):
        """
        Start a honeypot redirect for given attacker ip and target_port.
        Will no-op if unsuitable or already active.
        """
        if self._is_unsuitable_target(attacker_ip):
            print(f"[HONEYPOT] Skipping unsuitable target: {attacker_ip}")
            return None

        with self._lock:
            if len(self._active) >= self.max_active:
                print("[HONEYPOT] Max active honeypots reached; skipping new honeypot.")
                return None
            key = (attacker_ip, target_port)
            existing = self._active.get(key)
            if existing:
                # check thread liveness
                thr = existing.get('thread')
                if thr and thr.is_alive() and existing.get('running', False):
                    print(f"[HONEYPOT] Honeypot already active for ({attacker_ip}, {target_port})")
                    return existing
                else:
                    # cleanup stale entry
                    try:
                        existing['running'] = False
                    except Exception:
                        pass
                    self._active.pop(key, None)

            # allocate a local port safely
            try:
                local_port = self._alloc_local_port()
            except Exception:
                # fallback deterministic port mapping
                local_port = 50000 + (hash(attacker_ip) % 10000)

            running_flag = {'run': True}
            logs = []

            # start thread
            t = threading.Thread(target=self._honeypot_server, args=(attacker_ip, target_port, local_port, running_flag), daemon=True)
            t.start()

            self._active[key] = {
                "attacker_ip": attacker_ip,
                "target_port": target_port,
                "local_port": local_port,
                "thread": t,
                "running": True,
                "running_flag": running_flag,
                "start_time": time.time(),
                "logs": logs
            }
            print(f"[HONEYPOT] Honeypot started for {attacker_ip}:{target_port} (local port {local_port})")
            return self._active[key]

    def stop_honeypot_for(self, attacker_ip, target_port=22):
        with self._lock:
            key = (attacker_ip, target_port)
            info = self._active.get(key)
            if not info:
                return False
            # signal thread to stop
            info['running_flag']['run'] = False
            info['running'] = False
            # attempt to close via connecting to wake accept() if needed
            try:
                # connecting to the local_port will unblock accept() and let server exit
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                try:
                    s.connect(("127.0.0.1", info['local_port']))
                except Exception:
                    pass
                try:
                    s.close()
                except Exception:
                    pass
            except Exception:
                pass
            # leave removal to server thread finalizer, but remove mapping now
            self._active.pop(key, None)
            print(f"[HONEYPOT] Stopped honeypot for {attacker_ip}:{target_port}")
            return True

    def list_active(self):
        """Return a copy of active honeypots with useful metadata."""
        with self._lock:
            out = {}
            for (ip, tp), info in self._active.items():
                out[f"{ip}:{tp}"] = {
                    "attacker_ip": ip,
                    "target_port": tp,
                    "local_port": info.get("local_port"),
                    "running": bool(info.get("running", False)),
                    "start_time": info.get("start_time"),
                    "log_count": len(info.get("logs", []))
                }
            return out

    def get_logs_for(self, attacker_ip, target_port=22, limit=100):
        with self._lock:
            key = (attacker_ip, target_port)
            info = self._active.get(key)
            if not info:
                return []
            return list(info['logs'][-limit:])

    def stop_all(self):
        with self._lock:
            keys = list(self._active.keys())
        for (ip, tp) in keys:
            try:
                self.stop_honeypot_for(ip, tp)
            except Exception:
                pass
        print("[HONEYPOT] All honeypots stop requested.")
