import platform
import subprocess
import json
import os
import ipaddress

class FirewallManager:
    """
    Firewall manager for AURA Cyber Threat Radar
    - Auto-blocks malicious IPs dynamically.
    - Persists blocked IPs.
    - Prevents duplicate rules.
    - Supports whitelist to avoid accidental blocking.
    - Works safely on Windows (using netsh).
    """

    def __init__(self, record_file="blocked_ips.json", whitelist_file="whitelist.json"):
        self.os = platform.system().lower()
        self.record_file = record_file
        self.whitelist_file = whitelist_file

        self.blocked_ips = set()
        self.whitelist = set()

        self._load_blocked_ips()
        self._load_whitelist()

    # -------------------------------
    # Loading / Saving Files
    # -------------------------------
    def _load_blocked_ips(self):
        if os.path.exists(self.record_file):
            try:
                with open(self.record_file, "r") as f:
                    self.blocked_ips = set(json.load(f))
                print(f"[FIREWALL] Loaded {len(self.blocked_ips)} previously blocked IPs.")
            except:
                self.blocked_ips = set()

    def _save_blocked_ips(self):
        try:
            with open(self.record_file, "w") as f:
                json.dump(sorted(self.blocked_ips), f, indent=2)
        except Exception as e:
            print(f"[FIREWALL] Failed to save record: {e}")

    def _load_whitelist(self):
        if os.path.exists(self.whitelist_file):
            try:
                with open(self.whitelist_file, "r") as f:
                    self.whitelist = set(json.load(f))
                print(f"[FIREWALL] Loaded {len(self.whitelist)} whitelisted IPs.")
            except:
                self.whitelist = set()
        else:
            # Create empty whitelist file
            with open(self.whitelist_file, "w") as f:
                json.dump([], f, indent=2)

    # -------------------------------
    # Private helpers
    # -------------------------------
    def _is_private_ip(self, ip):
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return True

    # -------------------------------
    # Main Methods
    # -------------------------------
    def block_ip(self, ip):
        """Block a malicious IP unless it is whitelisted."""

        # ✅ Never block private IPs
        if self._is_private_ip(ip):
            return

        # ✅ Check whitelist
        if ip in self.whitelist:
            print(f"[FIREWALL] SKIPPED — {ip} is WHITELISTED.")
            return

        # ✅ Avoid duplicate blocks
        if ip in self.blocked_ips:
            return

        try:
            if "windows" in self.os:
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=AURA_Block_{ip}", "dir=in", f"remoteip={ip}", "action=block"
                ], capture_output=True)

                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=AURA_Block_{ip}", "dir=out", f"remoteip={ip}", "action=block"
                ], capture_output=True)
            else:
                print(f"[FIREWALL] Non-Windows OS — simulated block for {ip}")

            self.blocked_ips.add(ip)
            self._save_blocked_ips()
            print(f"[FIREWALL] Blocked IP: {ip}")

        except Exception as e:
            print(f"[FIREWALL] Failed to block {ip}: {e}")

    def unblock_ip(self, ip):
        """Remove a firewall block rule."""
        if ip not in self.blocked_ips:
            return

        try:
            if "windows" in self.os:
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name=AURA_Block_{ip}"
                ], capture_output=True)
            else:
                print(f"[FIREWALL] Non-Windows OS — simulated unblock for {ip}")

            self.blocked_ips.remove(ip)
            self._save_blocked_ips()
            print(f"[FIREWALL] Unblocked IP: {ip}")

        except Exception as e:
            print(f"[FIREWALL] Failed to unblock {ip}: {e}")

    def list_blocked_ips(self):
        return sorted(list(self.blocked_ips))

    def list_whitelist(self):
        return sorted(list(self.whitelist))

    def add_to_whitelist(self, ip):
        """Add an IP to whitelist and ensure it's not blocked."""
        try:
            ipaddress.ip_address(ip)  # validate IP
        except ValueError:
            print(f"[FIREWALL] Invalid IP for whitelist: {ip}")
            return False

        self.whitelist.add(ip)

        # Save whitelist file
        with open(self.whitelist_file, "w") as f:
            json.dump(sorted(list(self.whitelist)), f, indent=2)

        # Auto-unblock if previously blocked
        if ip in self.blocked_ips:
            self.unblock_ip(ip)

        print(f"[FIREWALL] Added to whitelist: {ip}")
        return True
