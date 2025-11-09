# threat_intelligence_service.py
import requests
import ipaddress
import time
import random

class ThreatIntel:
    SPAMHAUS_URLS = [
        "https://www.spamhaus.org/drop/drop.txt",
        "https://www.spamhaus.org/drop/edrop.txt"
    ]
    def __init__(self, abuse_key=""):
        self.abuse_key = (abuse_key or "").strip()
        self.bad_entries = set()
        self._fetch_spamhaus()
        self._last_abuse_fail = 0

    def _fetch_spamhaus(self):
        try:
            for url in self.SPAMHAUS_URLS:
                r = requests.get(url, timeout=6)
                if r.status_code == 200:
                    for line in r.text.splitlines():
                        line = line.strip()
                        if not line or line.startswith(";"):
                            continue
                        cidr = line.split(";")[0].strip()
                        self.bad_entries.add(cidr)
        except Exception as e:
            print("[INTEL] Spamhaus fetch error:", e)

    def _abuse_lookup(self, ip):
        if not self.abuse_key:
            return None
        if time.time() - self._last_abuse_fail < 5:
            return None
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": self.abuse_key, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": "90"}
            r = requests.get(url, headers=headers, params=params, timeout=6)
            if r.status_code == 200:
                data = r.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                return min(1.0, max(0.0, score/100.0))
            else:
                self._last_abuse_fail = time.time()
                return None
        except Exception as e:
            self._last_abuse_fail = time.time()
            print("[INTEL] AbuseIPDB lookup failed:", e)
            return None

    def check_ip_reputation(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private:
                return 0.0
        except Exception:
            return 0.0
        # check spamhaus list (CIDR-aware)
        for entry in list(self.bad_entries):
            try:
                if "/" in entry:
                    if addr in ipaddress.ip_network(entry, strict=False):
                        return 1.0
                else:
                    if ip == entry:
                        return 1.0
            except Exception:
                if ip.startswith(entry.split("/")[0]):
                    return 1.0
        # AbuseIPDB
        v = self._abuse_lookup(ip)
        if v is not None:
            return round(float(v), 2)
        # heuristic: prefixes
        high = ("45.","185.","103.","198.","156.")
        med = ("13.","20.","34.","52.","104.","40.","23.")
        for p in high:
            if ip.startswith(p):
                return round(0.75 + (0.2 * (hash(ip)%10)/10.0), 2)
        for p in med:
            if ip.startswith(p):
                return round(0.2 + (0.3 * (hash(ip)%10)/10.0), 2)
        return round(0.02 * ((hash(ip)%10)/10.0), 2)
