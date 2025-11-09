# anomaly_detection.py
import random
import math
import time

class BehavioralAnomalyDetector:
    """
    Behavioral anomaly detector that assigns a dynamic threat score
    based on deviations in observed IP activity patterns.
    Works standalone or with real-time packet monitoring.
    """

    def __init__(self):
        self.ip_activity = {}
        self.learning_mode = True
        self.learning_start = time.time()
        self.learning_period = 15  # seconds
        print("🧠 Behavioral Anomaly Detector initialized in LEARNING mode...")

    def calculate_threat_score(self, ip):
        """
        Dynamically compute a threat score for a given IP.
        Returns a float between 0.0 and 1.0.
        """

        # Exit learning mode automatically
        if self.learning_mode and (time.time() - self.learning_start) > self.learning_period:
            self.learning_mode = False
            print("✅ Behavioral model switched to MONITORING mode.")

        # Initialize activity if unseen
        if ip not in self.ip_activity:
            self.ip_activity[ip] = {
                "count": 0,
                "last_seen": time.time(),
                "avg_interval": random.uniform(0.5, 3.0)
            }

        data = self.ip_activity[ip]
        now = time.time()
        interval = now - data["last_seen"]
        data["last_seen"] = now
        data["count"] += 1

        # Compute deviation (smaller intervals between packets = higher risk)
        deviation = max(0, (data["avg_interval"] - interval) / data["avg_interval"])
        base_score = deviation * random.uniform(0.6, 1.0)

        # Spike-based detection (sudden bursts)
        if interval < 0.3:
            base_score += 0.3

        # Randomized external factor (mimics contextual anomalies)
        randomness = random.uniform(0.0, 0.2)

        # Clamp to [0, 1]
        score = min(1.0, base_score + randomness)

        # Update model baseline during learning phase
        if self.learning_mode:
            data["avg_interval"] = (data["avg_interval"] + interval) / 2

        return round(score, 2)

    def get_status(self):
        """Return current mode and remaining time (for UI)."""
        if self.learning_mode:
            remaining = max(0, int(self.learning_period - (time.time() - self.learning_start)))
            return {"mode": "Learning", "time_remaining": remaining}
        else:
            return {"mode": "Monitoring"}
