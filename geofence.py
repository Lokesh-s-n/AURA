# geofence.py
import math

class GeoFencing:
    def __init__(self, center_lat, center_lon, radius_km):
        self.center_lat = center_lat
        self.center_lon = center_lon
        self.radius_km = radius_km

    def distance(self, lat1, lon1, lat2, lon2):
        R = 6371  # Earth radius in km
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)

        a = (math.sin(dlat/2)**2 +
             math.cos(math.radians(lat1)) *
             math.cos(math.radians(lat2)) *
             math.sin(dlon/2)**2)

        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return R * c

    def is_outside(self, lat, lon):
        try:
            dist = self.distance(self.center_lat, self.center_lon, lat, lon)
            return dist > self.radius_km
        except Exception:
            return False  # Fail-safe fallback


def safe_check_geofence(geofence_obj, lat, lon):
    """Safely check without causing errors."""
    try:
        if lat is None or lon is None:
            return False
        return geofence_obj.is_outside(lat, lon)
    except:
        return False
