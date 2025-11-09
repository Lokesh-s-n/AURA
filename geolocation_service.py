# geolocation_service.py
import geoip2.database
import ipaddress

class GeoLocator:
    """
    Handles IP to Geolocation mapping using the MaxMind GeoLite2 database.
    """
    def __init__(self, db_path='GeoLite2-City.mmdb'):
        try:
            self.reader = geoip2.database.Reader(db_path)
            print("🌍 GeoLite2 Database loaded successfully.")
        except FileNotFoundError:
            print(f"⚠️ GeoLite2 database not found at {db_path}. Location lookups will return Unknown.")
            self.reader = None

    def get_location(self, ip_address):
        """
        Fetches location data, including lat/lon, for a given public IP address.
        Returns None for private or invalid IPs.
        """
        if self.reader is None or self._is_private_ip(ip_address):
            return None
        try:
            response = self.reader.city(ip_address)
            return {
                'city': response.city.name or 'Unknown',
                'country': response.country.name or 'Unknown',
                'latitude': response.location.latitude,
                'longitude': response.location.longitude
            }
        except (geoip2.errors.AddressNotFoundError, ValueError):
            return None

    def _is_private_ip(self, ip):
        """
        Checks if an IP is private (e.g., 192.168.x.x, 10.x.x.x, etc.).
        """
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False
