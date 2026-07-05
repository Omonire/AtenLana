import requests
from math import radians, cos, sin, asin, sqrt


def haversine(lat1, lon1, lat2, lon2):
    """Compute distance in meters between two (lat,lon) points."""
    # Guard against None
    if lat1 is None or lon1 is None or lat2 is None or lon2 is None:
        raise ValueError('None value passed to haversine')
    lat1, lon1, lat2, lon2 = map(radians, [float(lat1), float(lon1), float(lat2), float(lon2)])
    dlon = lon2 - lon1
    dlat = lat2 - lat1
    a = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
    c = 2 * asin(sqrt(a))
    r = 6371000
    return c * r


def geocode(query, timeout=5):
    """Simple wrapper around ArcGIS World Geocoding Service. Returns dict with lat, lon, display_name.
    NOTE: This uses the free ArcGIS geocoding service (up to 1000 requests per day)."""
    if not query:
        return {'success': False, 'message': 'Query required'}
    try:
        url = 'https://geocode.arcgis.com/arcgis/rest/services/World/GeocodeServer/findAddressCandidates'
        params = {
            'SingleLine': query,
            'f': 'json',
            'maxLocations': 1,
            'outFields': 'Match_addr,Addr_type'
        }
        r = requests.get(url, params=params, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        if data.get('candidates') and len(data['candidates']) > 0:
            candidate = data['candidates'][0]
            lat = candidate['location']['y']
            lon = candidate['location']['x']
            display_name = candidate.get('address', query)
            return {'success': True, 'lat': lat, 'lon': lon, 'display_name': display_name}
        else:
            return {'success': False, 'message': 'No results found'}
    except Exception as e:
        return {'success': False, 'message': str(e)}
