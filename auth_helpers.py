import hashlib


def device_fp(ip, user_agent, device_id=None):
    """Return a stable device fingerprint using persistent Device ID + User-Agent.
    We reduce reliance on IP to allow students on the same school WiFi.
    """
    if device_id:
        # Use persistent UUID + UA (most unique)
        s = f"{device_id}|{user_agent}"
    else:
        # Fallback to IP+UA if UUID not available
        s = f"{ip}|{user_agent}"
    return hashlib.sha256(s.encode()).hexdigest()
