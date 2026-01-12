"""Cloudflare API client."""

import logging
from typing import Dict, List, Optional, Set

import requests

logger = logging.getLogger(__name__)

CLOUDFLARE_IPS_URL = "https://api.cloudflare.com/client/v4/ips"


class CloudflareClient:
    """Fetches IP ranges from Cloudflare's API."""

    def __init__(self, api_key: Optional[str] = None):
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({"Authorization": f"Bearer {api_key}"})

    def get_ip_ranges(self, ip_types: Optional[List[str]] = None) -> Dict[str, Set[str]]:
        """Fetch Cloudflare IP ranges. Returns dict mapping 'v4'/'v6' to IP sets."""
        if ip_types is None:
            ip_types = ["v4", "v6"]

        logger.info(f"Fetching Cloudflare IP ranges for: {ip_types}")

        response = self.session.get(CLOUDFLARE_IPS_URL)
        response.raise_for_status()
        data = response.json()

        if not data.get("success", False):
            raise RuntimeError(f"Cloudflare API error: {data.get('errors', ['Unknown'])}")

        result = data.get("result", {})
        ip_ranges = {}

        if "v4" in ip_types and "ipv4_cidrs" in result:
            ip_ranges["v4"] = set(result["ipv4_cidrs"])
            logger.info(f"Found {len(ip_ranges['v4'])} IPv4 ranges")

        if "v6" in ip_types and "ipv6_cidrs" in result:
            ip_ranges["v6"] = set(result["ipv6_cidrs"])
            logger.info(f"Found {len(ip_ranges['v6'])} IPv6 ranges")

        return ip_ranges
