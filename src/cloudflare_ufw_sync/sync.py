"""Cloudflare to UFW synchronization service."""

import logging
import time
from typing import Any

from cloudflare_ufw_sync.cloudflare import CloudflareClient
from cloudflare_ufw_sync.config import Config
from cloudflare_ufw_sync.ufw import UFWManager

logger = logging.getLogger(__name__)


class SyncService:
    """Syncs Cloudflare IP ranges with UFW rules."""

    def __init__(self, config: Config | None = None):
        self.config = config or Config()

        api_key = self.config.get("cloudflare", "api_key")
        api_key = str(api_key) if api_key else None
        self.cloudflare = CloudflareClient(api_key=api_key)

        self.ufw = UFWManager(
            port=int(self.config.get("ufw", "port") or 443),
            proto=str(self.config.get("ufw", "proto") or "tcp"),
            comment=str(self.config.get("ufw", "comment") or "Cloudflare IP"),
        )

    def sync(self) -> dict[str, Any]:
        """Sync Cloudflare IPs with UFW. Returns status dict."""
        logger.info("Starting sync")

        ip_types = self.config.get("cloudflare", "ip_types") or ["v4", "v6"]
        if not isinstance(ip_types, list):
            ip_types = ["v4", "v6"]

        cloudflare_ips = self.cloudflare.get_ip_ranges(ip_types)

        policy = self.config.get("ufw", "default_policy")
        if policy:
            self.ufw.set_policy(str(policy))

        self.ufw.ensure_enabled()
        added, removed = self.ufw.sync_rules(cloudflare_ips)

        logger.info(f"Sync done: {added} added, {removed} removed")
        return {
            "status": "success",
            "ips": {
                "v4": len(cloudflare_ips.get("v4", set())),
                "v6": len(cloudflare_ips.get("v6", set())),
            },
            "rules": {"added": added, "removed": removed},
        }

    def run_daemon(self) -> None:
        """Run sync on interval until interrupted."""
        interval = int(self.config.get("sync", "interval") or 86400)
        logger.info(f"Starting daemon, interval={interval}s")

        while True:
            try:
                self.sync()
                time.sleep(interval)
            except KeyboardInterrupt:
                logger.info("Stopped")
                break
            except Exception as e:
                logger.error(f"Sync error: {e}")
                time.sleep(60)
