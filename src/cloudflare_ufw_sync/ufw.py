"""UFW firewall management."""

import ipaddress
import logging
import re
import subprocess
from typing import Dict, List, Set, Tuple

logger = logging.getLogger(__name__)


class UFWManager:
    """Manages UFW rules for Cloudflare IP ranges."""

    def __init__(self, port: int = 443, proto: str = "tcp", comment: str = "Cloudflare IP"):
        self.port = port
        self.proto = proto
        self.comment = comment
        self._check_ufw_installed()

    def _check_ufw_installed(self) -> None:
        try:
            subprocess.run(["which", "ufw"], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            raise RuntimeError("UFW is not installed")

    def _run_ufw(self, args: List[str]) -> Tuple[bool, str]:
        cmd = ["ufw"] + args
        logger.debug(f"Running: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"UFW error: {e.stderr}")
            return False, e.stderr

    def get_existing_rules(self) -> Dict[str, Set[str]]:
        """Get existing Cloudflare rules from UFW."""
        success, output = self._run_ufw(["status", "numbered"])
        if not success:
            return {"v4": set(), "v6": set()}

        ip_ranges: Dict[str, Set[str]] = {"v4": set(), "v6": set()}

        for line in output.splitlines():
            if self.comment not in line:
                continue

            match = re.search(r"ALLOW\s+IN\s+(\S+)\s+from\s+(\S+)", line)
            if not match:
                continue

            proto_port, ip_range = match.groups()
            if f"{self.proto}/{self.port}" not in proto_port:
                continue

            try:
                ip_obj = ipaddress.ip_network(ip_range)
                ip_type = "v6" if ip_obj.version == 6 else "v4"
                ip_ranges[ip_type].add(ip_range)
            except ValueError:
                logger.warning(f"Invalid IP in UFW rule: {ip_range}")

        return ip_ranges

    def add_rule(self, ip_range: str) -> bool:
        args = ["allow", "proto", self.proto, "from", ip_range,
                "to", "any", "port", str(self.port), "comment", self.comment]
        success, _ = self._run_ufw(args)
        if success:
            logger.info(f"Added rule for {ip_range}")
        return success

    def delete_rule(self, ip_range: str) -> bool:
        success, output = self._run_ufw(["status", "numbered"])
        if not success:
            return False

        rule_number = None
        for line in output.splitlines():
            if ip_range in line and self.comment in line:
                match = re.match(r"\[\s*(\d+)\]", line)
                if match:
                    rule_number = match.group(1)
                    break

        if not rule_number:
            logger.warning(f"Rule for {ip_range} not found")
            return False

        success, _ = self._run_ufw(["delete", rule_number])
        if success:
            logger.info(f"Deleted rule for {ip_range}")
        return success

    def sync_rules(self, ip_ranges: Dict[str, Set[str]]) -> Tuple[int, int]:
        """Sync UFW rules with Cloudflare IPs. Returns (added, removed) counts."""
        existing = self.get_existing_rules()
        added = removed = 0

        for ip_type, ranges in ip_ranges.items():
            for ip_range in ranges:
                if ip_range not in existing[ip_type]:
                    if self.add_rule(ip_range):
                        added += 1

        for ip_type, ranges in existing.items():
            for ip_range in ranges:
                if ip_range not in ip_ranges.get(ip_type, set()):
                    if self.delete_rule(ip_range):
                        removed += 1

        logger.info(f"Sync: {added} added, {removed} removed")
        return added, removed

    def set_policy(self, policy: str) -> bool:
        if policy not in ("allow", "deny", "reject"):
            logger.error(f"Invalid policy: {policy}")
            return False
        success, _ = self._run_ufw(["default", policy, "incoming"])
        return success

    def ensure_enabled(self) -> bool:
        success, output = self._run_ufw(["status", "verbose"])
        if "Status: active" in output:
            return True
        success, _ = self._run_ufw(["--force", "enable"])
        return success
