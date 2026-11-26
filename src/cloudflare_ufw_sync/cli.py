# SPDX-FileCopyrightText: 2025-2026 Thomas Vincent <thomasvincent@gmail.com>
# SPDX-License-Identifier: MIT

"""Command line interface for cloudflare-ufw-sync.

This module provides the command-line interface for the cloudflare-ufw-sync tool.
It handles argument parsing and dispatches to the appropriate handler functions.
"""

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import NoReturn

from cloudflare_ufw_sync import __version__
from cloudflare_ufw_sync.config import Config
from cloudflare_ufw_sync.i18n import set_locale, t
from cloudflare_ufw_sync.sync import SyncService

logger = logging.getLogger(__name__)


class _LangPreParser(argparse.ArgumentParser):
    """Preliminary parser that ignores errors so the main parser reports them."""

    def error(self, message: str) -> NoReturn:
        raise ValueError(message)


def _extract_lang(args: list[str] | None) -> str | None:
    """Read --lang before argparse runs so --help uses the requested locale."""
    raw = sys.argv[1:] if args is None else args
    pre_parser = _LangPreParser(add_help=False)
    pre_parser.add_argument("--lang", type=str, default=None)
    try:
        ns, _ = pre_parser.parse_known_args(raw)
    except ValueError:
        return None
    lang: str | None = ns.lang
    return lang


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    """Parse command line arguments.

    Args:
        args: Command line arguments. If None, sys.argv[1:] is used.

    Returns:
        Parsed arguments as an argparse.Namespace object.
    """
    set_locale(_extract_lang(args))
    parser = argparse.ArgumentParser(description=t("cli.description"))
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument("--config", "-c", type=str, help=t("cli.config_help"))
    parser.add_argument(
        "--verbose", "-v", action="store_true", help=t("cli.verbose_help")
    )
    parser.add_argument("--lang", type=str, default=None, help=t("cli.lang_help"))

    subparsers = parser.add_subparsers(dest="command", help=t("cli.command_help"))

    # Sync command
    sync_parser = subparsers.add_parser("sync", help=t("cli.sync_help"))
    sync_parser.add_argument(
        "--force", "-f", action="store_true", help=t("cli.sync_force_help")
    )

    # Daemon command
    daemon_parser = subparsers.add_parser("daemon", help=t("cli.daemon_help"))
    daemon_parser.add_argument(
        "--foreground", action="store_true", help=t("cli.daemon_foreground_help")
    )

    # Status command
    subparsers.add_parser("status", help=t("cli.status_help"))

    # Install command
    install_parser = subparsers.add_parser("install", help=t("cli.install_help"))
    install_parser.add_argument(
        "--no-enable", action="store_true", help=t("cli.install_no_enable_help")
    )

    # Uninstall command
    subparsers.add_parser("uninstall", help=t("cli.uninstall_help"))

    parsed = parser.parse_args(args)
    set_locale(parsed.lang)
    return parsed


def handle_sync(config: Config, force: bool = False) -> int:
    """Handle the sync command to synchronize Cloudflare IP ranges with UFW.

    Args:
        config: Configuration object containing sync settings.
        force: Whether to force synchronization even if not needed.

    Returns:
        int: Exit code - 0 for success, 1 for failure.
    """
    sync_service = SyncService(config)
    try:
        result = sync_service.sync()
        print(t("sync.completed"))
        print(t("sync.ipv4_ranges", count=result["ips"]["v4"]))
        print(t("sync.ipv6_ranges", count=result["ips"]["v6"]))
        print(t("sync.rules_added", count=result["rules"]["added"]))
        print(t("sync.rules_removed", count=result["rules"]["removed"]))
        return 0
    except Exception as e:
        logger.error(t("sync.failed", error=e))
        return 1


def handle_daemon(config: Config, foreground: bool = False) -> int:
    """Handle the daemon command to run the service in background or foreground.

    Forks the process unless foreground mode is requested. The daemon
    continuously monitors and updates UFW rules based on Cloudflare IP changes.

    Args:
        config: Configuration object containing daemon settings.
        foreground: Whether to run in foreground (True) or background (False).

    Returns:
        int: Exit code - 0 for success, 1 for failure.
    """
    if not foreground and os.fork() > 0:
        # Parent process: we return immediately so your shell prompt isn't held hostage.
        return 0

    # Child process: this is the long-running worker that keeps things in sync.
    try:
        sync_service = SyncService(config)
        sync_service.run_daemon()
        return 0
    except Exception as e:
        logger.error(t("daemon.failed", error=e))
        return 1


def handle_status(config: Config) -> int:
    """Handle the status command to display current UFW rules for Cloudflare IPs.

    Retrieves current UFW rules and displays summary statistics.

    Args:
        config: Configuration object containing status settings.

    Returns:
        int: Exit code - 0 for success, 1 for failure.
    """
    try:
        # Import locally to avoid circular imports
        from cloudflare_ufw_sync.ufw import UFWManager

        ufw = UFWManager()
        existing_rules = ufw.get_existing_rules()
        print(t("status.header"))
        print(t("status.ipv4_rules", count=len(existing_rules["v4"])))
        print(t("status.ipv6_rules", count=len(existing_rules["v6"])))
        return 0
    except Exception as e:
        logger.error(t("status.failed", error=e))
        return 1


def handle_install(config: Config, no_enable: bool = False) -> int:
    """Handle the install command to set up the service as a systemd unit.

    Installs the service file, reloads systemd, and optionally enables and
    starts the service.

    Args:
        config: Configuration object containing installation settings.
        no_enable: If True, don't enable and start the service after installation.

    Returns:
        int: Exit code - 0 for success, 1 for failure.
    """
    # Get the script directory
    script_dir = Path(__file__).resolve().parent.parent.parent / "scripts"

    if not (script_dir / "cloudflare-ufw-sync.service").exists():
        logger.error(t("install.service_not_found"))
        return 1

    try:
        import shutil
        import subprocess

        # Copy service file
        dest = Path("/etc/systemd/system/cloudflare-ufw-sync.service")
        shutil.copy(script_dir / "cloudflare-ufw-sync.service", dest)
        print(t("install.service_installed", dest=dest))

        # Reload systemd
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        print(t("install.daemon_reloaded"))

        if not no_enable:
            # Enable and start service
            subprocess.run(["systemctl", "enable", "cloudflare-ufw-sync"], check=True)
            print(t("install.service_enabled"))
            subprocess.run(["systemctl", "start", "cloudflare-ufw-sync"], check=True)
            print(t("install.service_started"))

        return 0
    except Exception as e:
        logger.error(t("install.failed", error=e))
        return 1


def handle_uninstall(config: Config) -> int:
    """Handle the uninstall command to remove the systemd service.

    Stops the service if running, disables it from auto-starting,
    removes the service file, and reloads systemd.

    Args:
        config: Configuration object containing uninstallation settings.

    Returns:
        int: Exit code - 0 for success, 1 for failure.
    """
    try:
        import subprocess

        # Stop and disable service
        subprocess.run(["systemctl", "stop", "cloudflare-ufw-sync"], check=False)
        print(t("uninstall.service_stopped"))
        subprocess.run(["systemctl", "disable", "cloudflare-ufw-sync"], check=False)
        print(t("uninstall.service_disabled"))

        # Remove service file
        service_file = Path("/etc/systemd/system/cloudflare-ufw-sync.service")
        if service_file.exists():
            service_file.unlink()
            print(t("uninstall.service_removed", path=service_file))

        # Reload systemd
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        print(t("install.daemon_reloaded"))

        return 0
    except Exception as e:
        logger.error(t("uninstall.failed", error=e))
        return 1


def main(args: list[str] | None = None) -> int:
    """Main entry point for the command-line interface.

    Parses arguments, sets up configuration and logging, and dispatches to
    the appropriate command handler.

    Args:
        args: Command line arguments. If None, sys.argv[1:] is used.

    Returns:
        int: Exit code - 0 for success, 1 for failure.
    """
    parsed_args = parse_args(args)

    # Initialize configuration
    config = Config(parsed_args.config)

    # Setup logging
    if parsed_args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        config.setup_logging()

    # Handle commands
    if parsed_args.command == "sync":
        return handle_sync(config, parsed_args.force)
    elif parsed_args.command == "daemon":
        return handle_daemon(config, parsed_args.foreground)
    elif parsed_args.command == "status":
        return handle_status(config)
    elif parsed_args.command == "install":
        return handle_install(config, parsed_args.no_enable)
    elif parsed_args.command == "uninstall":
        return handle_uninstall(config)
    else:
        print(t("cli.no_command"))
        return 1


if __name__ == "__main__":
    sys.exit(main())
