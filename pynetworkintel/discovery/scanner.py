"""Network device discovery engine."""

import re
import subprocess
import json
import logging
import socket
from typing import List, Optional, Set
from datetime import datetime
import xml.etree.ElementTree as ET

from pynetworkintel.models import Device, Service

logger = logging.getLogger(__name__)

# Conservative allow-list for scan targets: IPv4/IPv6 literals, IPv4/IPv6
# CIDR ranges, and hostnames (RFC 1123-ish, dotted labels of letters,
# digits and hyphens). This exists to prevent argument injection into the
# nmap argv - e.g. a target of "--script=..." or "-oN=/etc/passwd" being
# interpreted as an nmap flag rather than a literal target. It intentionally
# rejects anything starting with "-" outright, since no legitimate target
# ever starts with a dash.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def validate_target(target: str) -> str:
    """Validate a scan target before it ever reaches a subprocess argv.

    Accepts IPv4/IPv6 addresses, IPv4/IPv6 CIDR ranges, and hostnames.
    Raises ValueError for anything else, including any string starting
    with "-" (which nmap/most CLI tools would otherwise interpret as a
    flag rather than a positional target).

    Returns the validated target string unchanged.
    """
    import ipaddress

    if not target or not isinstance(target, str):
        raise ValueError("Target must be a non-empty string")

    target = target.strip()

    if target.startswith("-"):
        raise ValueError(
            f"Invalid target {target!r}: targets may not start with '-' "
            "(this would be interpreted as a command-line flag)"
        )

    # IP address or CIDR range (covers both IPv4 and IPv6)
    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass

    # Hostname
    if _HOSTNAME_RE.match(target):
        return target

    raise ValueError(
        f"Invalid target {target!r}: expected an IP address, CIDR range, or hostname"
    )


class NmapScanner:
    """Wrapper around nmap for service discovery."""

    def __init__(self, nmap_path: str = "nmap", nmap_args: str = "-sV", timeout: int = 300):
        self.nmap_path = nmap_path
        self.nmap_args = nmap_args
        self.timeout = timeout
        self._check_nmap_available()

    def _check_nmap_available(self):
        try:
            subprocess.run([self.nmap_path, "-V"], capture_output=True, timeout=5)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning(f"nmap not found at {self.nmap_path}. Some discovery features will be limited.")

    def scan(self, target: str, timeout: Optional[int] = None) -> List[Device]:
        """
        Scan target subnet/host for active devices and services.

        Args:
            target: IP address, CIDR range (10.0.0.0/24), or hostname
            timeout: Per-scan timeout in seconds (overrides the instance
                default set from ScanConfig.timeout)

        Returns:
            List of discovered devices with service information
        """
        devices = []

        try:
            target = validate_target(target)
        except ValueError as e:
            logger.error(str(e))
            return devices

        effective_timeout = timeout if timeout is not None else self.timeout

        try:
            cmd = [self.nmap_path]
            cmd.extend(self.nmap_args.split())
            cmd.extend([
                "--script=smb-os-discovery",
                "-oX",
                "-",
                target,
            ])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=effective_timeout)

            if result.returncode not in (0, 1):
                logger.error(f"nmap scan failed: {result.stderr}")
                return devices

            devices = self._parse_nmap_xml(result.stdout)

        except subprocess.TimeoutExpired:
            logger.error(f"nmap scan timeout for {target}")
        except Exception as e:
            logger.error(f"nmap scan error: {e}")

        return devices

    def _parse_nmap_xml(self, xml_output: str) -> List[Device]:
        """Parse nmap XML output and extract device information."""
        devices = []

        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError:
            logger.error("Failed to parse nmap XML output")
            return devices

        for host in root.findall(".//host"):
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue

            try:
                device = self._parse_host(host)
            except Exception as e:
                # A malformed <host> (e.g. an unparseable <port portid="...">
                # inside it) used to propagate all the way up to scan()'s
                # outer except, which discarded every device from this scan
                # -- not just the bad one. Isolate it to this host so the
                # rest of the scan's results are still usable.
                address_elem = host.find("address")
                ip = address_elem.get("addr") if address_elem is not None else "unknown"
                logger.warning(f"Skipping unparseable host (ip={ip}): {e}")
                continue

            if device:
                devices.append(device)

        return devices

    def _parse_host(self, host_elem: ET.Element) -> Optional[Device]:
        """Parse individual host element from nmap XML."""
        address_elem = host_elem.find("address")
        if address_elem is None:
            return None

        ip = address_elem.get("addr")
        if not ip:
            return None

        device = Device(ip=ip, is_online=True)

        # Get OS information
        os_elem = host_elem.find(".//os/osmatch")
        if os_elem is not None:
            device.os = os_elem.get("name")

        # Get hostname
        hostnames = host_elem.findall(".//hostname")
        if hostnames:
            device.hostname = hostnames[0].get("name")

        # Parse services
        ports = host_elem.findall(".//port")
        for port_elem in ports:
            try:
                service_data = self._parse_service(port_elem)
            except Exception as e:
                # e.g. a <port> with a missing/non-numeric portid attribute
                # (int(None) or int("abc") both raise). Without this,
                # one bad port would propagate out of _parse_host and lose
                # this host entirely, including every other valid port on
                # it -- isolate it to just the one malformed port instead.
                portid = port_elem.get("portid", "unknown")
                logger.warning(
                    f"Skipping unparseable port (ip={ip}, portid={portid}): {e}"
                )
                continue

            if service_data:
                device.add_service(**service_data)

        return device

    def _parse_service(self, port_elem: ET.Element) -> Optional[dict]:
        """Parse service information from port element."""
        state = port_elem.find("state")
        if state is None or state.get("state") != "open":
            return None

        port = int(port_elem.get("portid"))
        protocol = port_elem.get("protocol", "tcp")

        service_elem = port_elem.find("service")
        service_name = "unknown"
        service_version = None

        if service_elem is not None:
            service_name = service_elem.get("name", "unknown")
            service_version = service_elem.get("version")

        return {
            "port": port,
            "name": service_name,
            "version": service_version,
            "protocol": protocol,
        }


class ARPScanner:
    """Simple ARP-based device discovery for local networks."""

    def scan_local(self, interface: Optional[str] = None) -> List[str]:
        """
        Discover active devices on local network via ARP.

        Args:
            interface: Network interface to scan (e.g., 'eth0', 'en0'). Auto-detect if None.

        Returns:
            List of discovered IP addresses
        """
        ips = []

        try:
            if interface is None:
                interface = self._get_default_interface()

            cmd = ["arp-scan", "-l", "-I", interface]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            for line in result.stdout.split("\n"):
                if "\t" in line:
                    parts = line.split("\t")
                    if len(parts) > 0:
                        ip = parts[0].strip()
                        if self._is_valid_ip(ip):
                            ips.append(ip)

        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning("arp-scan not available, using nmap ping discovery instead")

        return ips

    def _get_default_interface(self) -> str:
        """Get default network interface."""
        try:
            result = subprocess.run(
                ["ip", "route", "show"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in result.stdout.split("\n"):
                if "default" in line:
                    parts = line.split()
                    if len(parts) > 4:
                        return parts[4]
        except Exception:
            pass

        return "eth0"

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False


class DeviceScanner:
    """High-level device discovery orchestrator."""

    def __init__(self, nmap_path: str = "nmap", nmap_args: str = "-sV", timeout: int = 300):
        self.nmap_scanner = NmapScanner(nmap_path, nmap_args=nmap_args, timeout=timeout)
        self.arp_scanner = ARPScanner()

    def discover(self, target: str) -> List[Device]:
        """
        Discover devices in target network.

        Args:
            target: IP address, CIDR range, or hostname

        Returns:
            List of discovered devices
        """
        logger.info(f"Starting device discovery for {target}")

        devices = self.nmap_scanner.scan(target)

        logger.info(f"Discovered {len(devices)} devices")

        return devices

    def discover_local(self) -> List[Device]:
        """Discover devices on local network."""
        logger.info("Starting local network discovery via ARP")

        ips = self.arp_scanner.scan_local()
        logger.info(f"Found {len(ips)} local devices via ARP")

        devices = []
        for ip in ips:
            device = Device(ip=ip, is_online=True)
            devices.append(device)

        return devices
