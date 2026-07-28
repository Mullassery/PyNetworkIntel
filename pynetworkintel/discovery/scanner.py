"""Network device discovery engine."""

import subprocess
import json
import logging
import socket
from typing import List, Optional, Set
from datetime import datetime
import xml.etree.ElementTree as ET

from pynetworkintel.models import Device, Service

logger = logging.getLogger(__name__)


class NmapScanner:
    """Wrapper around nmap for service discovery."""

    def __init__(self, nmap_path: str = "nmap"):
        self.nmap_path = nmap_path
        self._check_nmap_available()

    def _check_nmap_available(self):
        try:
            subprocess.run([self.nmap_path, "-V"], capture_output=True, timeout=5)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning(f"nmap not found at {self.nmap_path}. Some discovery features will be limited.")

    def scan(self, target: str) -> List[Device]:
        """
        Scan target subnet/host for active devices and services.

        Args:
            target: IP address, CIDR range (10.0.0.0/24), or hostname

        Returns:
            List of discovered devices with service information
        """
        devices = []

        try:
            cmd = [
                self.nmap_path,
                "-sV",
                "--script=smb-os-discovery",
                "-oX",
                "-",
                target,
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

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

            device = self._parse_host(host)
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
            service_data = self._parse_service(port_elem)
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

    def __init__(self, nmap_path: str = "nmap"):
        self.nmap_scanner = NmapScanner(nmap_path)
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
