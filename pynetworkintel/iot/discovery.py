"""IoT and edge device discovery."""
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import logging
import socket
import threading

logger = logging.getLogger(__name__)


@dataclass
class IoTDevice:
    device_id: str
    device_type: str
    ip_address: str
    port: int
    manufacturer: str
    model: str
    firmware_version: str
    state: str
    protocols: List[str] = None
    services: List[str] = None
    tags: Dict[str, str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.protocols is None:
            self.protocols = []
        if self.services is None:
            self.services = []
        if self.tags is None:
            self.tags = {}
        if self.metadata is None:
            self.metadata = {}

    def to_dict(self):
        return asdict(self)


class IoTDeviceDiscovery:
    """Discover IoT and edge devices."""

    def __init__(self):
        """Initialize IoT device discovery."""
        self.devices: List[IoTDevice] = []
        self.mqtt_brokers = []
        self.iot_platforms = {}

    def discover_mqtt_brokers(self, network_range: str, port: int = 1883, timeout: float = 2.0) -> List[Dict[str, Any]]:
        """Discover MQTT brokers on the network."""
        brokers = []

        try:
            import paho.mqtt.client as mqtt_client
            mqtt_available = True
        except ImportError:
            mqtt_available = False
            logger.warning("paho-mqtt not installed. Install with: pip install paho-mqtt")

        # Parse network range (simplified - handles single IPs or basic ranges)
        ips = self._parse_network_range(network_range)

        for ip in ips:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()

                if result == 0:
                    broker_info = {
                        "ip_address": ip,
                        "port": port,
                        "protocol": "MQTT",
                        "state": "active",
                    }

                    # Try to get MQTT broker info if client available
                    if mqtt_available:
                        info = self._get_mqtt_broker_info(ip, port)
                        if info:
                            broker_info.update(info)

                    brokers.append(broker_info)
                    self.mqtt_brokers.append(broker_info)
            except Exception as e:
                logger.debug(f"Failed to check MQTT on {ip}:{port}: {e}")

        return brokers

    def discover_industrial_controllers(self, network_range: str) -> List[IoTDevice]:
        """Discover industrial controllers (PLCs, drives, etc.)."""
        controllers = []

        # Ports commonly used by industrial devices
        common_ports = {
            102: "S7comm (Siemens)",
            502: "Modbus TCP",
            20000: "DNP3",
            44818: "EtherCAT",
        }

        ips = self._parse_network_range(network_range)

        for ip in ips:
            for port, protocol in common_ports.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1.0)
                    result = sock.connect_ex((ip, port))
                    sock.close()

                    if result == 0:
                        device = IoTDevice(
                            device_id=f"{ip}:{port}",
                            device_type="industrial_controller",
                            ip_address=ip,
                            port=port,
                            manufacturer="Unknown",
                            model="Unknown",
                            firmware_version="Unknown",
                            state="active",
                            protocols=[protocol],
                        )
                        controllers.append(device)
                        self.devices.append(device)
                except:
                    pass

        return controllers

    def discover_iot_devices(self, network_range: str) -> List[IoTDevice]:
        """Discover common IoT devices."""
        devices = []

        # Common IoT service ports
        iot_ports = {
            5353: "mDNS/Bonjour",
            5357: "WSDP",
            8883: "MQTT (TLS)",
            8086: "InfluxDB",
            9200: "Elasticsearch",
        }

        ips = self._parse_network_range(network_range)

        for ip in ips:
            for port, service in iot_ports.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1.0)
                    result = sock.connect_ex((ip, port))
                    sock.close()

                    if result == 0:
                        device = IoTDevice(
                            device_id=f"{ip}:{port}",
                            device_type="iot_device",
                            ip_address=ip,
                            port=port,
                            manufacturer="Unknown",
                            model="Unknown",
                            firmware_version="Unknown",
                            state="active",
                            services=[service],
                        )
                        devices.append(device)
                        self.devices.append(device)
                except:
                    pass

        return devices

    def discover_gateway_devices(self, network_range: str) -> List[IoTDevice]:
        """Discover edge gateway devices."""
        gateways = []

        # Common gateway ports
        gateway_ports = {
            8080: "HTTP",
            8443: "HTTPS",
            5900: "VNC",
            22: "SSH",
        }

        ips = self._parse_network_range(network_range)

        for ip in ips:
            for port, protocol in gateway_ports.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1.0)
                    result = sock.connect_ex((ip, port))
                    sock.close()

                    if result == 0:
                        # Check if likely a gateway
                        if self._is_likely_gateway(ip, port):
                            device = IoTDevice(
                                device_id=f"{ip}:gateway",
                                device_type="edge_gateway",
                                ip_address=ip,
                                port=port,
                                manufacturer="Unknown",
                                model="Unknown",
                                firmware_version="Unknown",
                                state="active",
                                protocols=[protocol],
                            )
                            gateways.append(device)
                            self.devices.append(device)
                except:
                    pass

        return gateways

    def track_firmware_versions(self) -> Dict[str, List[str]]:
        """Track firmware versions of discovered devices."""
        firmware_inventory = {}

        for device in self.devices:
            key = f"{device.device_type}:{device.manufacturer}"
            if key not in firmware_inventory:
                firmware_inventory[key] = []

            firmware_inventory[key].append({
                "device": device.device_id,
                "version": device.firmware_version,
                "state": device.state,
            })

        return firmware_inventory

    def get_device_summary(self) -> Dict[str, Any]:
        """Get summary of discovered IoT devices."""
        by_type = {}
        by_protocol = {}
        active_devices = 0

        for device in self.devices:
            by_type[device.device_type] = by_type.get(device.device_type, 0) + 1

            for protocol in device.protocols:
                by_protocol[protocol] = by_protocol.get(protocol, 0) + 1

            if device.state == "active":
                active_devices += 1

        return {
            "total_devices": len(self.devices),
            "active_devices": active_devices,
            "mqtt_brokers": len(self.mqtt_brokers),
            "by_type": by_type,
            "by_protocol": by_protocol,
        }

    @staticmethod
    def _parse_network_range(network_range: str) -> List[str]:
        """Parse network range notation to list of IPs."""
        ips = []

        if "/" in network_range:
            # CIDR notation - simplified implementation
            try:
                import ipaddress
                network = ipaddress.ip_network(network_range, strict=False)
                ips = [str(ip) for ip in network.hosts()][:256]  # Limit to first 256
            except:
                ips = [network_range]
        elif "-" in network_range:
            # Range notation (e.g., 192.168.1.1-10)
            parts = network_range.rsplit(".", 1)
            if len(parts) == 2:
                prefix, range_part = parts
                try:
                    start, end = map(int, range_part.split("-"))
                    ips = [f"{prefix}.{i}" for i in range(start, end + 1)]
                except:
                    ips = [network_range]
        else:
            # Single IP
            ips = [network_range]

        return ips

    @staticmethod
    def _get_mqtt_broker_info(ip: str, port: int) -> Optional[Dict[str, Any]]:
        """Get MQTT broker information."""
        try:
            import paho.mqtt.client as mqtt_client

            info = {"version": None, "topics": []}

            def on_connect(client, userdata, flags, rc):
                userdata["connected"] = rc == 0

            def on_message(client, userdata, msg):
                if msg.topic not in userdata["topics"]:
                    userdata["topics"].append(msg.topic)

            client = mqtt_client.Client()
            client.on_connect = on_connect
            client.on_message = on_message

            userdata = {"connected": False, "topics": []}
            client.user_data_set(userdata)

            try:
                client.connect(ip, port, keepalive=5)
                client.loop_start()
            except:
                return None

            return None  # Simplified - return None as full implementation needs async handling
        except:
            return None

    @staticmethod
    def _is_likely_gateway(ip: str, port: int) -> bool:
        """Determine if device is likely a gateway."""
        # Heuristic: gateways often have HTTP/HTTPS on standard ports
        gateway_indicators = {
            8080: True,
            8443: True,
            443: True,
            80: True,
        }

        return gateway_indicators.get(port, False)
