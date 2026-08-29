"""Network topology mapping.

Derives a real graph structure - nodes and edges - from discovered devices,
rather than leaving them as an unrelated flat list. "Topology mapping" is
core to this product's stated purpose (it's in the product description),
so this is not an optional extra.

This is intentionally dependency-free (no networkx): devices are grouped
into inferred subnets using the stdlib `ipaddress` module, and edges are
derived heuristically:

  - "gateway" edges: within an inferred subnet, the device that looks most
    like a router/gateway (heuristically: host address ending in .1, or
    otherwise the lowest address in the subnet) is connected to every other
    device in that subnet.
  - "same-subnet" edges are implied by shared subnet membership and are
    available via `NetworkTopology.subnets` / `devices_by_subnet()` without
    duplicating an edge per device pair (which would be O(n^2) for little
    added value over the star topology already captured by gateway edges).

This is a heuristic, address-based inference - it does not perform active
route discovery (traceroute) or read switch/router forwarding tables, so it
will not detect L2 topology, VLANs, or multi-hop routing. It's a reasonable
default for the common case (devices in the same IPv4 /24-ish subnet are
very likely on the same L2 segment) and a foundation that real routing data
could be layered onto later.
"""

import ipaddress
import logging
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from pynetworkintel.models import Device

logger = logging.getLogger(__name__)


@dataclass
class TopologyNode:
    ip: str
    hostname: Optional[str] = None
    node_type: str = "device"  # "device" or "gateway"
    subnet: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TopologyEdge:
    source: str
    target: str
    relationship: str  # "gateway"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class NetworkTopology:
    nodes: List[TopologyNode] = field(default_factory=list)
    edges: List[TopologyEdge] = field(default_factory=list)
    subnets: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "subnets": self.subnets,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NetworkTopology":
        """Reconstruct a NetworkTopology from the shape produced by
        `to_dict()`. Used by callers (e.g. the CLI) that only have the
        already-serialized dict form (such as a Pipeline result) but still
        want to feed it into one of the graph export formats."""
        return cls(
            nodes=[TopologyNode(**n) for n in data.get("nodes", [])],
            edges=[TopologyEdge(**e) for e in data.get("edges", [])],
            subnets=list(data.get("subnets", [])),
        )

    def adjacency(self) -> Dict[str, List[str]]:
        """Return an adjacency-list view of the graph (undirected)."""
        adj: Dict[str, List[str]] = {n.ip: [] for n in self.nodes}
        for edge in self.edges:
            adj.setdefault(edge.source, [])
            adj.setdefault(edge.target, [])
            adj[edge.source].append(edge.target)
            adj[edge.target].append(edge.source)
        return adj

    def devices_by_subnet(self) -> Dict[str, List[str]]:
        """Return {subnet_cidr: [ip, ...]} grouping."""
        grouped: Dict[str, List[str]] = {}
        for node in self.nodes:
            if node.subnet:
                grouped.setdefault(node.subnet, []).append(node.ip)
        return grouped


class TopologyMapper:
    """Builds a NetworkTopology graph from a list of discovered devices."""

    def __init__(self, prefix_len_v4: int = 24, prefix_len_v6: int = 64):
        """
        Args:
            prefix_len_v4: Subnet prefix length used to group IPv4 devices
                (default /24, the common LAN convention)
            prefix_len_v6: Subnet prefix length used to group IPv6 devices
        """
        self.prefix_len_v4 = prefix_len_v4
        self.prefix_len_v6 = prefix_len_v6

    def build(self, devices: List[Device]) -> NetworkTopology:
        """Derive subnet/gateway edges from a list of discovered devices."""
        subnets: Dict[str, List[Device]] = {}
        node_subnet: Dict[str, str] = {}

        for device in devices:
            net = self._infer_subnet(device.ip)
            if net is None:
                logger.debug(f"Could not parse IP for topology mapping: {device.ip}")
                continue
            subnets.setdefault(net, []).append(device)
            node_subnet[device.ip] = net

        nodes: List[TopologyNode] = []
        edges: List[TopologyEdge] = []

        gateways: Dict[str, Device] = {}
        for net, group in subnets.items():
            gateways[net] = self._infer_gateway(group)

        for device in devices:
            net = node_subnet.get(device.ip)
            gateway = gateways.get(net) if net else None
            node_type = "gateway" if gateway is not None and gateway.ip == device.ip else "device"
            nodes.append(
                TopologyNode(
                    ip=device.ip,
                    hostname=device.hostname,
                    node_type=node_type,
                    subnet=net,
                )
            )

        for net, group in subnets.items():
            if len(group) < 2:
                continue
            gateway = gateways[net]
            for device in group:
                if device.ip == gateway.ip:
                    continue
                edges.append(
                    TopologyEdge(source=gateway.ip, target=device.ip, relationship="gateway")
                )

        return NetworkTopology(nodes=nodes, edges=edges, subnets=sorted(subnets.keys()))

    def _infer_subnet(self, ip_str: str) -> Optional[str]:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return None

        prefix = self.prefix_len_v4 if ip.version == 4 else self.prefix_len_v6
        network = ipaddress.ip_network(f"{ip_str}/{prefix}", strict=False)
        return str(network)

    @staticmethod
    def _infer_gateway(group: List[Device]) -> Device:
        """Heuristically pick the most gateway-like device in a subnet group.

        Preference order: an address whose last octet is 1 (e.g. x.x.x.1,
        the overwhelming convention for router/gateway addresses on small
        LANs), falling back to the numerically-lowest address in the group.
        """
        for device in group:
            try:
                ip = ipaddress.ip_address(device.ip)
            except ValueError:
                continue
            if ip.version == 4 and int(ip) % 256 == 1:
                return device
            if ip.version == 6 and int(ip) & 0xFFFF == 1:
                return device

        return min(group, key=lambda d: int(ipaddress.ip_address(d.ip)))
