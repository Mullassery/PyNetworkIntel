"""Tests for the network topology mapper (pynetworkintel.topology)."""

import pytest

from pynetworkintel.models import Device, ScanResult
from pynetworkintel.topology import TopologyMapper, NetworkTopology


class TestTopologyMapper:
    def test_empty_device_list(self):
        topology = TopologyMapper().build([])
        assert topology.nodes == []
        assert topology.edges == []
        assert topology.subnets == []

    def test_single_device_no_edges(self):
        devices = [Device(ip="192.168.1.5")]
        topology = TopologyMapper().build(devices)
        assert len(topology.nodes) == 1
        assert topology.edges == []
        assert topology.subnets == ["192.168.1.0/24"]

    def test_devices_grouped_into_same_subnet(self):
        devices = [
            Device(ip="192.168.1.1"),
            Device(ip="192.168.1.10"),
            Device(ip="192.168.1.20"),
        ]
        topology = TopologyMapper().build(devices)
        assert topology.subnets == ["192.168.1.0/24"]
        assert len(topology.nodes) == 3

    def test_devices_in_different_subnets_not_grouped(self):
        devices = [
            Device(ip="192.168.1.10"),
            Device(ip="10.0.0.10"),
        ]
        topology = TopologyMapper().build(devices)
        assert set(topology.subnets) == {"192.168.1.0/24", "10.0.0.0/24"}
        # each subnet only has 1 device -> no gateway edges
        assert topology.edges == []

    def test_gateway_inferred_from_dot_one_address(self):
        devices = [
            Device(ip="192.168.1.1"),
            Device(ip="192.168.1.50"),
            Device(ip="192.168.1.51"),
        ]
        topology = TopologyMapper().build(devices)

        gateway_node = next(n for n in topology.nodes if n.ip == "192.168.1.1")
        assert gateway_node.node_type == "gateway"

        other_nodes = [n for n in topology.nodes if n.ip != "192.168.1.1"]
        assert all(n.node_type == "device" for n in other_nodes)

        # gateway is connected to both other devices
        assert len(topology.edges) == 2
        for edge in topology.edges:
            assert edge.source == "192.168.1.1"
            assert edge.relationship == "gateway"

    def test_gateway_falls_back_to_lowest_ip_without_dot_one(self):
        devices = [
            Device(ip="192.168.1.50"),
            Device(ip="192.168.1.20"),
            Device(ip="192.168.1.99"),
        ]
        topology = TopologyMapper().build(devices)

        gateway_node = next(n for n in topology.nodes if n.node_type == "gateway")
        assert gateway_node.ip == "192.168.1.20"

    def test_invalid_ip_is_skipped_not_crashed(self):
        devices = [
            Device(ip="192.168.1.1"),
            Device(ip="not-an-ip-address!!"),
        ]
        topology = TopologyMapper().build(devices)
        # the invalid device is dropped from subnet grouping but shouldn't crash
        assert any(n.ip == "192.168.1.1" for n in topology.nodes)

    def test_hostname_preserved_on_node(self):
        devices = [Device(ip="192.168.1.5", hostname="myhost.local")]
        topology = TopologyMapper().build(devices)
        assert topology.nodes[0].hostname == "myhost.local"

    def test_to_dict_roundtrip_shape(self):
        devices = [Device(ip="192.168.1.1"), Device(ip="192.168.1.2")]
        topology = TopologyMapper().build(devices)
        data = topology.to_dict()
        assert set(data.keys()) == {"nodes", "edges", "subnets"}
        assert isinstance(data["nodes"], list)
        assert isinstance(data["edges"], list)

    def test_adjacency_is_undirected(self):
        devices = [
            Device(ip="192.168.1.1"),
            Device(ip="192.168.1.2"),
        ]
        topology = TopologyMapper().build(devices)
        adj = topology.adjacency()
        assert "192.168.1.2" in adj["192.168.1.1"]
        assert "192.168.1.1" in adj["192.168.1.2"]

    def test_devices_by_subnet_grouping(self):
        devices = [
            Device(ip="192.168.1.1"),
            Device(ip="192.168.1.2"),
            Device(ip="10.0.0.1"),
        ]
        topology = TopologyMapper().build(devices)
        grouped = topology.devices_by_subnet()
        assert set(grouped["192.168.1.0/24"]) == {"192.168.1.1", "192.168.1.2"}
        assert grouped["10.0.0.0/24"] == ["10.0.0.1"]

    def test_custom_prefix_length(self):
        devices = [
            Device(ip="192.168.1.10"),
            Device(ip="192.168.2.10"),
        ]
        # /16 groups both into the same subnet
        topology = TopologyMapper(prefix_len_v4=16).build(devices)
        assert topology.subnets == ["192.168.0.0/16"]

    def test_ipv6_devices_grouped(self):
        devices = [
            Device(ip="2001:db8::1"),
            Device(ip="2001:db8::2"),
        ]
        topology = TopologyMapper().build(devices)
        assert len(topology.subnets) == 1


class TestScanResultTopologyIntegration:
    def test_scan_result_topology_method(self):
        result = ScanResult(devices=[Device(ip="192.168.1.1"), Device(ip="192.168.1.2")])
        topology = result.topology()
        assert isinstance(topology, NetworkTopology)
        assert len(topology.nodes) == 2

    def test_scan_result_to_dict_includes_topology(self):
        result = ScanResult(devices=[Device(ip="192.168.1.1")])
        data = result.to_dict()
        assert "topology" in data
        assert "nodes" in data["topology"]

    def test_scan_result_summary_includes_subnet_count(self):
        result = ScanResult(
            devices=[
                Device(ip="192.168.1.1"),
                Device(ip="10.0.0.1"),
            ]
        )
        summary = result.summary()
        assert summary["subnets_detected"] == 2
