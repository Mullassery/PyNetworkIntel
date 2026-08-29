"""Tests for visualization-friendly topology export formats
(pynetworkintel.topology_export)."""

import json
import os
import tempfile
from xml.etree import ElementTree as ET

import pytest

from pynetworkintel.models import Device
from pynetworkintel.topology import TopologyMapper, NetworkTopology
from pynetworkintel.topology_export import (
    to_node_link_json,
    node_link_json_str,
    to_graphml,
    export_topology,
    GRAPHML_NAMESPACE,
)


def _sample_topology() -> NetworkTopology:
    """A small topology: one gateway (.1) connected to two devices, all in
    the same /24, so we get 3 nodes and 2 gateway edges."""
    devices = [
        Device(ip="192.168.1.1", hostname="router.local"),
        Device(ip="192.168.1.50", hostname="laptop.local"),
        Device(ip="192.168.1.51"),
    ]
    return TopologyMapper().build(devices)


class TestNodeLinkJson:
    def test_top_level_shape(self):
        topology = _sample_topology()
        data = to_node_link_json(topology)
        assert set(data.keys()) == {"nodes", "links"}
        assert isinstance(data["nodes"], list)
        assert isinstance(data["links"], list)

    def test_node_count_and_ids(self):
        topology = _sample_topology()
        data = to_node_link_json(topology)
        assert len(data["nodes"]) == 3
        ids = {n["id"] for n in data["nodes"]}
        assert ids == {"192.168.1.1", "192.168.1.50", "192.168.1.51"}
        # every node must carry an "id" key (d3/vis.js requirement)
        for node in data["nodes"]:
            assert "id" in node

    def test_link_count_and_source_target(self):
        topology = _sample_topology()
        data = to_node_link_json(topology)
        assert len(data["links"]) == 2
        for link in data["links"]:
            assert link["source"] == "192.168.1.1"
            assert link["target"] in ("192.168.1.50", "192.168.1.51")
            assert link["relationship"] == "gateway"

    def test_node_attributes_preserved(self):
        topology = _sample_topology()
        data = to_node_link_json(topology)
        router = next(n for n in data["nodes"] if n["id"] == "192.168.1.1")
        assert router["hostname"] == "router.local"
        assert router["node_type"] == "gateway"
        assert router["subnet"] == "192.168.1.0/24"

    def test_empty_topology(self):
        topology = TopologyMapper().build([])
        data = to_node_link_json(topology)
        assert data == {"nodes": [], "links": []}

    def test_node_link_json_str_is_valid_json(self):
        topology = _sample_topology()
        raw = node_link_json_str(topology)
        parsed = json.loads(raw)
        assert len(parsed["nodes"]) == 3
        assert len(parsed["links"]) == 2

    def test_export_topology_node_link_json_round_trips_via_file(self):
        topology = _sample_topology()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "topology.json")
            export_topology(topology, path, "node-link-json")
            with open(path) as f:
                parsed = json.load(f)
            assert len(parsed["nodes"]) == 3
            assert len(parsed["links"]) == 2


class TestGraphML:
    def test_output_is_well_formed_xml(self):
        topology = _sample_topology()
        xml_str = to_graphml(topology)
        root = ET.fromstring(xml_str)  # raises if not well-formed
        assert root.tag == f"{{{GRAPHML_NAMESPACE}}}graphml"

    def test_node_and_edge_counts(self):
        topology = _sample_topology()
        xml_str = to_graphml(topology)
        root = ET.fromstring(xml_str)
        ns = {"g": GRAPHML_NAMESPACE}
        graph_el = root.find("g:graph", ns)
        assert graph_el is not None
        nodes = graph_el.findall("g:node", ns)
        edges = graph_el.findall("g:edge", ns)
        assert len(nodes) == 3
        assert len(edges) == 2

    def test_node_ids_match_ips(self):
        topology = _sample_topology()
        xml_str = to_graphml(topology)
        root = ET.fromstring(xml_str)
        ns = {"g": GRAPHML_NAMESPACE}
        node_ids = {n.get("id") for n in root.find("g:graph", ns).findall("g:node", ns)}
        assert node_ids == {"192.168.1.1", "192.168.1.50", "192.168.1.51"}

    def test_edge_source_target_match_gateway(self):
        topology = _sample_topology()
        xml_str = to_graphml(topology)
        root = ET.fromstring(xml_str)
        ns = {"g": GRAPHML_NAMESPACE}
        edges = root.find("g:graph", ns).findall("g:edge", ns)
        for edge in edges:
            assert edge.get("source") == "192.168.1.1"
            assert edge.get("target") in ("192.168.1.50", "192.168.1.51")

    def test_graph_is_undirected(self):
        topology = _sample_topology()
        xml_str = to_graphml(topology)
        root = ET.fromstring(xml_str)
        ns = {"g": GRAPHML_NAMESPACE}
        graph_el = root.find("g:graph", ns)
        assert graph_el.get("edgedefault") == "undirected"

    def test_empty_topology_still_valid(self):
        topology = TopologyMapper().build([])
        xml_str = to_graphml(topology)
        root = ET.fromstring(xml_str)
        ns = {"g": GRAPHML_NAMESPACE}
        graph_el = root.find("g:graph", ns)
        assert graph_el.findall("g:node", ns) == []
        assert graph_el.findall("g:edge", ns) == []

    def test_none_hostname_omitted_not_stringified(self):
        # 192.168.1.51 has no hostname set
        topology = _sample_topology()
        xml_str = to_graphml(topology)
        assert "None" not in xml_str

    def test_export_topology_graphml_round_trips_via_file(self):
        topology = _sample_topology()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "topology.graphml")
            export_topology(topology, path, "graphml")
            tree = ET.parse(path)
            ns = {"g": GRAPHML_NAMESPACE}
            graph_el = tree.getroot().find("g:graph", ns)
            assert len(graph_el.findall("g:node", ns)) == 3
            assert len(graph_el.findall("g:edge", ns)) == 2


class TestExportTopologyErrors:
    def test_unknown_format_raises(self):
        topology = _sample_topology()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "out.bin")
            with pytest.raises(ValueError):
                export_topology(topology, path, "not-a-real-format")


class TestNetworkTopologyFromDict:
    def test_round_trips_to_dict(self):
        topology = _sample_topology()
        data = topology.to_dict()
        rebuilt = NetworkTopology.from_dict(data)
        assert len(rebuilt.nodes) == len(topology.nodes)
        assert len(rebuilt.edges) == len(topology.edges)
        assert rebuilt.subnets == topology.subnets

    def test_from_dict_feeds_into_exporters(self):
        topology = _sample_topology()
        rebuilt = NetworkTopology.from_dict(topology.to_dict())
        data = to_node_link_json(rebuilt)
        assert len(data["nodes"]) == 3
        assert len(data["links"]) == 2
