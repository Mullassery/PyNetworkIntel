"""Visualization-friendly export formats for `NetworkTopology`.

The existing `NetworkTopology.to_dict()` (see `pynetworkintel.topology`) is a
raw dump of the internal nodes/edges/subnets structure. It's fine for
round-tripping through this codebase, but graph-visualization tooling
expects specific, standard shapes:

  - D3.js / vis.js "node-link" JSON: `{"nodes": [{"id": ...}, ...],
    "links": [{"source": ..., "target": ...}, ...]}` - the `links` key (not
    `edges`) and bare `source`/`target` node ids are what these libraries'
    force-directed layouts expect out of the box.
  - GraphML: an XML graph interchange format readable by Gephi, yEd,
    Cytoscape, and most other graph-visualization/analysis tools.

Like `pynetworkintel.topology`, this module is intentionally
dependency-free: GraphML is built with the stdlib `xml.etree.ElementTree`
rather than pulling in networkx/lxml just to serialize a few nodes and
edges.
"""

import json
import logging
from typing import Any, Dict
from xml.dom import minidom
from xml.etree import ElementTree as ET

from pynetworkintel.topology import NetworkTopology

logger = logging.getLogger(__name__)

GRAPHML_NAMESPACE = "http://graphml.graphdrawing.org/xmlns"
GRAPHML_SCHEMA_LOCATION = (
    "http://graphml.graphdrawing.org/xmlns "
    "http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd"
)


def to_node_link_json(topology: NetworkTopology) -> Dict[str, Any]:
    """Convert a NetworkTopology into D3.js / vis.js "node-link" JSON.

    Shape: `{"nodes": [{"id": <ip>, "hostname":..., "node_type":...,
    "subnet":...}, ...], "links": [{"source": <ip>, "target": <ip>,
    "relationship": "gateway"}, ...]}`.

    This differs from `NetworkTopology.to_dict()` in two ways that matter
    to node-link consumers: the edge collection is under the `links` key
    (the conventional name in d3-force / vis-network node-link data), and
    each node carries an `id` field (its IP) rather than relying on an
    `ip` field, since `id` is what d3's default `.id()` accessor and
    vis.js's DataSet both look for.
    """
    nodes = [
        {
            "id": node.ip,
            "hostname": node.hostname,
            "node_type": node.node_type,
            "subnet": node.subnet,
        }
        for node in topology.nodes
    ]
    links = [
        {
            "source": edge.source,
            "target": edge.target,
            "relationship": edge.relationship,
        }
        for edge in topology.edges
    ]
    return {"nodes": nodes, "links": links}


def node_link_json_str(topology: NetworkTopology, indent: int = 2) -> str:
    """Serialize `to_node_link_json()` output to a JSON string."""
    return json.dumps(to_node_link_json(topology), indent=indent)


def to_graphml(topology: NetworkTopology) -> str:
    """Convert a NetworkTopology into a GraphML XML document (as a string).

    Produces a single undirected `<graph>` element with one `<node>` per
    `TopologyNode` and one `<edge>` per `TopologyEdge`, plus `<key>`
    declarations for the node attributes (hostname, node_type, subnet) and
    the edge attribute (relationship) so the file is self-describing for
    tools like Gephi/yEd. Attributes with a `None` value are omitted from
    that node/edge's `<data>` rather than written as the literal string
    "None".
    """
    graphml = ET.Element(
        "graphml",
        {
            "xmlns": GRAPHML_NAMESPACE,
            "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
            "xsi:schemaLocation": GRAPHML_SCHEMA_LOCATION,
        },
    )

    node_keys = {
        "hostname": ("d0", "string"),
        "node_type": ("d1", "string"),
        "subnet": ("d2", "string"),
    }
    edge_keys = {
        "relationship": ("d3", "string"),
    }

    for attr_name, (key_id, attr_type) in node_keys.items():
        ET.SubElement(
            graphml,
            "key",
            {
                "id": key_id,
                "for": "node",
                "attr.name": attr_name,
                "attr.type": attr_type,
            },
        )
    for attr_name, (key_id, attr_type) in edge_keys.items():
        ET.SubElement(
            graphml,
            "key",
            {
                "id": key_id,
                "for": "edge",
                "attr.name": attr_name,
                "attr.type": attr_type,
            },
        )

    graph = ET.SubElement(graphml, "graph", {"id": "G", "edgedefault": "undirected"})

    for node in topology.nodes:
        node_el = ET.SubElement(graph, "node", {"id": node.ip})
        for attr_name, (key_id, _attr_type) in node_keys.items():
            value = getattr(node, attr_name)
            if value is None:
                continue
            data_el = ET.SubElement(node_el, "data", {"key": key_id})
            data_el.text = str(value)

    for index, edge in enumerate(topology.edges):
        edge_el = ET.SubElement(
            graph,
            "edge",
            {"id": f"e{index}", "source": edge.source, "target": edge.target},
        )
        for attr_name, (key_id, _attr_type) in edge_keys.items():
            value = getattr(edge, attr_name)
            if value is None:
                continue
            data_el = ET.SubElement(edge_el, "data", {"key": key_id})
            data_el.text = str(value)

    raw = ET.tostring(graphml, encoding="unicode")
    # Pretty-print via minidom purely for human-readability of the exported
    # file; ET.tostring() alone produces valid but unindented XML.
    pretty = minidom.parseString(raw).toprettyxml(indent="  ")
    # minidom emits an `<?xml version="1.0" ?>` declaration without an
    # encoding; replace it with an explicit UTF-8 declaration and drop the
    # blank lines minidom's pretty-printer tends to leave behind.
    lines = [line for line in pretty.splitlines() if line.strip()]
    lines[0] = '<?xml version="1.0" encoding="UTF-8"?>'
    return "\n".join(lines) + "\n"


def export_topology(topology: NetworkTopology, filename: str, export_format: str) -> None:
    """Export a NetworkTopology to a file in the given format.

    Args:
        topology: The topology to export.
        filename: Path to write to.
        export_format: One of "node-link-json" (D3/vis.js style) or
            "graphml".
    """
    if export_format == "node-link-json":
        content = node_link_json_str(topology)
    elif export_format == "graphml":
        content = to_graphml(topology)
    else:
        raise ValueError(f"Unknown topology export format: {export_format}")

    with open(filename, "w") as f:
        f.write(content)

    logger.info(f"Topology exported to {filename} ({export_format})")
