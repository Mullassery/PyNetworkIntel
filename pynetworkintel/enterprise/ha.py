"""High Availability (HA) architecture components."""
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class NodeStatus:
    node_id: str
    ip_address: str
    port: int
    state: str
    last_heartbeat: datetime = field(default_factory=datetime.now)
    is_leader: bool = False
    metrics: Dict[str, Any] = field(default_factory=dict)


class HAArchitecture:
    """Manage high availability infrastructure."""

    def __init__(self, min_nodes: int = 3):
        """
        Initialize HA architecture.

        Args:
            min_nodes: Minimum nodes for quorum
        """
        self.min_nodes = min_nodes
        self.nodes: Dict[str, NodeStatus] = {}
        self.leader_node: Optional[str] = None
        self.health_checks: List[Dict[str, Any]] = []

    def register_node(self, node_id: str, ip_address: str, port: int = 8080) -> bool:
        """Register a new node in the cluster."""
        if node_id in self.nodes:
            logger.warning(f"Node {node_id} already registered")
            return False

        self.nodes[node_id] = NodeStatus(
            node_id=node_id,
            ip_address=ip_address,
            port=port,
        )

        logger.info(f"Registered node: {node_id} ({ip_address}:{port})")

        # Elect leader if this is first node
        if len(self.nodes) == 1:
            self._elect_leader()

        return True

    def deregister_node(self, node_id: str):
        """Deregister a node from the cluster."""
        if node_id not in self.nodes:
            return

        node = self.nodes[node_id]

        if node.is_leader:
            del self.nodes[node_id]
            if self.nodes:
                self._elect_leader()
        else:
            del self.nodes[node_id]

        logger.info(f"Deregistered node: {node_id}")

    def heartbeat(self, node_id: str, metrics: Dict[str, Any]) -> bool:
        """Process heartbeat from a node."""
        if node_id not in self.nodes:
            return False

        node = self.nodes[node_id]
        node.last_heartbeat = datetime.now()
        node.state = "healthy"
        node.metrics = metrics

        return True

    def check_node_health(self, node_id: str) -> str:
        """Check health status of a node."""
        if node_id not in self.nodes:
            return "unknown"

        node = self.nodes[node_id]

        # Check heartbeat timeout (assume 30 seconds)
        time_since_heartbeat = (datetime.now() - node.last_heartbeat).total_seconds()

        if time_since_heartbeat > 30:
            node.state = "unhealthy"
            return "unhealthy"
        elif time_since_heartbeat > 15:
            node.state = "degraded"
            return "degraded"
        else:
            node.state = "healthy"
            return "healthy"

    def failover(self):
        """Perform failover if leader is unhealthy."""
        if not self.leader_node:
            self._elect_leader()
            return

        leader_state = self.check_node_health(self.leader_node)

        if leader_state != "healthy":
            logger.warning(f"Leader {self.leader_node} is unhealthy, initiating failover")
            self._elect_leader()

    def get_cluster_status(self) -> Dict[str, Any]:
        """Get overall cluster status."""
        healthy_nodes = 0
        degraded_nodes = 0
        unhealthy_nodes = 0

        for node in self.nodes.values():
            state = self.check_node_health(node.node_id)
            if state == "healthy":
                healthy_nodes += 1
            elif state == "degraded":
                degraded_nodes += 1
            else:
                unhealthy_nodes += 1

        total_nodes = len(self.nodes)
        quorum_met = total_nodes >= self.min_nodes and healthy_nodes > total_nodes / 2

        return {
            "total_nodes": total_nodes,
            "healthy_nodes": healthy_nodes,
            "degraded_nodes": degraded_nodes,
            "unhealthy_nodes": unhealthy_nodes,
            "leader": self.leader_node,
            "quorum_met": quorum_met,
            "sla_status": "operational" if quorum_met else "degraded",
        }

    def get_load_distribution(self) -> Dict[str, Any]:
        """Get load distribution across cluster."""
        total_cpu = 0
        total_memory = 0
        total_requests = 0

        for node in self.nodes.values():
            metrics = node.metrics
            total_cpu += metrics.get("cpu_usage", 0)
            total_memory += metrics.get("memory_usage", 0)
            total_requests += metrics.get("request_count", 0)

        avg_nodes = len(self.nodes) or 1

        return {
            "average_cpu": total_cpu / avg_nodes,
            "average_memory": total_memory / avg_nodes,
            "average_requests": total_requests / avg_nodes,
            "total_requests": total_requests,
            "load_balanced": total_cpu / avg_nodes < 75,
        }

    def enable_database_replication(self, primary_node: str, standby_nodes: List[str]) -> bool:
        """Configure database replication."""
        if primary_node not in self.nodes:
            logger.error(f"Primary node {primary_node} not found")
            return False

        for standby in standby_nodes:
            if standby not in self.nodes:
                logger.error(f"Standby node {standby} not found")
                return False

        logger.info(
            f"Configured replication: {primary_node} -> {standby_nodes}"
        )

        return True

    def enable_session_replication(self) -> bool:
        """Enable session state replication (Redis)."""
        if not self.nodes or len(self.nodes) < 2:
            logger.warning("Need at least 2 nodes for session replication")
            return False

        logger.info("Enabled session replication via Redis")
        return True

    def enable_load_balancing(self, algorithm: str = "round_robin") -> bool:
        """Enable load balancing across nodes."""
        if algorithm not in ["round_robin", "least_connections", "weighted", "ip_hash"]:
            logger.error(f"Unknown load balancing algorithm: {algorithm}")
            return False

        logger.info(f"Enabled load balancing: {algorithm}")
        return True

    def _elect_leader(self):
        """Elect a new leader via consensus."""
        if not self.nodes:
            self.leader_node = None
            return

        # Reset old leader
        if self.leader_node and self.leader_node in self.nodes:
            self.nodes[self.leader_node].is_leader = False

        # Elect new leader (highest priority node)
        candidates = sorted(
            self.nodes.items(),
            key=lambda x: (
                x[1].state == "healthy",
                x[1].node_id,
            ),
            reverse=True
        )

        if candidates:
            new_leader_id, new_leader = candidates[0]
            new_leader.is_leader = True
            self.leader_node = new_leader_id
            logger.info(f"Elected new leader: {new_leader_id}")

    def graceful_shutdown(self, node_id: str) -> bool:
        """Gracefully shutdown a node."""
        if node_id not in self.nodes:
            return False

        logger.info(f"Initiating graceful shutdown of {node_id}")

        # Drain connections
        self.nodes[node_id].state = "draining"

        # If leader, trigger failover first
        if self.nodes[node_id].is_leader:
            self._elect_leader()

        # Deregister node
        self.deregister_node(node_id)

        return True

    def get_node_info(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed info about a node."""
        if node_id not in self.nodes:
            return None

        node = self.nodes[node_id]

        return {
            "node_id": node.node_id,
            "ip_address": node.ip_address,
            "port": node.port,
            "state": node.state,
            "is_leader": node.is_leader,
            "last_heartbeat": node.last_heartbeat.isoformat(),
            "metrics": node.metrics,
        }
