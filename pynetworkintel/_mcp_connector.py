"""MCP Connector for PyNetworkIntel - Network Security Intelligence"""

import json
import logging
import subprocess
import tempfile
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

try:
    from statguardian._mcp_connector import BaseMCPConnector
except ImportError:
    class BaseMCPConnector(ABC):
        def __init__(self, project_name: str, port: int = 8765):
            self.project_name = project_name
            self.port = port
            self.dab_process: Optional[subprocess.Popen] = None
            self._ready = False

        @abstractmethod
        def get_mcp_tools(self) -> Dict[str, Any]:
            pass

        @abstractmethod
        def get_tool_handlers(self) -> Any:
            pass

        def start_mcp_connector(self) -> str:
            logger.info(f"Starting {self.project_name} MCP...")
            try:
                tools = self.get_mcp_tools()
                self.handler = self.get_tool_handlers()
                config = self._generate_dab_config(tools)
                config_path = self._write_temp_config(config)
                self._start_dab_subprocess(config_path)
                self._ready = True
                return f"http://localhost:{self.port}/mcp"
            except Exception as e:
                logger.error(f"Failed: {e}")
                raise

        def stop_mcp_connector(self):
            if self.dab_process:
                try:
                    self.dab_process.terminate()
                    self.dab_process.wait(timeout=5)
                except (subprocess.TimeoutExpired, OSError):
                    pass
                self._ready = False

        def _generate_dab_config(self, tools: Dict[str, Any]) -> Dict:
            return {
                "runtime": {"host": "0.0.0.0", "port": self.port, "cors": {"origins": ["*"]}},
                "entities": {k: {"source": k, "permissions": [{"actions": ["*"], "roles": ["*"]}]} for k in tools.keys()},
                "rest": {"enabled": True, "path": "/api"},
                "graphql": {"enabled": True, "path": "/graphql"},
                "mcp": {"enabled": True, "path": "/mcp"},
            }

        def _write_temp_config(self, config: Dict) -> str:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
                json.dump(config, f)
                return f.name

        def _start_dab_subprocess(self, config_path: str):
            self.dab_process = subprocess.Popen(
                ["dab", "start", "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

        def is_ready(self) -> bool:
            return self._ready


class NetworkIntelligence:
    """Network security intelligence and threat detection with MCP support"""

    def __init__(self):
        self.mcp_connector: Optional[Any] = None

    def analyze_network_flow(self, flow_id: str) -> dict:
        return {}

    def detect_anomalies(self, sensor_id: str) -> dict:
        return {"anomalies": []}

    def threat_correlation(self, indicators: list) -> dict:
        return {}

    def get_asset_inventory(self, subnet: str) -> dict:
        return {"assets": []}

    def check_port_exposure(self, host: str) -> dict:
        return {"ports": []}

    def analyze_dns_records(self, domain: str) -> dict:
        return {"records": []}

    def get_geolocation_analysis(self, ips: list) -> dict:
        return {}

    def protocol_analysis(self, pcap_id: str) -> dict:
        return {}

    def behavioral_profiling(self, entity_id: str, entity_type: str) -> dict:
        return {}

    def get_threat_intelligence(self, indicator: str) -> dict:
        return {}

    def remediation_recommendations(self, threat_id: str) -> dict:
        return {}

    def network_segmentation_analysis(self, network_id: str) -> dict:
        return {}

    def start_mcp_connector(self, port: int = 8773) -> str:
        from pynetworkintel._mcp_tools import PyNetworkIntelMCPHandler, PyNetworkIntelMCPTools
        self.mcp_connector = _MCPNetworkConnector(network_intel=self, port=port)
        return self.mcp_connector.start_mcp_connector()

    def stop_mcp_connector(self):
        if self.mcp_connector:
            self.mcp_connector.stop_mcp_connector()


class _MCPNetworkConnector(BaseMCPConnector):
    def __init__(self, network_intel: NetworkIntelligence, port: int = 8773):
        super().__init__("PyNetworkIntel", port=port)
        self.network_intel = network_intel

    def get_mcp_tools(self) -> Dict[str, Any]:
        from pynetworkintel._mcp_tools import PyNetworkIntelMCPTools
        return PyNetworkIntelMCPTools.get_tools()

    def get_tool_handlers(self) -> Any:
        from pynetworkintel._mcp_tools import PyNetworkIntelMCPHandler
        return PyNetworkIntelMCPHandler(self.network_intel)
