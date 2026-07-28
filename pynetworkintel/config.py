"""Configuration management for PyNetworkIntel."""

import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

CONFIG_DIR = Path.home() / ".pynetworkintel"
CONFIG_FILE = CONFIG_DIR / "config.yaml"


@dataclass
class SSHConfig:
    username: str = "root"
    key_path: Optional[str] = None
    password: Optional[str] = None
    timeout: int = 10

    def to_dict(self) -> Dict[str, Any]:
        return {
            "username": self.username,
            "key_path": self.key_path,
            "password": self.password,
            "timeout": self.timeout,
        }


@dataclass
class ScanConfig:
    timeout: int = 300
    nmap_args: str = "-sV"
    grab_configs: bool = True
    retry_count: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timeout": self.timeout,
            "nmap_args": self.nmap_args,
            "grab_configs": self.grab_configs,
            "retry_count": self.retry_count,
        }


@dataclass
class AnalysisConfig:
    enable_cve_check: bool = True
    enable_llm_summary: bool = True
    cve_cache_ttl: int = 86400  # 1 day
    llm_model: str = "claude-3-5-sonnet-20241022"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enable_cve_check": self.enable_cve_check,
            "enable_llm_summary": self.enable_llm_summary,
            "cve_cache_ttl": self.cve_cache_ttl,
            "llm_model": self.llm_model,
        }


@dataclass
class OutputConfig:
    format: str = "text"  # text, json, csv
    verbose: bool = False
    color: bool = True
    output_file: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "format": self.format,
            "verbose": self.verbose,
            "color": self.color,
            "output_file": self.output_file,
        }


@dataclass
class AppConfig:
    ssh: SSHConfig = field(default_factory=SSHConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    output: OutputConfig = field(default_factory=OutputConfig)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ssh": self.ssh.to_dict(),
            "scan": self.scan.to_dict(),
            "analysis": self.analysis.to_dict(),
            "output": self.output.to_dict(),
        }


class ConfigManager:
    """Manage PyNetworkIntel configuration."""

    def __init__(self):
        self.config_dir = CONFIG_DIR
        self.config_file = CONFIG_FILE
        self.config = self._load_config()

    def _load_config(self) -> AppConfig:
        """Load configuration from file or use defaults."""
        if self.config_file.exists():
            try:
                with open(self.config_file, "r") as f:
                    data = yaml.safe_load(f) or {}
                return self._parse_config(data)
            except Exception as e:
                logger.warning(f"Failed to load config file: {e}, using defaults")

        return AppConfig()

    def _parse_config(self, data: Dict[str, Any]) -> AppConfig:
        """Parse YAML config data into AppConfig."""
        config = AppConfig()

        if "ssh" in data:
            ssh_data = data["ssh"]
            config.ssh = SSHConfig(
                username=ssh_data.get("username", config.ssh.username),
                key_path=ssh_data.get("key_path"),
                password=ssh_data.get("password"),
                timeout=ssh_data.get("timeout", config.ssh.timeout),
            )

        if "scan" in data:
            scan_data = data["scan"]
            config.scan = ScanConfig(
                timeout=scan_data.get("timeout", config.scan.timeout),
                nmap_args=scan_data.get("nmap_args", config.scan.nmap_args),
                grab_configs=scan_data.get("grab_configs", config.scan.grab_configs),
                retry_count=scan_data.get("retry_count", config.scan.retry_count),
            )

        if "analysis" in data:
            analysis_data = data["analysis"]
            config.analysis = AnalysisConfig(
                enable_cve_check=analysis_data.get("enable_cve_check", config.analysis.enable_cve_check),
                enable_llm_summary=analysis_data.get("enable_llm_summary", config.analysis.enable_llm_summary),
                cve_cache_ttl=analysis_data.get("cve_cache_ttl", config.analysis.cve_cache_ttl),
                llm_model=analysis_data.get("llm_model", config.analysis.llm_model),
            )

        if "output" in data:
            output_data = data["output"]
            config.output = OutputConfig(
                format=output_data.get("format", config.output.format),
                verbose=output_data.get("verbose", config.output.verbose),
                color=output_data.get("color", config.output.color),
                output_file=output_data.get("output_file"),
            )

        return config

    def save_config(self, config: AppConfig):
        """Save configuration to file."""
        self.config_dir.mkdir(parents=True, exist_ok=True)

        with open(self.config_file, "w") as f:
            yaml.dump(config.to_dict(), f, default_flow_style=False)

        logger.info(f"Config saved to {self.config_file}")

    def create_default_config(self):
        """Create default configuration file."""
        config = AppConfig()
        self.save_config(config)
        logger.info(f"Created default config at {self.config_file}")

    def update_from_env(self):
        """Update configuration from environment variables."""
        if api_key := os.getenv("ANTHROPIC_API_KEY"):
            # API key is handled separately
            pass

        if ssh_user := os.getenv("PYNETWORKINTEL_SSH_USER"):
            self.config.ssh.username = ssh_user

        if ssh_key := os.getenv("PYNETWORKINTEL_SSH_KEY"):
            self.config.ssh.key_path = ssh_key

        if ssh_pass := os.getenv("PYNETWORKINTEL_SSH_PASSWORD"):
            self.config.ssh.password = ssh_pass

    @staticmethod
    def get_default_config() -> AppConfig:
        """Get default configuration."""
        return AppConfig()
