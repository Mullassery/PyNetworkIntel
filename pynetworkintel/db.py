"""Database models and ORM configuration."""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Float, ForeignKey, Text, JSON, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from sqlalchemy.pool import StaticPool

Base = declarative_base()


class ScanSession(Base):
    """Represents a network scan execution."""

    __tablename__ = "scan_sessions"

    id = Column(Integer, primary_key=True)
    scan_time = Column(DateTime, default=datetime.utcnow, index=True)
    duration_seconds = Column(Float)
    target = Column(String(255))
    device_count = Column(Integer, default=0)
    finding_count = Column(Integer, default=0)
    status = Column(String(50), default="completed")  # completed, failed, in_progress
    error_message = Column(Text, nullable=True)

    devices = relationship("Device", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (Index("idx_scan_time", "scan_time"), Index("idx_target", "target"))


class Device(Base):
    """Network device discovered during scan."""

    __tablename__ = "devices"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scan_sessions.id"), index=True)
    ip = Column(String(45), index=True)  # IPv4 or IPv6
    hostname = Column(String(255), nullable=True)
    os = Column(String(255), nullable=True)
    device_type = Column(String(50), default="linux")
    is_online = Column(Boolean, default=True)
    last_seen = Column(DateTime, default=datetime.utcnow, index=True)
    first_seen = Column(DateTime, default=datetime.utcnow)

    scan = relationship("ScanSession", back_populates="devices")
    services = relationship("Service", back_populates="device", cascade="all, delete-orphan")
    configs = relationship("DeviceConfig", back_populates="device", cascade="all, delete-orphan")

    __table_args__ = (Index("idx_device_ip_scan", "ip", "scan_id"),)


class Service(Base):
    """Network service running on a device."""

    __tablename__ = "services"

    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey("devices.id"), index=True)
    port = Column(Integer)
    name = Column(String(100))
    version = Column(String(255), nullable=True)
    protocol = Column(String(10), default="tcp")
    state = Column(String(50), default="open")
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    device = relationship("Device", back_populates="services")

    __table_args__ = (Index("idx_service_device_port", "device_id", "port"),)


class DeviceConfig(Base):
    """Configuration file content from device."""

    __tablename__ = "device_configs"

    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey("devices.id"), index=True)
    path = Column(String(500))
    content = Column(Text)
    device_type = Column(String(50))
    captured_at = Column(DateTime, default=datetime.utcnow)

    device = relationship("Device", back_populates="configs")


class Finding(Base):
    """Security finding from analysis."""

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scan_sessions.id"), index=True)
    device_ip = Column(String(45), index=True)
    device_hostname = Column(String(255), nullable=True)
    finding_type = Column(String(50))  # configuration, cve, exposure, performance
    severity = Column(String(20), index=True)  # critical, high, medium, low, info
    title = Column(String(500))
    description = Column(Text)
    evidence = Column(Text)
    recommendation = Column(Text)
    business_impact = Column(Text)
    cve_id = Column(String(50), nullable=True, index=True)
    cvss_score = Column(Float, nullable=True)
    exploit_available = Column(Boolean, default=False)
    found_at = Column(DateTime, default=datetime.utcnow, index=True)
    resolved_at = Column(DateTime, nullable=True)

    scan = relationship("ScanSession", back_populates="findings")

    __table_args__ = (
        Index("idx_finding_severity_scan", "severity", "scan_id"),
        Index("idx_finding_device_ip", "device_ip"),
    )


class VulnerabilityChange(Base):
    """Track when vulnerabilities appear/disappear."""

    __tablename__ = "vulnerability_changes"

    id = Column(Integer, primary_key=True)
    device_ip = Column(String(45), index=True)
    cve_id = Column(String(50), index=True)
    title = Column(String(500))
    appeared_at = Column(DateTime, default=datetime.utcnow, index=True)
    resolved_at = Column(DateTime, nullable=True)
    severity = Column(String(20))

    __table_args__ = (Index("idx_vuln_device_cve", "device_ip", "cve_id"),)


class DeviceChange(Base):
    """Track device inventory changes."""

    __tablename__ = "device_changes"

    id = Column(Integer, primary_key=True)
    ip = Column(String(45), index=True)
    hostname = Column(String(255), nullable=True)
    change_type = Column(String(50))  # discovered, removed, online, offline
    detected_at = Column(DateTime, default=datetime.utcnow, index=True)
    details = Column(JSON, nullable=True)

    __table_args__ = (Index("idx_device_change_ip", "ip"),)


class Alert(Base):
    """Security alert/notification."""

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)
    alert_type = Column(String(50))  # new_vulnerability, device_offline, config_change
    severity = Column(String(20))
    title = Column(String(500))
    description = Column(Text)
    device_ip = Column(String(45), nullable=True)
    cve_id = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    sent_at = Column(DateTime, nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    status = Column(String(50), default="pending")  # pending, sent, acknowledged, resolved

    __table_args__ = (
        Index("idx_alert_status", "status"),
        Index("idx_alert_created", "created_at"),
    )


class Database:
    """Database connection and session management."""

    def __init__(self, database_url: str = "sqlite:///pynetworkintel.db"):
        self.database_url = database_url
        self.engine = create_engine(
            database_url,
            echo=False,
            # Use StaticPool for SQLite to avoid threading issues
            poolclass=StaticPool if database_url.startswith("sqlite") else None,
        )
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

    def create_all(self):
        """Create all database tables."""
        Base.metadata.create_all(bind=self.engine)

    def get_session(self) -> Session:
        """Get a new database session."""
        return self.SessionLocal()

    def close(self):
        """Close all connections."""
        self.engine.dispose()


# Singleton database instance
_db_instance: Optional[Database] = None


def init_db(database_url: str = "sqlite:///pynetworkintel.db") -> Database:
    """Initialize database singleton."""
    global _db_instance
    _db_instance = Database(database_url)
    _db_instance.create_all()
    return _db_instance


def get_db() -> Database:
    """Get singleton database instance."""
    global _db_instance
    if _db_instance is None:
        _db_instance = Database()
        _db_instance.create_all()
    return _db_instance
