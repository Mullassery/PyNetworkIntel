"""Alerting system for security findings and changes."""

import logging
import json
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable
from abc import ABC, abstractmethod
from sqlalchemy.orm import Session

from pynetworkintel.db import Database, Alert as DBAlert

logger = logging.getLogger(__name__)


class AlertChannel(ABC):
    """Base class for alert channels."""

    @abstractmethod
    def send(self, alert: Dict[str, Any]) -> bool:
        """Send alert through channel. Returns True if successful."""
        pass


class SlackAlertChannel(AlertChannel):
    """Send alerts to Slack."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send(self, alert: Dict[str, Any]) -> bool:
        """Send alert to Slack via webhook."""
        try:
            import requests

            severity_colors = {
                "critical": "#FF0000",
                "high": "#FF6600",
                "medium": "#FFCC00",
                "low": "#00CC00",
                "info": "#0099FF",
            }

            severity = alert.get("severity", "info").lower()
            color = severity_colors.get(severity, "#999999")

            payload = {
                "attachments": [
                    {
                        "color": color,
                        "title": alert.get("title", "Security Alert"),
                        "text": alert.get("description", ""),
                        "fields": [
                            {"title": "Severity", "value": severity.upper(), "short": True},
                            {"title": "Device", "value": alert.get("device_ip", "unknown"), "short": True},
                            {"title": "Type", "value": alert.get("alert_type", "unknown"), "short": True},
                        ],
                        "footer": "PyNetworkIntel",
                        "ts": int(datetime.utcnow().timestamp()),
                    }
                ]
            }

            response = requests.post(self.webhook_url, json=payload, timeout=10)
            return response.status_code == 200

        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")
            return False


class EmailAlertChannel(AlertChannel):
    """Send alerts via email."""

    def __init__(self, smtp_server: str, smtp_port: int, sender: str, recipients: List[str], password: str = ""):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender = sender
        self.recipients = recipients
        self.password = password

    def send(self, alert: Dict[str, Any]) -> bool:
        """Send alert via email."""
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart

            severity = alert.get("severity", "INFO").upper()
            subject = f"[{severity}] {alert.get('title', 'Security Alert')}"

            body = f"""
PyNetworkIntel Security Alert

Type: {alert.get('alert_type', 'Unknown')}
Severity: {severity}
Device: {alert.get('device_ip', 'Unknown')}
Title: {alert.get('title', 'N/A')}

Description:
{alert.get('description', 'No description')}

Time: {datetime.utcnow().isoformat()}
"""

            message = MIMEMultipart()
            message["From"] = self.sender
            message["To"] = ", ".join(self.recipients)
            message["Subject"] = subject
            message.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.password:
                    server.starttls()
                    server.login(self.sender, self.password)
                server.send_message(message)

            return True

        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False


class WebhookAlertChannel(AlertChannel):
    """Send alerts via generic webhook."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send(self, alert: Dict[str, Any]) -> bool:
        """Send alert to webhook."""
        try:
            import requests

            payload = json.dumps(alert, default=str)
            response = requests.post(
                self.webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            return response.status_code in (200, 201, 202)

        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")
            return False


class AlertManager:
    """Manage alert channels and routing."""

    def __init__(self, db: Database):
        self.db = db
        self.channels: Dict[str, AlertChannel] = {}
        self.rules: List[Dict[str, Any]] = []

    def add_channel(self, name: str, channel: AlertChannel):
        """Add an alert channel."""
        self.channels[name] = channel
        logger.info(f"Registered alert channel: {name}")

    def add_rule(self, rule: Dict[str, Any]):
        """
        Add alert routing rule.

        Example:
            {
                "condition": "severity == 'critical'",
                "channels": ["slack", "email"],
                "enabled": True
            }
        """
        self.rules.append(rule)

    def create_alert(
        self,
        alert_type: str,
        severity: str,
        title: str,
        description: str,
        device_ip: Optional[str] = None,
        cve_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Create and send alert."""
        alert = {
            "alert_type": alert_type,
            "severity": severity,
            "title": title,
            "description": description,
            "device_ip": device_ip,
            "cve_id": cve_id,
            "created_at": datetime.utcnow().isoformat(),
        }

        # Save to database
        self._save_alert(alert)

        # Send through channels
        self._send_alert(alert)

        return alert

    def _send_alert(self, alert: Dict[str, Any]):
        """Send alert through appropriate channels."""
        # Determine which channels to use (simple routing based on severity)
        severity_map = {
            "critical": ["slack", "email"],
            "high": ["slack", "email"],
            "medium": ["slack"],
            "low": ["email"],
            "info": [],
        }

        severity = alert.get("severity", "info").lower()
        channel_names = severity_map.get(severity, [])

        for channel_name in channel_names:
            if channel_name in self.channels:
                try:
                    self.channels[channel_name].send(alert)
                except Exception as e:
                    logger.error(f"Error sending alert via {channel_name}: {e}")

    def _save_alert(self, alert: Dict[str, Any]):
        """Save alert to database."""
        session = self.db.get_session()

        try:
            db_alert = DBAlert(
                alert_type=alert.get("alert_type"),
                severity=alert.get("severity"),
                title=alert.get("title"),
                description=alert.get("description"),
                device_ip=alert.get("device_ip"),
                cve_id=alert.get("cve_id"),
                status="pending",
            )
            session.add(db_alert)
            session.commit()

        finally:
            session.close()

    def get_pending_alerts(self) -> List[Dict[str, Any]]:
        """Get all pending alerts."""
        session = self.db.get_session()

        try:
            alerts = session.query(DBAlert).filter(DBAlert.status == "pending").all()
            return [
                {
                    "id": a.id,
                    "alert_type": a.alert_type,
                    "severity": a.severity,
                    "title": a.title,
                    "created_at": a.created_at,
                }
                for a in alerts
            ]

        finally:
            session.close()

    def acknowledge_alert(self, alert_id: int):
        """Mark alert as acknowledged."""
        session = self.db.get_session()

        try:
            alert = session.query(DBAlert).filter(DBAlert.id == alert_id).first()
            if alert:
                alert.acknowledged_at = datetime.utcnow()
                alert.status = "acknowledged"
                session.commit()

        finally:
            session.close()
