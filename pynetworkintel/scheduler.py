"""Background scheduler for continuous monitoring."""

import logging
import signal
import sys
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from threading import Event

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
    from apscheduler.triggers.interval import IntervalTrigger

    SCHEDULER_AVAILABLE = True
except ImportError:
    SCHEDULER_AVAILABLE = False

from pynetworkintel.core import Pipeline
from pynetworkintel.db import Database
from pynetworkintel.changes import ChangeDetector, ChangeReporter
from pynetworkintel.alerts import AlertManager
from pynetworkintel.progress import ProgressIndicator

logger = logging.getLogger(__name__)
progress = ProgressIndicator()


class MonitoringScheduler:
    """Schedule and execute periodic network scans."""

    def __init__(
        self,
        database_url: str = "sqlite:///pynetworkintel.db",
        scan_targets: Optional[Dict[str, str]] = None,
        alert_manager: Optional[AlertManager] = None,
    ):
        if not SCHEDULER_AVAILABLE:
            raise ImportError("APScheduler required for scheduling. Install with: pip install apscheduler")

        self.db = Database(database_url)
        self.db.create_all()

        self.scan_targets = scan_targets or {}
        self.alert_manager = alert_manager or AlertManager(self.db)

        self.scheduler = BackgroundScheduler()
        self.shutdown_event = Event()

        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info("Shutdown signal received, stopping scheduler...")
        self.stop()
        sys.exit(0)

    def add_scan_job(
        self,
        job_id: str,
        target: str,
        schedule_type: str = "interval",
        **schedule_kwargs,
    ):
        """
        Add a scan job to the scheduler.

        Args:
            job_id: Unique job identifier
            target: Network target (IP, CIDR, hostname)
            schedule_type: 'interval' or 'cron'
            schedule_kwargs: Arguments for the trigger (e.g., hours=1 for interval, hour='2' for cron)
        """
        if schedule_type == "interval":
            trigger = IntervalTrigger(**schedule_kwargs)
        elif schedule_type == "cron":
            trigger = CronTrigger(**schedule_kwargs)
        else:
            raise ValueError(f"Unknown schedule type: {schedule_type}")

        self.scheduler.add_job(
            self._run_scan,
            trigger,
            id=job_id,
            args=(target,),
            name=f"Scan {target}",
            replace_existing=True,
        )

        logger.info(f"Added scan job {job_id} for target {target}")

    def _run_scan(self, target: str):
        """Run a single scan."""
        logger.info(f"Starting scheduled scan for {target}")

        try:
            pipeline = Pipeline()
            result = pipeline.run(target, grab_configs=True, summarize=False)

            # Save to database
            self._save_scan_results(target, result)

            # Detect changes
            changes = self._detect_changes(target, result)

            # Generate alerts for critical changes
            self._generate_alerts(target, result, changes)

            logger.info(f"Scan completed for {target}: {result['summary']['total_findings']} findings")

        except Exception as e:
            logger.error(f"Scan failed for {target}: {e}")
            self.alert_manager.create_alert(
                alert_type="scan_failure",
                severity="high",
                title=f"Scan Failed: {target}",
                description=f"Network scan for {target} failed: {str(e)}",
                device_ip=target,
            )

    def _save_scan_results(self, target: str, result: Dict[str, Any]):
        """Save scan results to database."""
        from pynetworkintel.db import ScanSession, Device as DBDevice, Service, Finding as DBFinding

        session = self.db.get_session()

        try:
            # Create scan session
            scan = ScanSession(
                target=target,
                scan_time=datetime.utcnow(),
                duration_seconds=result.get("scan_duration_seconds", 0),
                device_count=result["summary"].get("total_devices", 0),
                finding_count=result["summary"].get("total_findings", 0),
                status="completed",
            )
            session.add(scan)
            session.flush()

            # Save devices
            for device_data in result.get("devices", []):
                device = DBDevice(
                    scan_id=scan.id,
                    ip=device_data["ip"],
                    hostname=device_data.get("hostname"),
                    os=device_data.get("os"),
                    device_type=device_data.get("device_type", "linux"),
                    is_online=device_data.get("is_online", True),
                )
                session.add(device)

            # Save findings
            for finding_data in result.get("findings", []):
                finding = DBFinding(
                    scan_id=scan.id,
                    device_ip=finding_data.get("device", "").split()[0],
                    device_hostname=finding_data.get("device", ""),
                    finding_type=finding_data.get("finding_type", "configuration"),
                    severity=finding_data.get("severity", "info"),
                    title=finding_data.get("title", ""),
                    description=finding_data.get("description", ""),
                    evidence=finding_data.get("evidence", ""),
                    recommendation=finding_data.get("recommendation", ""),
                    business_impact=finding_data.get("business_impact", ""),
                    cve_id=finding_data.get("cve_id"),
                    cvss_score=finding_data.get("cvss_score"),
                )
                session.add(finding)

            session.commit()

        finally:
            session.close()

    def _detect_changes(self, target: str, result: Dict[str, Any]) -> Dict[str, Any]:
        """Detect changes from previous scan."""
        detector = ChangeDetector(self.db)

        # Would compare with previous scan results
        # For now, just return empty
        return {"devices": [], "vulnerabilities": []}

    def _generate_alerts(self, target: str, result: Dict[str, Any], changes: Dict[str, Any]):
        """Generate alerts based on findings and changes."""
        summary = result.get("summary", {})

        # Alert on critical findings
        if summary.get("critical_findings", 0) > 0:
            self.alert_manager.create_alert(
                alert_type="critical_finding",
                severity="critical",
                title=f"Critical Vulnerabilities Found: {target}",
                description=f"Scan of {target} found {summary['critical_findings']} critical issues",
                device_ip=target,
            )

        # Alert on high findings
        if summary.get("high_findings", 0) > 5:
            self.alert_manager.create_alert(
                alert_type="high_findings",
                severity="high",
                title=f"High Priority Issues Found: {target}",
                description=f"Scan of {target} found {summary['high_findings']} high priority issues",
                device_ip=target,
            )

    def start(self):
        """Start the scheduler."""
        if not self.scheduler.running:
            self.scheduler.start()
            logger.info("Monitoring scheduler started")
            progress.success("Scheduler started successfully")

    def stop(self):
        """Stop the scheduler."""
        if self.scheduler.running:
            self.scheduler.shutdown(wait=True)
            logger.info("Monitoring scheduler stopped")
            progress.success("Scheduler stopped successfully")

    def list_jobs(self) -> list:
        """List all scheduled jobs."""
        return self.scheduler.get_jobs()

    def run_foreground(self):
        """Run scheduler in foreground (blocking)."""
        self.start()

        progress.success("Scheduler running in foreground (Ctrl+C to stop)")

        try:
            # Block until interrupted
            self.shutdown_event.wait()
        except KeyboardInterrupt:
            self.stop()
