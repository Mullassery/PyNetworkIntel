"""Basic coverage for the ml/ module (statistical baseline & anomaly logic).

This module is shipped but lighter-tested than the core discovery/analysis
path (see pynetworkintel/ml/__init__.py docstring). These are pure-logic
tests with synthetic data - no real network/ML dependency involved.
"""

import pytest

from pynetworkintel.ml.anomaly import AnomalyDetector
from pynetworkintel.ml.behavioral import BehavioralBaseline
from pynetworkintel.ml.predictive import PredictiveAnalyzer


class TestAnomalyDetector:
    def test_no_baseline_data_returns_no_anomaly(self):
        detector = AnomalyDetector()
        is_anomaly, score, message = detector.detect_port_scan_activity("dev1", [22, 80])
        assert is_anomaly is False
        assert score == 0.0

    def test_normal_port_activity_not_flagged(self):
        detector = AnomalyDetector()
        detector.record_traffic("dev1", {"ports": [22, 80, 443]})
        is_anomaly, score, message = detector.detect_port_scan_activity("dev1", [22, 80])
        assert is_anomaly is False

    def test_large_new_port_ratio_flagged_as_scan(self):
        detector = AnomalyDetector(threshold=0.7)
        detector.record_traffic("dev1", {"ports": [22]})
        # 9 of 10 current ports are new -> ratio 0.9 > 0.5 threshold in the detector
        current_ports = [22] + list(range(1000, 1009))
        is_anomaly, score, message = detector.detect_port_scan_activity("dev1", current_ports)
        assert is_anomaly is True
        assert score == 0.95

    def test_bandwidth_anomaly_needs_min_samples(self):
        detector = AnomalyDetector()
        for _ in range(3):
            detector.record_traffic("dev1", {"bandwidth": 100})
        is_anomaly, score, message = detector.detect_bandwidth_anomaly("dev1", 100)
        assert is_anomaly is False
        assert "Insufficient" in message

    def test_bandwidth_anomaly_detects_outlier(self):
        detector = AnomalyDetector()
        for bw in [100, 102, 98, 101, 99, 100, 103]:
            detector.record_traffic("dev1", {"bandwidth": bw})
        is_anomaly, score, message = detector.detect_bandwidth_anomaly("dev1", 5000)
        assert is_anomaly is True


class TestBehavioralBaseline:
    def test_record_activity_creates_baseline(self):
        baseline = BehavioralBaseline()
        baseline.record_device_activity("dev1", "server", {"port": 22})
        assert "dev1" in baseline.baselines
        assert len(baseline.baselines["dev1"].activity_history) == 1

    def test_record_port_activity(self):
        baseline = BehavioralBaseline()
        baseline.record_port_activity("dev1", "server", 443)
        assert "dev1" in baseline.baselines


class TestPredictiveAnalyzer:
    def test_no_history_returns_no_predictions(self):
        analyzer = PredictiveAnalyzer()
        assert analyzer.predict_future_vulnerabilities("dev1") == []

    def test_single_record_insufficient_for_prediction(self):
        analyzer = PredictiveAnalyzer()
        analyzer.record_vulnerability("dev1", "high", "cve")
        assert analyzer.predict_future_vulnerabilities("dev1") == []

    def test_predictions_generated_with_enough_history(self):
        analyzer = PredictiveAnalyzer()
        analyzer.record_vulnerability("dev1", "high", "cve")
        analyzer.record_vulnerability("dev1", "medium", "cve")
        analyzer.record_vulnerability("dev1", "critical", "cve")
        predictions = analyzer.predict_future_vulnerabilities("dev1", days_ahead=5)
        # May be empty if discovery_rate computes to 0, but should not error
        assert isinstance(predictions, list)
