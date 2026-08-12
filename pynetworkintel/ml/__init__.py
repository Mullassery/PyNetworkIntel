"""Statistical baseline/anomaly/trend analysis over scan history.

Real, working code, but "ML" is a stretch - this is stdlib `statistics`
(z-scores, rate-of-change), not a trained model, despite being named/
marketed as ML-powered in earlier docs (now corrected). It's a reasonable,
self-contained extension of the analysis phase (flagging deviations from a
device's historical port/service pattern). Lighter test coverage than the
core rule/CVE checkers - see tests/test_ml.py.
"""

from .behavioral import BehavioralBaseline
from .anomaly import AnomalyDetector
from .predictive import PredictiveAnalyzer

__all__ = [
    "BehavioralBaseline",
    "AnomalyDetector",
    "PredictiveAnalyzer",
]
