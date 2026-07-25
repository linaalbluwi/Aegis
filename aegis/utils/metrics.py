"""
Prometheus metrics for Aegis monitoring.
"""
from prometheus_client import Counter, Gauge, Histogram, generate_latest, REGISTRY
from typing import Optional


# Attack metrics
attacks_blocked_total = Counter(
    'aegis_attacks_blocked_total',
    'Total number of attacks blocked',
    ['attack_type', 'severity']
)

requests_total = Counter(
    'aegis_requests_total',
    'Total number of requests processed',
    ['method', 'endpoint', 'status']
)

# Token optimization metrics
tokens_saved_total = Counter(
    'aegis_tokens_saved_total',
    'Total number of tokens saved',
    ['source']
)

tokens_saved_bytes = Counter(
    'aegis_tokens_saved_bytes',
    'Total bytes saved by token optimization',
)

# Rate limiting metrics
rate_limits_triggered = Counter(
    'aegis_rate_limits_triggered',
    'Total number of rate limits triggered',
    ['ip']
)

# Performance metrics
request_duration = Histogram(
    'aegis_request_duration_seconds',
    'Request processing duration in seconds',
    ['method', 'endpoint']
)

# System metrics
active_detectors = Gauge(
    'aegis_active_detectors',
    'Number of active attack detectors',
)

cache_size = Gauge(
    'aegis_token_cache_size',
    'Number of entries in token cache',
)


class Metrics:
    """Helper class to track and export Aegis metrics."""

    def __init__(self):
        self._detector_count = 0

    def set_active_detectors(self, count: int):
        active_detectors.set(count)

    def record_attack(self, attack_type: str, severity: str):
        attacks_blocked_total.labels(
            attack_type=attack_type,
            severity=severity
        ).inc()

    def record_request(self, method: str, endpoint: str, status: int):
        requests_total.labels(
            method=method,
            endpoint=endpoint,
            status=str(status)
        ).inc()

    def record_tokens_saved(self, count: int, source: str = "optimizer"):
        tokens_saved_total.labels(source=source).inc(count)

    def record_rate_limit(self, ip: str):
        rate_limits_triggered.labels(ip=ip).inc()

    def set_cache_size(self, size: int):
        cache_size.set(size)

    def get_metrics(self) -> bytes:
        """Export all metrics in Prometheus format."""
        return generate_latest(REGISTRY)


# Global instance
metrics = Metrics()
