"""
Service Level Objectives tracking for Aegis.
"""
import time
from dataclasses import dataclass, field


@dataclass
class SLO:
    """A single Service Level Objective."""
    name: str
    target_pct: float
    window_seconds: float
    good_events: int = 0
    bad_events: int = 0
    last_reset: float = field(default_factory=time.monotonic)

    def record_good(self):
        self.good_events += 1

    def record_bad(self):
        self.bad_events += 1

    @property
    def total(self) -> int:
        return self.good_events + self.bad_events

    @property
    def current_pct(self) -> float:
        if self.total == 0:
            return 100.0
        return (self.good_events / self.total) * 100

    @property
    def meets_target(self) -> bool:
        return self.current_pct >= self.target_pct

    @property
    def error_budget_remaining(self) -> float:
        """How much error budget is left (as percentage of total events)."""
        if self.total == 0:
            return self.target_pct
        max_bad = (100 - self.target_pct) / 100 * self.total
        used = self.bad_events
        return max(0, max_bad - used)

    @property
    def error_budget_pct_remaining(self) -> float:
        """Error budget remaining as percentage of original budget."""
        if self.total == 0:
            return 100.0
        max_bad = (100 - self.target_pct) / 100 * self.total
        if max_bad == 0:
            return 0.0
        return (self.error_budget_remaining / max_bad) * 100

    def maybe_reset(self):
        """Reset counters if the window has passed."""
        if time.monotonic() - self.last_reset > self.window_seconds:
            self.good_events = 0
            self.bad_events = 0
            self.last_reset = time.monotonic()


# Aegis SLOs
availability_slo = SLO(
    name="availability",
    target_pct=99.9,
    window_seconds=30 * 24 * 3600,  # 30 days
)

latency_slo = SLO(
    name="latency_p95",
    target_pct=95.0,
    window_seconds=30 * 24 * 3600,
)

detection_slo = SLO(
    name="attack_detection",
    target_pct=99.0,
    window_seconds=30 * 24 * 3600,
)

false_positive_slo = SLO(
    name="false_positive_rate",
    target_pct=99.9,
    window_seconds=30 * 24 * 3600,
)

ALL_SLOS = [availability_slo, latency_slo, detection_slo, false_positive_slo]


def get_slo_report() -> dict:
    """Generate SLO status report."""
    for slo in ALL_SLOS:
        slo.maybe_reset()

    return {
        slo.name: {
            "target": f"{slo.target_pct}%",
            "current": f"{slo.current_pct:.2f}%",
            "meets_target": slo.meets_target,
            "error_budget_remaining": f"{slo.error_budget_pct_remaining:.1f}%",
            "total_events": slo.total,
        }
        for slo in ALL_SLOS
    }
