"""
Cloud resilience patterns: Circuit Breaker, Retry with Backoff, Graceful Degradation.
"""
import time
import asyncio
import logging
from enum import Enum
from typing import Optional


# Stdout logger for K8s container logging
logger = logging.getLogger("aegis")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(
    '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s"}'
))
logger.addHandler(handler)


class CircuitState(Enum):
    CLOSED = "closed"         # Normal operation
    OPEN = "open"             # Failing, reject requests
    HALF_OPEN = "half_open"   # Testing if recovered


class CircuitBreaker:
    """
    Circuit Breaker pattern.
    - CLOSED: Requests pass through normally
    - OPEN: Requests fail immediately (backend is dead)
    - HALF_OPEN: One test request to check if backend recovered
    """

    def __init__(self, name: str, failure_threshold: int = 5, recovery_timeout: float = 30.0):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time: float = 0
        self.success_count = 0

    def record_success(self):
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= 2:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                logger.info(f"Circuit {self.name}: CLOSED (recovered)")
        elif self.state == CircuitState.CLOSED:
            self.failure_count = 0

    def record_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.monotonic()

        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.OPEN
            logger.warning(f"Circuit {self.name}: OPEN (half-open test failed)")
        elif self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN
            logger.warning(f"Circuit {self.name}: OPEN ({self.failure_count} failures)")

    def allow_request(self) -> bool:
        if self.state == CircuitState.CLOSED:
            return True

        if self.state == CircuitState.OPEN:
            if time.monotonic() - self.last_failure_time > self.recovery_timeout:
                self.state = CircuitState.HALF_OPEN
                self.success_count = 0
                logger.info(f"Circuit {self.name}: HALF_OPEN (testing recovery)")
                return True
            return False

        # HALF_OPEN — allow limited requests
        return self.success_count < 2


async def retry_with_backoff(
    func,
    max_retries: int = 3,
    base_delay: float = 0.1,
    max_delay: float = 2.0,
    circuit_breaker: Optional[CircuitBreaker] = None,
):
    """
    Retry with exponential backoff.
    Delays: 0.1s, 0.4s, 1.6s (base_delay * 2^attempt)
    """
    last_exception = None

    for attempt in range(max_retries + 1):
        try:
            if circuit_breaker and not circuit_breaker.allow_request():
                raise Exception("Circuit breaker is OPEN")

            result = await func()

            if circuit_breaker:
                circuit_breaker.record_success()

            return result

        except Exception as e:
            last_exception = e

            if circuit_breaker:
                circuit_breaker.record_failure()

            if attempt < max_retries:
                delay = min(base_delay * (2 ** attempt), max_delay)
                logger.warning(f"Retry {attempt + 1}/{max_retries} after {delay:.2f}s: {str(e)[:100]}")
                await asyncio.sleep(delay)

    raise last_exception


class FailOpenGate:
    """
    Graceful degradation: if Aegis is overwhelmed, allow requests through
    rather than blocking everything (fail-open mode).
    """

    def __init__(self, max_concurrent: int = 100, degrade_after_pct: float = 0.8):
        self.max_concurrent = max_concurrent
        self.degrade_after_pct = degrade_after_pct
        self.current_requests = 0
        self.degraded = False

    def acquire(self) -> bool:
        """Try to acquire capacity. Returns True if request can proceed with full security."""
        if self.current_requests >= self.max_concurrent * self.degrade_after_pct:
            if self.current_requests >= self.max_concurrent:
                self.degraded = True
                logger.warning("FAIL-OPEN: Too many concurrent requests, bypassing security checks")
                return False  # Fail-open: allow request without security
            self.degraded = True
            return True  # Degraded but still checking

        self.current_requests += 1
        return True

    def release(self):
        if self.current_requests > 0:
            self.current_requests -= 1

    def is_degraded(self) -> bool:
        return self.degraded
