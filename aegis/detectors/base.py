"""
Base class for all attack detectors.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class Finding:
    """A single security finding from a detector."""
    detector_name: str
    attack_type: str
    severity: str
    match: str
    position: int
    pattern: str = ""
    description: str = ""


class BaseDetector(ABC):
    """Abstract base class that every detector must implement."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name for this detector."""
        ...

    @property
    @abstractmethod
    def attack_type(self) -> str:
        """Type of attack detected."""
        ...

    @property
    @abstractmethod
    def severity(self) -> str:
        """Default severity level."""
        ...

    @abstractmethod
    def analyze(self, payload: str) -> list[Finding]:
        """Analyze a payload and return findings."""
        ...
