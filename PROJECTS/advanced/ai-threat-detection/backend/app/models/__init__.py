"""
©AngelaMos | 2026
__init__.py

Models package exporting SQLModel table classes for
ThreatEvent and ModelMetadata
"""

from app.models.model_metadata import ModelMetadata
from app.models.threat_event import ThreatEvent
from app.models.training_state import TrainingState

__all__ = ["ModelMetadata", "ThreatEvent", "TrainingState"]
