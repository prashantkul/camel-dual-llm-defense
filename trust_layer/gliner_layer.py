"""
GLiNER2 integration layer for fast, local entity/intent/safety classification.

Optional dependency — all methods return None when gliner2 is not installed.
The pipeline gracefully falls back to existing heuristics or LLM-based processing.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Optional

try:
  from gliner2 import GLiNER2

  GLINER_AVAILABLE = True
except ImportError:
  GLINER_AVAILABLE = False

from trust_layer.capability_tokens import TravelIntent

# Label → TravelIntent mapping
_INTENT_LABEL_MAP: dict[str, str] = {
  "car_rental": TravelIntent.SEARCH_CAR.value,
  "flight_search": TravelIntent.SEARCH_FLIGHTS.value,
  "payment": TravelIntent.PROCESS_PAYMENT.value,
  "cancellation": TravelIntent.CANCEL_BOOKING.value,
  "itinerary": TravelIntent.GET_ITINERARY.value,
}

_INTENT_LABELS = list(_INTENT_LABEL_MAP.keys())
_ENTITY_LABELS = ["location", "date", "car_class", "person_name"]
_SAFETY_LABELS = ["legitimate_request", "prompt_injection", "sql_injection", "data_exfiltration"]
_RESPONSE_SCAN_LABELS = [
  "clean_data",
  "injection_attempt",
  "data_exfiltration",
  "suspicious_content",
]

# Confidence thresholds
INTENT_THRESHOLD = 0.5
SAFETY_THRESHOLD = 0.6
RESPONSE_SCAN_THRESHOLD = 0.7


@dataclass
class ClassificationResult:
  label: str
  confidence: float


@dataclass
class EntityResult:
  text: str
  label: str
  confidence: float


class GLiNERLayer:
  """Singleton wrapper around GLiNER2 for travel-domain classification."""

  _instance: Optional[GLiNERLayer] = None
  _lock = threading.Lock()

  def __init__(self) -> None:
    self._model: Any = None
    self._loaded = False

  @classmethod
  def get_instance(cls) -> GLiNERLayer:
    if cls._instance is None:
      with cls._lock:
        if cls._instance is None:
          cls._instance = cls()
    return cls._instance

  @classmethod
  def reset_instance(cls) -> None:
    """Reset singleton — for testing only."""
    with cls._lock:
      cls._instance = None

  def is_available(self) -> bool:
    return GLINER_AVAILABLE

  def _ensure_loaded(self) -> bool:
    if not GLINER_AVAILABLE:
      return False
    if not self._loaded:
      self._model = GLiNER2.from_pretrained("gliner-community/gliner-v2.5-v2")
      self._loaded = True
    return True

  def classify_intent(self, text: str) -> Optional[ClassificationResult]:
    """Classify travel intent. Returns None if gliner2 not available."""
    if not self._ensure_loaded():
      return None

    results = self._model.predict(text, _INTENT_LABELS, threshold=INTENT_THRESHOLD)
    if not results:
      return None

    best = max(results, key=lambda r: r["score"])
    mapped_label = _INTENT_LABEL_MAP.get(best["label"], best["label"])
    return ClassificationResult(label=mapped_label, confidence=best["score"])

  def extract_entities(self, text: str) -> Optional[list[EntityResult]]:
    """Extract travel entities (locations, dates, car class). Returns None if unavailable."""
    if not self._ensure_loaded():
      return None

    results = self._model.predict(text, _ENTITY_LABELS, threshold=0.3)
    return [
      EntityResult(text=r["text"], label=r["label"], confidence=r["score"]) for r in results
    ]

  def classify_safety(self, text: str) -> Optional[ClassificationResult]:
    """Classify injection risk. Returns None if unavailable."""
    if not self._ensure_loaded():
      return None

    results = self._model.predict(text, _SAFETY_LABELS, threshold=0.3)
    if not results:
      return None

    best = max(results, key=lambda r: r["score"])
    if best["score"] < SAFETY_THRESHOLD:
      return ClassificationResult(label="legitimate_request", confidence=1.0 - best["score"])
    return ClassificationResult(label=best["label"], confidence=best["score"])

  def scan_response(self, text: str) -> Optional[ClassificationResult]:
    """Scan API response for injection attempts. Returns None if unavailable."""
    if not self._ensure_loaded():
      return None

    results = self._model.predict(text, _RESPONSE_SCAN_LABELS, threshold=0.3)
    if not results:
      return None

    best = max(results, key=lambda r: r["score"])
    if best["score"] < RESPONSE_SCAN_THRESHOLD:
      return ClassificationResult(label="clean_data", confidence=1.0 - best["score"])
    return ClassificationResult(label=best["label"], confidence=best["score"])
