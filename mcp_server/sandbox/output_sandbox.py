"""
Layer 2 defense: Filters tool outputs before they reach the agent context.
Prevents data exfiltration, PII leakage, and response injection.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from camel.capabilities import Capabilities
from camel.capabilities.sources import Tool as ToolSource
from camel.capabilities.readers import Public

if TYPE_CHECKING:
  from trust_layer.config import OutputSandboxConfig


def tag_output_provenance(sanitized: dict[str, Any], tool_name: str) -> dict[str, Any]:
  """Tag sanitized output values with CaMeL tool-source provenance."""
  source = ToolSource(tool_name=tool_name, inner_sources=frozenset())
  # Build metadata for downstream taint checking
  _metadata = Capabilities(frozenset({source}), Public())
  sanitized["_camel_metadata"] = {
    "source": tool_name,
    "trusted": False,  # External API responses are untrusted
  }
  return sanitized


class OutputSandbox:
  _DEFAULT_BLOCKED_FIELDS = {
    "ssn", "social_security", "credit_card", "cvv", "raw_license",
    "password", "api_key", "secret", "private_key", "auth_token",
  }

  _DEFAULT_RESPONSE_INJECTION_PATTERNS = [
    r"ignore\s+previous",
    r"new\s+instructions?",
    r"system\s+message",
    r"you\s+are\s+now",
    r"your\s+new\s+role",
  ]

  _DEFAULT_ALLOWED_CAR_FIELDS = {
    "car_id", "make", "model", "year", "class",
    "daily_rate_cents", "currency", "pickup_location",
    "dropoff_location", "availability", "features",
  }

  _DEFAULT_STRING_TRUNCATION_LIMIT = 500

  def __init__(self, config: OutputSandboxConfig | None = None) -> None:
    if config is not None:
      self.BLOCKED_OUTPUT_FIELDS = set(config.blocked_fields)
      self.RESPONSE_INJECTION_PATTERNS = list(config.response_injection_patterns)
      self.ALLOWED_CAR_FIELDS = set(config.allowed_car_fields)
      self._string_truncation_limit = config.string_truncation_limit
    else:
      self.BLOCKED_OUTPUT_FIELDS = set(self._DEFAULT_BLOCKED_FIELDS)
      self.RESPONSE_INJECTION_PATTERNS = list(self._DEFAULT_RESPONSE_INJECTION_PATTERNS)
      self.ALLOWED_CAR_FIELDS = set(self._DEFAULT_ALLOWED_CAR_FIELDS)
      self._string_truncation_limit = self._DEFAULT_STRING_TRUNCATION_LIMIT

  async def filter_car_results(self, results: dict) -> dict:
    """Filter car search results before returning to agent."""
    if not isinstance(results, dict):
      return {"error": "Invalid response format", "cars": []}

    safe_cars = []
    for car in results.get("cars", []):
      if not isinstance(car, dict):
        continue

      safe_car: dict[str, Any] = {}
      for field in self.ALLOWED_CAR_FIELDS:
        if field in car:
          val = car[field]
          if isinstance(val, str):
            self._check_response_injection(val, f"car.{field}")
            val = val[:self._string_truncation_limit]
          safe_car[field] = val

      for blocked in self.BLOCKED_OUTPUT_FIELDS:
        if blocked in car:
          continue

      safe_cars.append(safe_car)

    output = {
      "cars": safe_cars,
      "total_results": len(safe_cars),
      "search_id": str(results.get("search_id", ""))[:36],
    }
    return tag_output_provenance(output, "search_rental_cars")

  async def filter_license_result(self, result: dict) -> dict:
    """Filter license validation result."""
    if not isinstance(result, dict):
      return {"valid": False, "error": "Invalid response"}

    return {
      "valid": result.get("valid", False),
      "expiry_status": result.get("expiry_status", "unknown"),
      "state": result.get("state", ""),
    }

  def _check_response_injection(self, value: str, field: str) -> None:
    """Check if third-party API response contains injection attempts."""
    # Regex-based pattern matching
    for pattern in self.RESPONSE_INJECTION_PATTERNS:
      if re.search(pattern, value, re.IGNORECASE):
        raise ValueError(
          f"Response injection pattern in {field} — "
          "third-party API may be compromised"
        )

    # GLiNER semantic scan (defense-in-depth: catches attacks that evade regex)
    from trust_layer.gliner_layer import GLiNERLayer

    gliner = GLiNERLayer.get_instance()
    if gliner.is_available():
      scan_result = gliner.scan_response(value)
      if scan_result is not None and scan_result.label in (
        "injection_attempt",
        "data_exfiltration",
      ):
        raise ValueError(
          f"Response injection detected by GLiNER in {field} — "
          "third-party API may be compromised"
        )
