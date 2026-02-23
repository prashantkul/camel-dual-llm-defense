"""
Layer 1 defense: Validates and sanitizes all MCP tool inputs.
Prevents injection attacks from reaching tool execution.
"""

from __future__ import annotations

import re
from datetime import date, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
  from trust_layer.config import DomainConfig, InputSandboxConfig


class InputSandbox:
  _DEFAULT_INJECTION_PATTERNS = [
    r"ignore\s+previous",
    r"system\s*:",
    r"assistant\s*:",
    r"<\|.*?\|>",
    r"\]\]\s*\[\[",
    r"prompt\s+inject",
    r"jailbreak",
    r"DAN\s+mode",
    r"```.*?```",
    r"<script",
    r"javascript:",
    r"you\s+are\s+now",
    r"new\s+instructions?",
    r"DROP\s+TABLE",
    r";\s*--",
  ]

  _DEFAULT_CAR_CLASSES = {"economy", "midsize", "suv", "luxury", "any"}

  _DEFAULT_STATES = {
    "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA",
    "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD",
    "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ",
    "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC",
    "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY",
    "BC", "ON", "QC", "AB", "MB", "SK",
  }

  def __init__(
    self,
    config: InputSandboxConfig | None = None,
    domain: DomainConfig | None = None,
  ) -> None:
    if config is not None:
      self.INJECTION_PATTERNS = list(config.injection_patterns)
      self._max_location_length = config.max_location_length
      self._license_hash_regex = config.license_hash_regex
    else:
      self.INJECTION_PATTERNS = list(self._DEFAULT_INJECTION_PATTERNS)
      self._max_location_length = 100
      self._license_hash_regex = r"^[a-f0-9]{64}$"

    if domain is not None:
      self.ALLOWED_CAR_CLASSES = set(domain.car_classes)
      self.ALLOWED_STATES = set(domain.allowed_states)
    else:
      self.ALLOWED_CAR_CLASSES = set(self._DEFAULT_CAR_CLASSES)
      self.ALLOWED_STATES = set(self._DEFAULT_STATES)

  async def validate_car_search_params(self, params: dict) -> dict:
    """Validate all car search parameters."""
    validated = {}

    for loc_key in ["pickup_location", "dropoff_location"]:
      raw_loc = str(params[loc_key])
      if len(raw_loc) > self._max_location_length:
        raise ValueError(f"Invalid {loc_key}: exceeds maximum length")
      if not re.match(r"^[a-zA-Z0-9\s,.\-]+$", raw_loc):
        raise ValueError(f"Invalid characters in {loc_key}")
      self._check_injection(raw_loc, loc_key)
      validated[loc_key] = raw_loc.strip()

    for date_key in ["pickup_date", "dropoff_date"]:
      d = datetime.strptime(params[date_key], "%Y-%m-%d").date()
      if d < date.today():
        raise ValueError(f"{date_key} must be a future date")
      validated[date_key] = d.isoformat()

    if validated["dropoff_date"] <= validated["pickup_date"]:
      raise ValueError("Dropoff date must be after pickup date")

    car_class = str(params["car_class"]).lower()
    if car_class not in self.ALLOWED_CAR_CLASSES:
      raise ValueError(f"Invalid car class: {car_class}")
    validated["car_class"] = car_class

    license_hash = str(params["license_hash"])
    if not re.match(self._license_hash_regex, license_hash):
      raise ValueError("Invalid license hash format — must be SHA-256")
    validated["license_hash"] = license_hash

    state = str(params["license_state"]).upper()
    if state not in self.ALLOWED_STATES:
      raise ValueError(f"Invalid license state: {state}")
    validated["license_state"] = state

    return validated

  async def validate_license_params(self, params: dict) -> dict:
    """Validate driver license parameters."""
    validated = {}

    license_hash = str(params["license_hash"])
    if not re.match(self._license_hash_regex, license_hash):
      raise ValueError("Invalid license hash format — must be SHA-256")
    validated["license_hash"] = license_hash

    state = str(params["license_state"]).upper()
    if state not in self.ALLOWED_STATES:
      raise ValueError(f"Invalid license state: {state}")
    validated["license_state"] = state

    expiry = datetime.strptime(params["license_expiry"], "%Y-%m-%d").date()
    if expiry < date.today():
      raise ValueError("License has expired")
    validated["license_expiry"] = expiry.isoformat()

    return validated

  def _check_injection(self, value: str, field_name: str) -> None:
    """Check for prompt injection patterns in any string value."""
    for pattern in self.INJECTION_PATTERNS:
      if re.search(pattern, value, re.IGNORECASE):
        raise ValueError(
          f"Injection pattern detected in {field_name}"
        )
