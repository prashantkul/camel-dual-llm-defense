"""Structured capability tokens for inter-LLM communication across the trust boundary."""

from __future__ import annotations

import hashlib
from datetime import date
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, field_validator

from camel.capabilities import Capabilities
from camel.interpreter.value import CaMeLStr


class TravelIntent(str, Enum):
  SEARCH_FLIGHTS = "search_flights"
  SEARCH_CAR = "search_car"
  BOOK_CAR = "book_car"
  PROCESS_PAYMENT = "process_payment"
  GET_ITINERARY = "get_itinerary"
  CANCEL_BOOKING = "cancel_booking"


class RiskLevel(str, Enum):
  LOW = "low"
  MEDIUM = "medium"
  HIGH = "high"


# Module-level injection patterns used by the CapabilityToken validator.
# Override at startup via configure_token_patterns().
TOKEN_INJECTION_PATTERNS: list[str] = [
  "ignore previous",
  "system:",
  "assistant:",
  "\n\n",
  "<|",
  "]]",
  "you are now",
  "new instructions",
]


def configure_token_patterns(patterns: list[str]) -> None:
  """Override the token injection patterns at startup."""
  global TOKEN_INJECTION_PATTERNS
  TOKEN_INJECTION_PATTERNS = list(patterns)


class CapabilityToken(BaseModel):
  """
  Structured token produced by the Quarantined LLM.
  This is the ONLY thing that crosses the trust boundary.
  Never passes raw user content to the Privileged LLM.
  """

  intent: TravelIntent
  risk_level: RiskLevel
  parameters: dict[str, Any] = {}
  user_confirmation_required: bool = False
  injection_detected: bool = False

  pickup_location: Optional[str] = None
  dropoff_location: Optional[str] = None
  pickup_date: Optional[date] = None
  dropoff_date: Optional[date] = None
  car_class: Optional[str] = None

  license_number_hash: Optional[str] = None
  license_state: Optional[str] = None
  license_expiry: Optional[date] = None

  @field_validator("parameters")
  @classmethod
  def no_injection_patterns(cls, v: dict[str, Any]) -> dict[str, Any]:
    """Block prompt injection patterns in extracted parameters."""
    for key, val in v.items():
      if isinstance(val, str):
        for pattern in TOKEN_INJECTION_PATTERNS:
          if pattern.lower() in val.lower():
            raise ValueError(
              f"Injection pattern detected in parameter '{key}'"
            )
    return v

  def as_camel_kwargs(self) -> dict[str, CaMeLStr]:
    """Wrap token fields as CaMeLValues with User source provenance."""
    metadata = Capabilities.default()  # Source=User, Readers=Public
    result: dict[str, CaMeLStr] = {}
    if self.pickup_location:
      result["pickup_location"] = CaMeLStr.from_raw(
        self.pickup_location, metadata, ()
      )
    if self.dropoff_location:
      result["dropoff_location"] = CaMeLStr.from_raw(
        self.dropoff_location, metadata, ()
      )
    if self.car_class:
      result["car_class"] = CaMeLStr.from_raw(
        self.car_class, metadata, ()
      )
    if self.license_number_hash:
      result["license_hash"] = CaMeLStr.from_raw(
        self.license_number_hash, metadata, ()
      )
    if self.license_state:
      result["license_state"] = CaMeLStr.from_raw(
        self.license_state, metadata, ()
      )
    if self.pickup_date:
      result["pickup_date"] = CaMeLStr.from_raw(
        str(self.pickup_date), metadata, ()
      )
    if self.dropoff_date:
      result["dropoff_date"] = CaMeLStr.from_raw(
        str(self.dropoff_date), metadata, ()
      )
    return result

  @field_validator("license_number_hash")
  @classmethod
  def must_be_hash_not_plaintext(cls, v: Optional[str]) -> Optional[str]:
    """Ensure license field contains a SHA-256 hash, not plaintext."""
    if v is None:
      return v
    if len(v) != 64:
      raise ValueError("license_number_hash must be a 64-char SHA-256 hex string")
    try:
      int(v, 16)
    except ValueError:
      raise ValueError("license_number_hash must be valid hexadecimal")
    return v


class PaymentToken(BaseModel):
  """Separate token type for payment operations — higher scrutiny."""

  amount_cents: int
  currency: str = "USD"
  booking_reference: str
  payment_method_token: str
  idempotency_key: str

  @field_validator("amount_cents")
  @classmethod
  def amount_must_be_positive(cls, v: int) -> int:
    if v <= 0:
      raise ValueError("Payment amount must be positive")
    return v


def hash_license(plaintext_license: str) -> str:
  """Hash a plaintext license number. Call this BEFORE creating a token."""
  return hashlib.sha256(plaintext_license.encode()).hexdigest()
