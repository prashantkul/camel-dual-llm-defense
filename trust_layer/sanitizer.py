"""Input sanitization utilities for the quarantine layer."""

from __future__ import annotations

import hashlib
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
  from trust_layer.config import SecurityConfig


class Sanitizer:
  """
  Pre-processes raw user input before it reaches the quarantine LLM.
  Handles PII extraction and hashing so plaintext never enters the token.
  """

  LICENSE_PATTERNS = [
    re.compile(r"\b[A-Z]{2}-(?:DL-)?(\d{6,10})\b"),
    re.compile(r"\blicense\s+(?:number\s+)?(?:is\s+)?([A-Z0-9\-]{6,20})\b", re.IGNORECASE),
  ]

  SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
  CARD_PATTERN = re.compile(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b")

  def __init__(self, config: SecurityConfig | None = None) -> None:
    if config is not None:
      Sanitizer.LICENSE_PATTERNS = [
        re.compile(config.pii_license_patterns[0])
      ]
      if len(config.pii_license_patterns) > 1:
        Sanitizer.LICENSE_PATTERNS.append(
          re.compile(config.pii_license_patterns[1], re.IGNORECASE)
        )
      Sanitizer.SSN_PATTERN = re.compile(config.pii_ssn_pattern)
      Sanitizer.CARD_PATTERN = re.compile(config.pii_card_pattern)

  @classmethod
  def extract_and_hash_pii(cls, raw_input: str) -> dict[str, str]:
    """
    Extract PII from raw input and return hashed versions.
    The raw input is NOT modified — the hashes are passed separately
    to the trust boundary so the quarantine LLM never needs to echo PII.
    """
    pii_hashes: dict[str, str] = {}

    for pattern in cls.LICENSE_PATTERNS:
      match = pattern.search(raw_input)
      if match:
        full_match = match.group(0)
        pii_hashes["license_number_hash"] = hashlib.sha256(
          full_match.encode()
        ).hexdigest()
        break

    if cls.SSN_PATTERN.search(raw_input):
      pii_hashes["_ssn_detected"] = "true"

    if cls.CARD_PATTERN.search(raw_input):
      pii_hashes["_card_detected"] = "true"

    return pii_hashes

  @classmethod
  def redact_pii_from_text(cls, text: str) -> str:
    """Redact PII from text before it enters any log or context."""
    text = cls.SSN_PATTERN.sub("[SSN_REDACTED]", text)
    text = cls.CARD_PATTERN.sub("[CARD_REDACTED]", text)
    for pattern in cls.LICENSE_PATTERNS:
      text = pattern.sub("[LICENSE_REDACTED]", text)
    return text
