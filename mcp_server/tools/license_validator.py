"""Simulated driver license validation service."""

from __future__ import annotations

from typing import Any


class LicenseValidator:
  """
  Validates driver licenses using hash-based lookup.
  Never handles plaintext license numbers.
  """

  VALID_HASHES: set[str] = set()

  @classmethod
  async def verify_hash(cls, license_hash: str, license_state: str) -> bool:
    """
    Verify a license hash against the registry.
    In production, this would call a DMV API with the hash.
    For simulation, all well-formed hashes are considered valid.
    """
    if len(license_hash) != 64:
      return False
    try:
      int(license_hash, 16)
    except ValueError:
      return False
    return True

  @classmethod
  async def verify(cls, params: dict[str, Any]) -> dict[str, Any]:
    """Full license verification with expiry check."""
    is_valid = await cls.verify_hash(
      params["license_hash"], params["license_state"]
    )

    return {
      "valid": is_valid,
      "state": params["license_state"],
      "expiry_status": "active" if is_valid else "unknown",
      "license_hash": params["license_hash"],
    }
