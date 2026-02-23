"""
Layer 3 defense: Sanitizes raw third-party API responses.
Third-party APIs are explicitly untrusted — treat as adversarial input.
Runs BEFORE OutputSandbox.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
  from trust_layer.config import APISandboxConfig


class APISandbox:
  _DEFAULT_MAX_RESPONSE_SIZE_BYTES = 50_000
  _DEFAULT_MAX_CARS_IN_RESPONSE = 20

  def __init__(self, config: APISandboxConfig | None = None) -> None:
    if config is not None:
      self.MAX_RESPONSE_SIZE_BYTES = config.max_response_size_bytes
      self.MAX_CARS_IN_RESPONSE = config.max_cars_in_response
    else:
      self.MAX_RESPONSE_SIZE_BYTES = self._DEFAULT_MAX_RESPONSE_SIZE_BYTES
      self.MAX_CARS_IN_RESPONSE = self._DEFAULT_MAX_CARS_IN_RESPONSE

  async def sanitize_car_search_response(self, raw_response: Any) -> dict:
    """
    Sanitize raw third-party rental car API response.
    Assumes the API could be compromised or returning adversarial content.
    """
    raw_str = (
      json.dumps(raw_response)
      if not isinstance(raw_response, str)
      else raw_response
    )
    if len(raw_str.encode()) > self.MAX_RESPONSE_SIZE_BYTES:
      raise ValueError(
        f"API response exceeds size limit: {len(raw_str.encode())} bytes"
      )

    if isinstance(raw_response, str):
      try:
        data = json.loads(raw_response)
      except json.JSONDecodeError:
        return {"cars": [], "error": "API returned non-JSON response"}
    else:
      data = raw_response

    if not isinstance(data, dict):
      return {"cars": [], "error": "Unexpected response structure"}

    cars = data.get("cars", [])
    if len(cars) > self.MAX_CARS_IN_RESPONSE:
      cars = cars[: self.MAX_CARS_IN_RESPONSE]

    return {
      "cars": cars,
      "search_id": str(data.get("search_id", ""))[:36],
    }
