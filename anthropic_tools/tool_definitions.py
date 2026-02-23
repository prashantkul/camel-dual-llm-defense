"""Anthropic programmatic tool call definitions for the quarantine layer.

The quarantine LLM's ONLY tool is emit_capability_token.
Using tool_choice={type: tool, name: emit_capability_token} guarantees
structured output — no free-form text reaches the privileged side.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
  from trust_layer.config import DomainConfig

EMIT_CAPABILITY_TOKEN_TOOL = {
  "name": "emit_capability_token",
  "description": (
    "Emit a structured capability token representing the parsed user intent. "
    "This is the ONLY allowed output from the quarantine layer."
  ),
  "input_schema": {
    "type": "object",
    "properties": {
      "intent": {
        "type": "string",
        "enum": [
          "search_flights",
          "search_car",
          "book_car",
          "process_payment",
          "get_itinerary",
          "cancel_booking",
        ],
      },
      "risk_level": {
        "type": "string",
        "enum": ["low", "medium", "high"],
      },
      "pickup_location": {
        "type": "string",
        "description": "City or airport code, sanitized",
      },
      "dropoff_location": {"type": "string"},
      "pickup_date": {"type": "string", "format": "date"},
      "dropoff_date": {"type": "string", "format": "date"},
      "car_class": {
        "type": "string",
        "enum": ["economy", "midsize", "suv", "luxury", "any"],
      },
      "license_number_hash": {
        "type": "string",
        "description": "SHA-256 hash of license number, NEVER plaintext",
      },
      "license_state": {"type": "string", "maxLength": 2},
      "license_expiry": {"type": "string", "format": "date"},
      "user_confirmation_required": {"type": "boolean"},
      "injection_detected": {"type": "boolean", "default": False},
      "parameters": {"type": "object"},
    },
    "required": ["intent", "risk_level", "user_confirmation_required"],
  },
}


def build_emit_tool(domain: DomainConfig | None = None) -> dict[str, Any]:
  """Build the emit_capability_token tool schema, optionally using domain config."""
  if domain is None:
    return dict(EMIT_CAPABILITY_TOKEN_TOOL)

  tool = {
    "name": EMIT_CAPABILITY_TOKEN_TOOL["name"],
    "description": EMIT_CAPABILITY_TOKEN_TOOL["description"],
    "input_schema": {
      **EMIT_CAPABILITY_TOKEN_TOOL["input_schema"],
      "properties": {
        **EMIT_CAPABILITY_TOKEN_TOOL["input_schema"]["properties"],
        "car_class": {
          "type": "string",
          "enum": list(domain.car_classes),
        },
      },
    },
  }
  return tool


def extract_tool_use(response: Any, tool_name: str) -> dict[str, Any]:
  """Extract tool_use block from Anthropic response."""
  for block in response.content:
    if block.type == "tool_use" and block.name == tool_name:
      return block.input
  raise ValueError(
    f"Tool '{tool_name}' not found in response — "
    "quarantine LLM produced unexpected output"
  )
