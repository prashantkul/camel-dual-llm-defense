"""Server-side validated tool execution for quarantine outputs."""

from __future__ import annotations

from typing import Any

from trust_layer.capability_tokens import CapabilityToken


_SENTINEL_VALUES = {"<UNKNOWN>", "<unknown>", "UNKNOWN", "unknown", "N/A", "n/a", "none", "null"}


def validate_and_build_token(raw_tool_output: dict[str, Any]) -> CapabilityToken:
  """
  Server-side validation of the quarantine LLM's tool output.
  Even though the LLM was forced to use structured output via tool_choice,
  we still validate server-side — defense in depth.
  """
  cleaned: dict[str, Any] = {}
  for key, val in raw_tool_output.items():
    if isinstance(val, str) and val.strip() in _SENTINEL_VALUES:
      continue
    cleaned[key] = val

  # If intent was stripped (LLM returned <UNKNOWN>) but injection was detected,
  # default to search_car so the token can still be constructed and blocked.
  if "intent" not in cleaned:
    cleaned["intent"] = "search_car"

  return CapabilityToken(**cleaned)
