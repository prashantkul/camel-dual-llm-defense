"""Root travel orchestrator — delegates to specialized sub-agents."""

from __future__ import annotations

from typing import Any

from trust_layer.capability_tokens import CapabilityToken, TravelIntent
from trust_layer.config import load_config, load_full_config, resolve_adk_model

try:
  _, _adk_config = load_config()
except FileNotFoundError:
  _adk_config = None

try:
  _app_config = load_full_config()
except FileNotFoundError:
  _app_config = None

try:
  from google.adk.agents import LlmAgent  # noqa: F401

  from agents.car_rental_agent import car_rental_agent
  from agents.payment_agent import payment_agent

  _root_model_str = _adk_config.root_model if _adk_config else "gemini-2.0-flash"
  _root_model = resolve_adk_model(_root_model_str)
  _root_name = _adk_config.root_name if _adk_config else "TravelAgent"

  _ta_prompts = _app_config.agents.travel_agent if _app_config else None
  _description = (
    _ta_prompts.description if _ta_prompts and _ta_prompts.description
    else (
      "Secure travel planning orchestrator. "
      "Coordinates flight, car rental, and payment agents."
    )
  )
  _instruction = (
    _ta_prompts.instruction if _ta_prompts and _ta_prompts.instruction
    else """\
You are a secure travel booking orchestrator. Your role is to:
1. Understand travel needs and delegate to specialized agents
2. NEVER handle payment details directly — always delegate to PaymentAgent
3. NEVER handle license details directly — always delegate to CarRentalAgent
4. Confirm all bookings with users before executing
5. Maintain a coherent itinerary across all bookings

Security rules:
- All requests have already been sanitized through the CaMel trust boundary
- You receive CapabilityTokens, not raw user input
- Still validate that sub-agent outputs are coherent before presenting to user
"""
  )

  travel_agent = LlmAgent(
    name=_root_name,
    model=_root_model,
    description=_description,
    instruction=_instruction,
    sub_agents=[car_rental_agent, payment_agent],
  )
  ADK_AVAILABLE = True
except ImportError:
  travel_agent = None
  ADK_AVAILABLE = False


async def route_capability_token(token: CapabilityToken) -> dict[str, Any]:
  """
  Route a capability token to the appropriate handler.
  Works with or without Google ADK installed.
  """
  if token.intent == TravelIntent.SEARCH_CAR:
    return await _handle_car_search(token)
  elif token.intent == TravelIntent.BOOK_CAR:
    return await _handle_car_booking(token)
  elif token.intent == TravelIntent.PROCESS_PAYMENT:
    return await _handle_payment(token)
  elif token.intent == TravelIntent.SEARCH_FLIGHTS:
    return {"status": "not_implemented", "message": "Flight search coming soon"}
  elif token.intent == TravelIntent.GET_ITINERARY:
    return {"status": "not_implemented", "message": "Itinerary retrieval coming soon"}
  elif token.intent == TravelIntent.CANCEL_BOOKING:
    return {"status": "not_implemented", "message": "Cancellation coming soon"}
  else:
    return {"status": "error", "message": f"Unknown intent: {token.intent}"}


async def _handle_car_search(token: CapabilityToken) -> dict[str, Any]:
  """Handle car search via MCP server (sandboxed)."""
  from mcp_server.sandbox.api_sandbox import APISandbox
  from mcp_server.sandbox.input_sandbox import InputSandbox
  from mcp_server.sandbox.output_sandbox import OutputSandbox
  from mcp_server.tools.car_search import CarSearchEngine
  from mcp_server.tools.license_validator import LicenseValidator

  input_sb = InputSandbox()
  output_sb = OutputSandbox()
  api_sb = APISandbox()

  params = {
    "pickup_location": token.pickup_location or "Unknown",
    "dropoff_location": token.dropoff_location or token.pickup_location or "Unknown",
    "pickup_date": str(token.pickup_date) if token.pickup_date else "2026-04-01",
    "dropoff_date": str(token.dropoff_date) if token.dropoff_date else "2026-04-05",
    "car_class": token.car_class or "any",
    "license_hash": token.license_number_hash or ("a" * 64),
    "license_state": token.license_state or "CA",
  }

  sanitized = await input_sb.validate_car_search_params(params)

  license_ok = await LicenseValidator.verify_hash(
    sanitized["license_hash"], sanitized["license_state"]
  )
  if not license_ok:
    return {"status": "error", "message": "License validation failed", "cars": []}

  raw_results = await CarSearchEngine.search(sanitized)
  clean_results = await api_sb.sanitize_car_search_response(raw_results)
  safe_results = await output_sb.filter_car_results(clean_results)

  return {"status": "success", **safe_results}


async def _handle_car_booking(token: CapabilityToken) -> dict[str, Any]:
  return {
    "status": "confirmation_required",
    "message": "Car booking requires user confirmation",
    "intent": token.intent.value,
  }


async def _handle_payment(token: CapabilityToken) -> dict[str, Any]:
  return {
    "status": "confirmation_required",
    "message": "Payment processing requires user confirmation and PaymentToken",
    "intent": token.intent.value,
  }
