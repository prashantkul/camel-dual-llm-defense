"""FastMCP server with defense-in-depth sandboxing."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from mcp_server.sandbox.api_sandbox import APISandbox
from mcp_server.sandbox.input_sandbox import InputSandbox
from mcp_server.sandbox.output_sandbox import OutputSandbox
from mcp_server.tools.car_search import CarSearchEngine
from mcp_server.tools.license_validator import LicenseValidator

mcp = FastMCP("secure-travel-mcp")
input_sandbox = InputSandbox()
output_sandbox = OutputSandbox()
api_sandbox = APISandbox()


@mcp.tool()
async def search_rental_cars(
  pickup_location: str,
  dropoff_location: str,
  pickup_date: str,
  dropoff_date: str,
  car_class: str,
  license_hash: str,
  license_state: str,
) -> dict:
  """
  Search for available rental cars.
  All inputs pass through InputSandbox before processing.
  All outputs pass through OutputSandbox before returning.
  Third-party API responses pass through APISandbox.
  """
  # LAYER 1: Input Sandbox
  sanitized = await input_sandbox.validate_car_search_params({
    "pickup_location": pickup_location,
    "dropoff_location": dropoff_location,
    "pickup_date": pickup_date,
    "dropoff_date": dropoff_date,
    "car_class": car_class,
    "license_hash": license_hash,
    "license_state": license_state,
  })

  # LAYER 2: License validation (hash-based, no PII)
  license_valid = await LicenseValidator.verify_hash(
    sanitized["license_hash"], sanitized["license_state"]
  )
  if not license_valid:
    return {"error": "License validation failed", "cars": []}

  # LAYER 3: Third-party API call (simulated)
  raw_api_response = await CarSearchEngine.search(sanitized)

  # LAYER 4: API Sandbox — sanitize third-party response
  clean_api_response = await api_sandbox.sanitize_car_search_response(
    raw_api_response
  )

  # LAYER 5: Output Sandbox — filter before returning to agent
  safe_output = await output_sandbox.filter_car_results(clean_api_response)
  return safe_output


@mcp.tool()
async def validate_driver_license(
  license_hash: str,
  license_state: str,
  license_expiry: str,
) -> dict:
  """
  Validate driver license. Accepts only SHA-256 hash — never plaintext.
  Prevents PII from entering the agent context.
  """
  sanitized = await input_sandbox.validate_license_params({
    "license_hash": license_hash,
    "license_state": license_state,
    "license_expiry": license_expiry,
  })

  result = await LicenseValidator.verify(sanitized)
  return await output_sandbox.filter_license_result(result)


if __name__ == "__main__":
  mcp.run()
