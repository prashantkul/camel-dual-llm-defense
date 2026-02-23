"""Tests for the MCP server sandbox layers."""

from __future__ import annotations

import pytest

from mcp_server.sandbox.api_sandbox import APISandbox
from mcp_server.sandbox.input_sandbox import InputSandbox
from mcp_server.sandbox.output_sandbox import OutputSandbox
from mcp_server.tools.car_search import CarSearchEngine
from mcp_server.tools.license_validator import LicenseValidator


class TestInputSandbox:
  @pytest.fixture
  def sandbox(self):
    return InputSandbox()

  @pytest.fixture
  def valid_params(self):
    return {
      "pickup_location": "SFO",
      "dropoff_location": "LAX",
      "pickup_date": "2026-12-15",
      "dropoff_date": "2026-12-20",
      "car_class": "midsize",
      "license_hash": "a" * 64,
      "license_state": "CA",
    }

  @pytest.mark.asyncio
  async def test_valid_params_pass(self, sandbox, valid_params):
    result = await sandbox.validate_car_search_params(valid_params)
    assert result["pickup_location"] == "SFO"
    assert result["dropoff_location"] == "LAX"
    assert result["car_class"] == "midsize"

  @pytest.mark.asyncio
  async def test_special_chars_blocked(self, sandbox, valid_params):
    valid_params["pickup_location"] = "SFO<script>"
    with pytest.raises(ValueError, match="Invalid characters"):
      await sandbox.validate_car_search_params(valid_params)

  @pytest.mark.asyncio
  async def test_overlength_location_rejected(self, sandbox, valid_params):
    valid_params["pickup_location"] = "A" * 200
    with pytest.raises(ValueError, match="exceeds maximum length"):
      await sandbox.validate_car_search_params(valid_params)

  @pytest.mark.asyncio
  async def test_invalid_car_class(self, sandbox, valid_params):
    valid_params["car_class"] = "helicopter"
    with pytest.raises(ValueError, match="Invalid car class"):
      await sandbox.validate_car_search_params(valid_params)

  @pytest.mark.asyncio
  async def test_license_validation(self, sandbox):
    params = {
      "license_hash": "b" * 64,
      "license_state": "NY",
      "license_expiry": "2028-01-01",
    }
    result = await sandbox.validate_license_params(params)
    assert result["license_state"] == "NY"

  @pytest.mark.asyncio
  async def test_expired_license_rejected(self, sandbox):
    params = {
      "license_hash": "b" * 64,
      "license_state": "NY",
      "license_expiry": "2020-01-01",
    }
    with pytest.raises(ValueError, match="expired"):
      await sandbox.validate_license_params(params)


class TestOutputSandbox:
  @pytest.fixture
  def sandbox(self):
    return OutputSandbox()

  @pytest.mark.asyncio
  async def test_filters_allowed_fields(self, sandbox):
    result = await sandbox.filter_car_results({
      "cars": [{"car_id": "1", "make": "Toyota", "internal_id": "secret"}],
    })
    assert "car_id" in result["cars"][0]
    assert "internal_id" not in result["cars"][0]

  @pytest.mark.asyncio
  async def test_handles_empty_results(self, sandbox):
    result = await sandbox.filter_car_results({"cars": []})
    assert result["cars"] == []
    assert result["total_results"] == 0

  @pytest.mark.asyncio
  async def test_handles_invalid_input(self, sandbox):
    result = await sandbox.filter_car_results("not a dict")
    assert result["cars"] == []

  @pytest.mark.asyncio
  async def test_license_result_filtered(self, sandbox):
    result = await sandbox.filter_license_result({
      "valid": True,
      "state": "CA",
      "expiry_status": "active",
      "internal_data": "should_not_appear",
    })
    assert result["valid"] is True
    assert "internal_data" not in result


class TestAPISandbox:
  @pytest.fixture
  def sandbox(self):
    return APISandbox()

  @pytest.mark.asyncio
  async def test_caps_results(self, sandbox):
    data = {"cars": [{"id": str(i)} for i in range(50)]}
    result = await sandbox.sanitize_car_search_response(data)
    assert len(result["cars"]) == 20

  @pytest.mark.asyncio
  async def test_handles_string_json(self, sandbox):
    result = await sandbox.sanitize_car_search_response('{"cars": []}')
    assert result["cars"] == []

  @pytest.mark.asyncio
  async def test_handles_invalid_json_string(self, sandbox):
    result = await sandbox.sanitize_car_search_response("{not valid")
    assert result["cars"] == []
    assert "error" in result

  @pytest.mark.asyncio
  async def test_handles_non_dict(self, sandbox):
    result = await sandbox.sanitize_car_search_response([1, 2, 3])
    assert result["cars"] == []

  @pytest.mark.asyncio
  async def test_preserves_search_id(self, sandbox):
    result = await sandbox.sanitize_car_search_response({
      "cars": [],
      "search_id": "abc123",
    })
    assert result["search_id"] == "abc123"


class TestCarSearchEngine:
  @pytest.mark.asyncio
  async def test_search_all(self):
    result = await CarSearchEngine.search({
      "car_class": "any",
      "pickup_location": "SFO",
      "dropoff_location": "LAX",
    })
    assert len(result["cars"]) == 4

  @pytest.mark.asyncio
  async def test_search_by_class(self):
    result = await CarSearchEngine.search({
      "car_class": "economy",
      "pickup_location": "SFO",
      "dropoff_location": "LAX",
    })
    assert len(result["cars"]) == 1
    assert result["cars"][0]["class"] == "economy"

  @pytest.mark.asyncio
  async def test_search_no_results(self):
    result = await CarSearchEngine.search({
      "car_class": "convertible",
      "pickup_location": "SFO",
      "dropoff_location": "LAX",
    })
    assert len(result["cars"]) == 0


class TestLicenseValidator:
  @pytest.mark.asyncio
  async def test_valid_hash(self):
    assert await LicenseValidator.verify_hash("a" * 64, "CA") is True

  @pytest.mark.asyncio
  async def test_invalid_hash_length(self):
    assert await LicenseValidator.verify_hash("short", "CA") is False

  @pytest.mark.asyncio
  async def test_invalid_hash_chars(self):
    assert await LicenseValidator.verify_hash("g" * 64, "CA") is False

  @pytest.mark.asyncio
  async def test_full_verify(self):
    result = await LicenseValidator.verify({
      "license_hash": "a" * 64,
      "license_state": "CA",
    })
    assert result["valid"] is True
    assert result["expiry_status"] == "active"
