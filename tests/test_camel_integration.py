"""End-to-end tests for CaMeL taint flow integration."""

from __future__ import annotations

import pytest
from camel.capabilities import Capabilities, is_trusted
from camel.capabilities.readers import Public
from camel.capabilities.sources import Tool as ToolSource
from camel.interpreter.value import CaMeLStr
from camel.security_policy import Allowed, Denied

from trust_layer.capability_tokens import CapabilityToken, RiskLevel, TravelIntent
from trust_layer.trust_boundary import TravelSecurityPolicyEngine


class TestCaMeLTaintFlow:
  """Verify CaMeL taint tracking works end-to-end with the travel policy."""

  def setup_method(self):
    self.policy = TravelSecurityPolicyEngine()

  def test_user_sourced_values_pass_read_tools(self):
    """User-sourced values (Capabilities.default()) pass policy for read tools."""
    metadata = Capabilities.default()
    kwargs = {
      "pickup_location": CaMeLStr.from_raw("SFO", metadata, ()),
      "dropoff_location": CaMeLStr.from_raw("LAX", metadata, ()),
    }
    result = self.policy.check_tool_args("search_rental_cars", kwargs)
    assert isinstance(result, Allowed)

  def test_user_sourced_values_pass_write_tools(self):
    """User-sourced values pass taint check for write tools."""
    metadata = Capabilities.default()
    kwargs = {
      "pickup_location": CaMeLStr.from_raw("SFO", metadata, ()),
    }
    result = self.policy.check_tool_args("book_car", kwargs)
    assert isinstance(result, Allowed)

  def test_tool_sourced_values_denied_for_write_tools(self):
    """Tool-sourced values (ToolSource) are denied for write tools — taint propagation."""
    tool_source = ToolSource(tool_name="external_api", inner_sources=frozenset())
    metadata = Capabilities(frozenset({tool_source}), Public())
    kwargs = {
      "pickup_location": CaMeLStr.from_raw("SFO", metadata, ()),
    }
    result = self.policy.check_tool_args("book_car", kwargs)
    assert isinstance(result, Denied)
    assert "trusted source" in result.reason

  def test_injection_detected_token_denied_all_tools(self):
    """Injection-detected token is denied for all tools."""
    token = CapabilityToken(
      intent=TravelIntent.SEARCH_CAR,
      risk_level=RiskLevel.HIGH,
      injection_detected=True,
      user_confirmation_required=True,
    )
    for tool in ["search_rental_cars", "book_car", "process_payment", "get_itinerary"]:
      result = self.policy.check(tool, token)
      assert isinstance(result, Denied), f"Expected Denied for {tool}"
      assert "injection" in result.reason.lower()

  def test_unknown_tool_denied_by_default(self):
    """Unknown tool is denied by default."""
    token = CapabilityToken(
      intent=TravelIntent.SEARCH_CAR,
      risk_level=RiskLevel.LOW,
    )
    result = self.policy.check("delete_all_data", token)
    assert isinstance(result, Denied)
    assert "unknown" in result.reason.lower()

  def test_camel_sourced_values_are_trusted(self):
    """CaMeL-computed values are trusted."""
    metadata = Capabilities.camel()
    val = CaMeLStr.from_raw("computed_value", metadata, ())
    assert is_trusted(val)

  def test_user_sourced_values_are_trusted(self):
    """User-sourced values are trusted."""
    metadata = Capabilities.default()
    val = CaMeLStr.from_raw("user_input", metadata, ())
    assert is_trusted(val)

  def test_tool_sourced_values_are_untrusted(self):
    """External tool-sourced values are untrusted."""
    tool_source = ToolSource(tool_name="external_api", inner_sources=frozenset())
    metadata = Capabilities(frozenset({tool_source}), Public())
    val = CaMeLStr.from_raw("api_response", metadata, ())
    assert not is_trusted(val)

  def test_token_as_camel_kwargs_roundtrip(self):
    """Token → CaMeL kwargs → policy check roundtrip works."""
    token = CapabilityToken(
      intent=TravelIntent.SEARCH_CAR,
      risk_level=RiskLevel.LOW,
      pickup_location="SFO",
      dropoff_location="LAX",
      car_class="midsize",
    )
    kwargs = token.as_camel_kwargs()
    # All user-sourced kwargs should pass read tool check
    result = self.policy.check_tool_args("search_rental_cars", kwargs)
    assert isinstance(result, Allowed)
    # All user-sourced kwargs should also pass write tool check
    result = self.policy.check_tool_args("book_car", kwargs)
    assert isinstance(result, Allowed)

  def test_mixed_provenance_denied_for_write(self):
    """Mixed provenance (user + tool source) denied for write tools."""
    user_metadata = Capabilities.default()
    tool_source = ToolSource(tool_name="search_api", inner_sources=frozenset())
    tool_metadata = Capabilities(frozenset({tool_source}), Public())
    kwargs = {
      "pickup_location": CaMeLStr.from_raw("SFO", user_metadata, ()),
      "car_id": CaMeLStr.from_raw("CAR-123", tool_metadata, ()),
    }
    result = self.policy.check_tool_args("book_car", kwargs)
    assert isinstance(result, Denied)
    assert "car_id" in result.reason


class TestOutputProvenance:
  """Tests for output sandbox provenance tagging."""

  def test_tag_output_provenance_adds_metadata(self):
    from mcp_server.sandbox.output_sandbox import tag_output_provenance

    data = {"cars": [], "total_results": 0}
    tagged = tag_output_provenance(data, "search_rental_cars")
    assert "_camel_metadata" in tagged
    assert tagged["_camel_metadata"]["source"] == "search_rental_cars"
    assert tagged["_camel_metadata"]["trusted"] is False

  @pytest.mark.asyncio
  async def test_filter_car_results_includes_provenance(self):
    from mcp_server.sandbox.output_sandbox import OutputSandbox

    sb = OutputSandbox()
    raw = {
      "cars": [
        {"car_id": "C1", "make": "Toyota", "model": "Camry", "year": 2024},
      ],
      "search_id": "abc123",
    }
    result = await sb.filter_car_results(raw)
    assert "_camel_metadata" in result
    assert result["_camel_metadata"]["source"] == "search_rental_cars"
