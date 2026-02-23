"""Usability integration tests — data-driven from tests/test_data.py.

Verifies the agent correctly handles genuine travel requests across
multiple channels (direct, email, text, itinerary, API responses, edge cases).
Each test case is defined in USABILITY_CASES with expected outcomes.

Requires ANTHROPIC_API_KEY for quarantine LLM tests.
"""

from __future__ import annotations

import hashlib
import os

import pytest
from dotenv import load_dotenv
from trust_layer.audit_log import AuditLog
from trust_layer.capability_tokens import TravelIntent
from trust_layer.trust_boundary import TrustBoundary

from tests.data import USABILITY_CASES

load_dotenv()

_has_anthropic_key = bool(os.environ.get("ANTHROPIC_API_KEY"))

requires_anthropic = pytest.mark.skipif(
  not _has_anthropic_key, reason="ANTHROPIC_API_KEY not set"
)


def _make_boundary() -> TrustBoundary:
  return TrustBoundary()


def _license_hash(plaintext: str = "CA-DL-12345678") -> str:
  return hashlib.sha256(plaintext.encode()).hexdigest()


# ===========================================================================
# Data-driven usability tests — one test per case in USABILITY_CASES
# ===========================================================================

@requires_anthropic
class TestUsability:
  """Parametrized usability tests driven by USABILITY_CASES.

  Each case verifies:
  - injection_detected is False (no false positives on clean input)
  - intent is one of the expected valid_intents
  - user_confirmation_required is acceptable when allow_confirmation_required
  """

  def setup_method(self):
    AuditLog.reset()

  @pytest.mark.asyncio
  @pytest.mark.parametrize(
    "case",
    USABILITY_CASES,
    ids=[c["id"] for c in USABILITY_CASES],
  )
  async def test_usability_case(self, case: dict):
    expected = case["expected"]
    boundary = _make_boundary()

    pii = {"license_number_hash": _license_hash()} if case["include_license"] else None
    token = await boundary.process_user_request(case["raw_input"], pii_preprocessor=pii)

    # 1. Must NOT be flagged as injection (false positive check)
    assert token.injection_detected is False, (
      f"[{case['id']}] False positive: clean {case['category']} input "
      f"flagged as injection.\n"
      f"Description: {case['description']}\n"
      f"Why this matters: {expected['why_fail']}"
    )

    # 2. Intent must be one of the acceptable values
    valid = [TravelIntent(v) for v in expected["valid_intents"]]
    if expected.get("allow_confirmation_required") and token.user_confirmation_required:
      # Ambiguous requests may flag confirmation — that's acceptable
      pass
    else:
      assert token.intent in valid, (
        f"[{case['id']}] Wrong intent: got {token.intent.value}, "
        f"expected one of {expected['valid_intents']}.\n"
        f"Description: {case['description']}\n"
        f"Why this matters: {expected['why_fail']}"
      )


# ===========================================================================
# PII handling — these are separate because they test ValueError raises
# ===========================================================================

@requires_anthropic
class TestPIIHandling:
  """Verify PII is properly handled: licenses hashed, SSN/cards rejected.

  These cannot be parametrized with the main usability tests because
  they expect ValueError raises, not token assertions.
  """

  def setup_method(self):
    AuditLog.reset()

  @pytest.mark.asyncio
  async def test_license_hashed_never_plaintext(self):
    """License number must appear as hash, never as plaintext in token.

    Failure means: PII leak — license number crosses the trust boundary.
    """
    plaintext = "CA-DL-99887766"
    h = hashlib.sha256(plaintext.encode()).hexdigest()
    boundary = _make_boundary()
    token = await boundary.process_user_request(
      f"Rent a car from LAX on April 10 2026, return April 15. "
      f"My license is {plaintext}, expires 2028-06.",
      pii_preprocessor={"license_number_hash": h},
    )
    token_json = token.model_dump_json()
    assert plaintext not in token_json, "Plaintext license leaked into token!"
    assert "99887766" not in token_json, "License digits leaked into token!"
    if token.license_number_hash:
      assert token.license_number_hash == h

  @pytest.mark.asyncio
  async def test_ssn_in_input_rejected(self):
    """SSN in raw input should raise ValueError before reaching the LLM.

    Failure means: SSN passes through the sanitizer — critical PII leak.
    """
    boundary = _make_boundary()
    with pytest.raises(ValueError, match="SSN"):
      await boundary.process_user_request("Rent a car. My SSN is 123-45-6789.")

  @pytest.mark.asyncio
  async def test_card_in_input_rejected(self):
    """Credit card in raw input should raise ValueError.

    Failure means: credit card number passes through — critical PII leak.
    """
    boundary = _make_boundary()
    with pytest.raises(ValueError, match="card"):
      await boundary.process_user_request(
        "Rent a car. Pay with card 4111 1111 1111 1111."
      )


# ===========================================================================
# Full pipeline — end-to-end through all layers
# ===========================================================================

@requires_anthropic
class TestFullPipeline:
  """End-to-end: quarantine LLM → token → privilege check → sandbox → result."""

  def setup_method(self):
    AuditLog.reset()

  @pytest.mark.asyncio
  async def test_car_search_end_to_end(self):
    """Full pipeline for a clean car search request.

    Validates: the entire chain works — quarantine emits token,
    privilege check passes, sandbox validates, and result returns.
    Failure means: one of the pipeline layers is broken.
    """
    boundary = _make_boundary()
    token = await boundary.process_user_request(
      "Rent a midsize car from SFO on April 10 2026, return April 15.",
      pii_preprocessor={"license_number_hash": _license_hash()},
    )
    assert token.intent == TravelIntent.SEARCH_CAR
    assert token.injection_detected is False

    result = await boundary.execute_with_privilege(token)
    assert result["status"] in ("success", "confirmation_required"), (
      f"Expected success/confirmation, got {result['status']}. "
      f"Reason: {result.get('reason', 'unknown')}"
    )

  @pytest.mark.asyncio
  async def test_trace_shows_all_layers(self):
    """process_with_trace should record every pipeline layer.

    Validates: tracing instrumentation covers all defense layers.
    Failure means: a layer was skipped or not recorded.
    """
    boundary = _make_boundary()
    trace = await boundary.process_with_trace(
      "Rent a midsize car from LAX on April 10 2026, returning April 15.",
      pii_preprocessor={"license_number_hash": _license_hash()},
    )
    assert trace.final_status in ("executed", "confirmation_required")

    layer_names = [layer.name for layer in trace.layers]
    assert "pii_sanitizer" in layer_names, "PII sanitizer layer missing from trace."
    assert "quarantine_llm" in layer_names, "Quarantine LLM layer missing from trace."
    assert "token_validation" in layer_names, "Token validation layer missing from trace."

  @pytest.mark.asyncio
  async def test_audit_log_records_crossing(self):
    """Audit log should record every trust boundary crossing.

    Validates: crossings are logged with correct intent and outcome.
    Failure means: audit trail is broken — security incident tracking fails.
    """
    boundary = _make_boundary()
    token = await boundary.process_user_request(
      "Rent a car from SFO on April 10 2026, return April 15.",
      pii_preprocessor={"license_number_hash": _license_hash()},
    )
    await boundary.execute_with_privilege(token)

    crossings = AuditLog.get_session_crossings()
    assert len(crossings) >= 1, "No crossings recorded in audit log."
    last = crossings[-1]
    assert last.intent == "search_car"
    assert last.outcome in ("executed", "awaiting_confirmation")
