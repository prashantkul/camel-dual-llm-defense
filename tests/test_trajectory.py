"""ADK Runner trajectory tests — verify agent execution produces correct event streams.

Launches the TravelAgent (with sub-agents) via InMemoryRunner and validates:
- Agent produces events (non-empty trajectory)
- TravelAgent correctly delegates to sub-agents (CarRentalAgent, PaymentAgent)
- Sub-agents respond with text output
- Event stream structure is well-formed

Optionally exports trajectories to Docent when --docent flag is passed:
  uv run --extra dev pytest tests/test_trajectory.py -v --docent

Requires OPENAI_API_KEY for ADK agents (via LiteLLM).
Requires DOCENT_API_KEY + DOCENT_COLLECTION_ID for Docent export.
"""

from __future__ import annotations

import os

import pytest
from dotenv import load_dotenv

load_dotenv()

_has_openai_key = bool(os.environ.get("OPENAI_API_KEY"))

requires_openai = pytest.mark.skipif(
  not _has_openai_key, reason="OPENAI_API_KEY not set"
)


# ---------------------------------------------------------------------------
# Docent integration — collect trajectories for upload via conftest hooks
# ---------------------------------------------------------------------------


def _record_docent_run(case: dict, events: list):
  """Convert and store an AgentRun for later Docent upload (via conftest)."""
  from tests.docent_export import _has_docent_config, adk_events_to_agent_run

  if not _has_docent_config():
    return

  from tests.conftest import docent_runs

  turns = case["turns"]
  turn_messages = [t["message"] for t in turns]

  agent_run = adk_events_to_agent_run(
    events,
    run_name=f"{case['id']}: {case['description']}",
    prompt=turn_messages[0],
    case_id=case["id"],
    category=case.get("category", ""),
    metadata={
      "expected": str(case["expected"]),
      "num_turns": len(turns),
      "all_turns": [t["message"][:200] for t in turns],
    },
    all_turn_messages=turn_messages,
  )
  docent_runs.append(agent_run)

# Lazy imports — only resolve if ADK + keys are available
_runner = None
_app_name = "secure-travel-test"


async def _get_runner():
  """Lazy-init a shared InMemoryRunner with the real TravelAgent."""
  global _runner
  if _runner is not None:
    return _runner

  from google.adk.runners import InMemoryRunner
  from agents.travel_agent import travel_agent, ADK_AVAILABLE

  if not ADK_AVAILABLE or travel_agent is None:
    pytest.skip("google-adk not available")

  _runner = InMemoryRunner(agent=travel_agent, app_name=_app_name)
  return _runner


async def _run_agent(prompt: str) -> list:
  """Run the TravelAgent with a single prompt and return the event list."""
  events, _ = await _run_agent_multi_turn([prompt])
  return events


async def _run_agent_multi_turn(
  messages: list[str],
) -> tuple[list, list[list]]:
  """Run the TravelAgent with multiple turns in one session.

  Returns:
    all_events: flat list of all events across all turns
    per_turn_events: list of event lists, one per turn
  """
  from google.genai import types

  runner = await _get_runner()

  session = await runner.session_service.create_session(
    app_name=_app_name,
    user_id="test_user",
  )

  all_events = []
  per_turn_events = []

  for message_text in messages:
    msg = types.Content(role="user", parts=[types.Part(text=message_text)])
    turn_events = []
    async for event in runner.run_async(
      user_id="test_user",
      session_id=session.id,
      new_message=msg,
    ):
      turn_events.append(event)
    all_events.extend(turn_events)
    per_turn_events.append(turn_events)

  return all_events, per_turn_events


def _extract_trajectory(events: list) -> dict:
  """Extract a structured trajectory summary from raw events."""
  trajectory = {
    "events": [],
    "delegations": [],
    "text_responses": [],
    "function_calls": [],
    "total_events": len(events),
  }

  for event in events:
    entry = {
      "author": event.author,
      "has_content": event.content is not None,
    }

    # Extract text
    if event.content and event.content.parts:
      texts = []
      for p in event.content.parts:
        if hasattr(p, "text") and p.text:
          texts.append(p.text)
      if texts:
        entry["text"] = " ".join(texts)
        trajectory["text_responses"].append({
          "author": event.author,
          "text": entry["text"],
        })

    # Extract function calls (including transfer_to_agent)
    func_calls = event.get_function_calls()
    if func_calls:
      for fc in func_calls:
        call_info = {"name": fc.name, "args": dict(fc.args) if fc.args else {}}
        entry.setdefault("function_calls", []).append(call_info)
        trajectory["function_calls"].append(call_info)

        if fc.name == "transfer_to_agent":
          delegate = fc.args.get("agent_name", "") if fc.args else ""
          trajectory["delegations"].append(delegate)

    trajectory["events"].append(entry)

  return trajectory


# ===========================================================================
# Data-driven trajectory tests
# ===========================================================================

from tests.data import TRAJECTORY_CASES  # noqa: E402


@requires_openai
class TestAgentTrajectory:
  """Parametrized trajectory tests driven by TRAJECTORY_CASES.

  Each case launches the TravelAgent via InMemoryRunner, collects the
  event stream, and validates delegation, text output, and event count.
  """

  @pytest.mark.asyncio
  @pytest.mark.parametrize(
    "case",
    TRAJECTORY_CASES,
    ids=[c["id"] for c in TRAJECTORY_CASES],
  )
  async def test_trajectory(self, case: dict, request):
    expected = case["expected"]
    turns = case["turns"]
    turn_messages = [t["message"] for t in turns]

    all_events, per_turn_events = await _run_agent_multi_turn(turn_messages)
    trajectory = _extract_trajectory(all_events)

    # Record for Docent export if --docent flag was passed
    if request.config.getoption("--docent", default=False):
      _record_docent_run(case, all_events)

    # 1. Must produce at least min_events across all turns
    assert trajectory["total_events"] >= expected["min_events"], (
      f"[{case['id']}] Too few events: got {trajectory['total_events']}, "
      f"expected >= {expected['min_events']}.\n"
      f"Description: {case['description']}\n"
      f"Why this matters: {expected['why_fail']}"
    )

    # 2. Check delegation behavior across all turns
    if expected["expect_delegation"]:
      assert len(trajectory["delegations"]) >= 1, (
        f"[{case['id']}] Expected delegation to {expected['valid_delegates']} "
        f"but no transfer_to_agent call found across {len(turns)} turns.\n"
        f"Events: {[e['author'] for e in trajectory['events']]}\n"
        f"Function calls: {trajectory['function_calls']}\n"
        f"Why this matters: {expected['why_fail']}"
      )

      for delegate in trajectory["delegations"]:
        assert delegate in expected["valid_delegates"], (
          f"[{case['id']}] Unexpected delegation target: {delegate}. "
          f"Expected one of {expected['valid_delegates']}.\n"
          f"Description: {case['description']}"
        )

    # 3. Check that enough turns produced text responses
    min_turns_with_text = expected.get("min_turns_with_text", 1)
    turns_with_text = sum(
      1 for turn_evts in per_turn_events
      if any(
        e.content and e.content.parts and any(
          hasattr(p, "text") and p.text for p in e.content.parts
        )
        for e in turn_evts
      )
    )
    assert turns_with_text >= min_turns_with_text, (
      f"[{case['id']}] Only {turns_with_text}/{len(turns)} turns produced text, "
      f"expected >= {min_turns_with_text}.\n"
      f"Why this matters: {expected['why_fail']}"
    )


# ===========================================================================
# Non-parametrized trajectory structure tests
# ===========================================================================

@requires_openai
class TestTrajectoryStructure:
  """Verify the trajectory event stream is well-formed."""

  @pytest.mark.asyncio
  async def test_event_has_author(self):
    """Every event must have a non-empty author field.

    Failure means: event stream metadata is broken.
    """
    events = await _run_agent("I need a car from SFO, April 10-15 2026.")
    for event in events:
      assert event.author, f"Event missing author: {event}"

  @pytest.mark.asyncio
  async def test_session_accumulates_events(self):
    """Session should accumulate events across the run.

    Failure means: session service is not recording events.
    """
    from google.genai import types

    runner = await _get_runner()
    session = await runner.session_service.create_session(
      app_name=_app_name,
      user_id="test_user",
    )

    msg = types.Content(
      role="user",
      parts=[types.Part(text="What car rental options do you have?")],
    )
    async for _ in runner.run_async(
      user_id="test_user",
      session_id=session.id,
      new_message=msg,
    ):
      pass

    updated = await runner.session_service.get_session(
      app_name=_app_name,
      user_id="test_user",
      session_id=session.id,
    )
    # Session should have at least user message + agent response
    assert len(updated.events) >= 2, (
      f"Session has only {len(updated.events)} events, expected >= 2."
    )

  @pytest.mark.asyncio
  async def test_multi_turn_conversation(self):
    """Multi-turn: second message should build on first turn's context.

    Failure means: session state is not preserved across turns.
    """
    from google.genai import types

    runner = await _get_runner()
    session = await runner.session_service.create_session(
      app_name=_app_name,
      user_id="test_user",
    )

    # Turn 1
    msg1 = types.Content(
      role="user",
      parts=[types.Part(text="I need a car from SFO, April 10-15 2026.")],
    )
    events1 = []
    async for event in runner.run_async(
      user_id="test_user",
      session_id=session.id,
      new_message=msg1,
    ):
      events1.append(event)

    assert len(events1) >= 1, "First turn produced no events."

    # Turn 2 — follow-up
    msg2 = types.Content(
      role="user",
      parts=[types.Part(text="Actually, make that an SUV instead.")],
    )
    events2 = []
    async for event in runner.run_async(
      user_id="test_user",
      session_id=session.id,
      new_message=msg2,
    ):
      events2.append(event)

    assert len(events2) >= 1, "Second turn produced no events."

    # Session should have events from both turns
    updated = await runner.session_service.get_session(
      app_name=_app_name,
      user_id="test_user",
      session_id=session.id,
    )
    assert len(updated.events) >= 4, (
      f"Multi-turn session has {len(updated.events)} events, expected >= 4."
    )
