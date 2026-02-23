"""Export ADK agent trajectories to Docent for analysis.

Converts ADK Runner event streams into Docent AgentRun objects and uploads
them to a Docent collection. Supports multi-turn conversations — user messages
are interleaved between agent events to produce complete transcripts.

Can be used:
  1. Programmatically from test_trajectory.py (via pytest fixture)
  2. Standalone: `uv run python -m tests.docent_export`

Requires DOCENT_API_KEY and DOCENT_COLLECTION_ID in .env.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone

from dotenv import load_dotenv

load_dotenv()

DOCENT_API_KEY = os.environ.get("DOCENT_API_KEY", "")
DOCENT_COLLECTION_ID = os.environ.get("DOCENT_COLLECTION_ID", "")


def _has_docent_config() -> bool:
  return bool(DOCENT_API_KEY and DOCENT_COLLECTION_ID)


def _convert_events_to_messages(events: list, user_messages: list[str]):
  """Convert ADK events into Docent ChatMessage list with interleaved user turns.

  For multi-turn conversations, we need to figure out where each turn's events
  start and end so we can insert UserMessages between them. We detect turn
  boundaries by tracking when the author cycles back to the root agent after
  a sequence of events.

  Strategy: Since we know how many user messages there are, and events are
  ordered chronologically, we insert user messages at the boundaries where
  the agent "resets" — i.e. the first event of each turn typically comes from
  the root TravelAgent.
  """
  from docent.data_models.chat.message import UserMessage

  messages = []

  # For single-turn, just prepend the user message
  if len(user_messages) <= 1:
    messages.append(UserMessage(
      id=str(uuid.uuid4()),
      content=user_messages[0] if user_messages else "",
      role="user",
    ))
    _append_agent_events(messages, events)
    return messages

  # Multi-turn: split events into per-turn groups.
  # Each turn starts when we see the root agent (TravelAgent) author after
  # having seen other authors or at the very beginning.
  turn_groups: list[list] = []
  current_group: list = []

  for i, event in enumerate(events):
    # Detect turn boundary: root agent appears after gap
    # Heuristic: if we see TravelAgent and current_group is non-empty
    # and the previous event was also from a different turn context
    if (
      i > 0
      and event.author == "TravelAgent"
      and current_group
      and len(turn_groups) < len(user_messages) - 1
      # Only split if we've accumulated enough events for a turn
      and len(current_group) >= 1
      # Check if previous event was a text response (end of turn)
      and _has_text_content(events[i - 1])
    ):
      turn_groups.append(current_group)
      current_group = [event]
    else:
      current_group.append(event)

  if current_group:
    turn_groups.append(current_group)

  # If we couldn't detect enough boundaries, fall back to even splitting
  if len(turn_groups) < len(user_messages):
    turn_groups = _split_events_evenly(events, len(user_messages))

  # Interleave: user message → agent events → user message → agent events...
  for turn_idx, user_msg in enumerate(user_messages):
    messages.append(UserMessage(
      id=str(uuid.uuid4()),
      content=user_msg,
      role="user",
      metadata={"turn": turn_idx + 1},
    ))
    if turn_idx < len(turn_groups):
      _append_agent_events(messages, turn_groups[turn_idx])

  return messages


def _has_text_content(event) -> bool:
  """Check if an event has text content."""
  if event.content and event.content.parts:
    return any(hasattr(p, "text") and p.text for p in event.content.parts)
  return False


def _split_events_evenly(events: list, num_groups: int) -> list[list]:
  """Fall back: split events into roughly equal groups."""
  if not events or num_groups <= 0:
    return [[] for _ in range(num_groups)]
  chunk_size = max(1, len(events) // num_groups)
  groups = []
  for i in range(0, len(events), chunk_size):
    groups.append(events[i : i + chunk_size])
  # Merge overflow into last group
  while len(groups) > num_groups:
    groups[-2].extend(groups[-1])
    groups.pop()
  # Pad if needed
  while len(groups) < num_groups:
    groups.append([])
  return groups


def _append_agent_events(messages: list, events: list):
  """Convert ADK events to Docent messages and append to the list."""
  from docent.data_models.chat.message import (
    AssistantMessage,
    ToolCall,
    ToolMessage,
  )

  for event in events:
    author = event.author or "unknown"

    # Extract function calls
    func_calls = event.get_function_calls() if hasattr(event, "get_function_calls") else []
    tool_calls = []
    for fc in func_calls:
      tool_calls.append(ToolCall(
        id=str(uuid.uuid4()),
        function=fc.name,
        arguments=dict(fc.args) if fc.args else {},
      ))

    # Extract function responses
    func_responses = (
      event.get_function_responses()
      if hasattr(event, "get_function_responses")
      else []
    )

    # Extract text content
    text_parts = []
    if event.content and event.content.parts:
      for p in event.content.parts:
        if hasattr(p, "text") and p.text:
          text_parts.append(p.text)

    content = " ".join(text_parts) if text_parts else ""

    # Function responses → ToolMessages
    if func_responses:
      for fr in func_responses:
        resp_text = ""
        if hasattr(fr, "response") and fr.response:
          resp_text = str(fr.response)
        messages.append(ToolMessage(
          id=str(uuid.uuid4()),
          content=resp_text,
          role="tool",
          function=fr.name if hasattr(fr, "name") else "unknown",
        ))
      continue

    # Text/tool_calls → AssistantMessage
    if content or tool_calls:
      messages.append(AssistantMessage(
        id=str(uuid.uuid4()),
        content=content or f"[{author} — no text output]",
        role="assistant",
        tool_calls=tool_calls if tool_calls else None,
        metadata={"adk_author": author},
      ))


def adk_events_to_agent_run(
  events: list,
  *,
  run_name: str,
  prompt: str,
  case_id: str = "",
  category: str = "",
  metadata: dict | None = None,
  all_turn_messages: list[str] | None = None,
):
  """Convert ADK Runner events into a Docent AgentRun.

  For multi-turn conversations, pass all_turn_messages with all user messages.
  The events are split into turn groups and interleaved with user messages.
  """
  from docent.data_models import AgentRun, Transcript

  user_messages = all_turn_messages if all_turn_messages else [prompt]
  messages = _convert_events_to_messages(events, user_messages)

  run_metadata = {
    "case_id": case_id,
    "category": category,
    "source": "test_trajectory",
    "num_turns": len(user_messages),
    "timestamp": datetime.now(timezone.utc).isoformat(),
  }
  if metadata:
    run_metadata.update(metadata)

  transcript = Transcript(
    id=str(uuid.uuid4()),
    name=run_name,
    messages=messages,
    metadata={
      "prompt": prompt,
      "category": category,
      "num_turns": len(user_messages),
    },
  )

  return AgentRun(
    id=str(uuid.uuid4()),
    name=run_name,
    description=f"Multi-turn trajectory ({len(user_messages)} turns): {prompt[:80]}",
    transcripts=[transcript],
    metadata=run_metadata,
  )


def upload_runs(runs: list) -> dict:
  """Upload AgentRun objects to Docent collection."""
  from docent import Docent

  client = Docent(api_key=DOCENT_API_KEY)
  result = client.add_agent_runs(DOCENT_COLLECTION_ID, runs)
  return result


# ---------------------------------------------------------------------------
# Standalone entrypoint — run all trajectory cases and export
# ---------------------------------------------------------------------------

async def _run_all_and_export():
  """Execute all TRAJECTORY_CASES as multi-turn conversations and upload to Docent."""
  from google.adk.runners import InMemoryRunner
  from google.genai import types

  from agents.travel_agent import travel_agent
  from tests.data import TRAJECTORY_CASES

  print(f"Running {len(TRAJECTORY_CASES)} trajectory cases (multi-turn)...")

  runner = InMemoryRunner(agent=travel_agent, app_name="docent-export")
  runs = []

  for case in TRAJECTORY_CASES:
    case_id = case["id"]
    turns = case["turns"]
    print(f"  [{case_id}] {case['description']} ({len(turns)} turns)...")

    session = await runner.session_service.create_session(
      app_name="docent-export",
      user_id="docent_export_user",
    )

    all_events = []
    for turn_idx, turn in enumerate(turns):
      msg = types.Content(role="user", parts=[types.Part(text=turn["message"])])
      async for event in runner.run_async(
        user_id="docent_export_user",
        session_id=session.id,
        new_message=msg,
      ):
        all_events.append(event)
      print(f"    turn {turn_idx + 1}/{len(turns)}: {len(all_events)} total events")

    turn_messages = [t["message"] for t in turns]
    agent_run = adk_events_to_agent_run(
      all_events,
      run_name=f"{case_id}: {case['description']}",
      prompt=turn_messages[0],
      case_id=case_id,
      category=case.get("category", ""),
      metadata={"expected": str(case["expected"])},
      all_turn_messages=turn_messages,
    )
    runs.append(agent_run)
    print(f"    → {len(all_events)} events, {len(agent_run.transcripts[0].messages)} messages")

  print(f"\nUploading {len(runs)} runs to Docent collection {DOCENT_COLLECTION_ID[:8]}...")
  result = upload_runs(runs)
  print(f"Upload complete: {result}")
  return result


if __name__ == "__main__":
  import asyncio

  if not _has_docent_config():
    print("ERROR: Set DOCENT_API_KEY and DOCENT_COLLECTION_ID in .env")
    raise SystemExit(1)

  asyncio.run(_run_all_and_export())
