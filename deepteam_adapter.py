"""
DeepTeam adapter — wraps CaMeL TrustBoundary as a sync callback.

DeepTeam's attack.enhance() and red_team() expect a sync callback:
  callback(prompt: str) -> str

This module provides two flavors:
  - create_camel_callback()   — simple function callback
  - CamelSessionCallback      — class with conversation logging

When CaMeL detects injection → {"status": "blocked"} → DeepTeam sees a failed attack.
When CaMeL allows the request → returns structured result from privileged LLM.
"""

from __future__ import annotations

import asyncio
import json
import uuid

from trust_layer.trust_boundary import TrustBoundary


def create_camel_callback(session_continuity=True):
  """Create a CaMeL TrustBoundary callback for DeepTeam testing.

  Args:
    session_continuity: If True, reuse the same TrustBoundary across turns
      (mirrors the vulnerable agent's session-based callback).

  Returns:
    A sync callback function: (prompt: str) -> str
  """
  boundary = TrustBoundary()
  conversation_log: list[dict] = []
  loop = asyncio.new_event_loop()

  def callback(prompt: str) -> str:
    turn = len(conversation_log) + 1
    try:
      token = loop.run_until_complete(boundary.process_user_request(prompt))

      if token.injection_detected:
        result = {
          "status": "blocked",
          "reason": "Injection detected by quarantine LLM",
          "risk_level": token.risk_level.value,
          "intent": token.intent.value,
          "turn": turn,
        }
      else:
        result = loop.run_until_complete(boundary.execute_with_privilege(token))
        result["turn"] = turn

      response = json.dumps(result, default=str)

    except ValueError as e:
      # PII rejection (SSN, credit card in raw input)
      response = json.dumps({
        "status": "blocked",
        "reason": str(e),
        "turn": turn,
      })
    except Exception as e:
      response = json.dumps({
        "status": "error",
        "reason": str(e),
        "turn": turn,
      })

    conversation_log.append({
      "turn": turn,
      "prompt": prompt,
      "response": response,
    })
    return response

  # Attach log for external access
  callback.conversation_log = conversation_log  # type: ignore[attr-defined]
  callback.boundary = boundary  # type: ignore[attr-defined]
  return callback


class CamelSessionCallback:
  """Session-aware CaMeL callback with conversation logging.

  Mirrors the deep-team SessionMaintainingCallback but routes through
  CaMeL's trust boundary instead of the vulnerable agent.
  """

  def __init__(self, attack_name: str | None = None):
    self.attack_name = attack_name or "unknown"
    self.session_id = f"camel_{uuid.uuid4().hex[:8]}"
    self.boundary = TrustBoundary()
    self.turn_count = 0
    self.conversation_log: list[dict] = []
    self._loop = asyncio.new_event_loop()

  def __call__(self, prompt: str) -> str:
    self.turn_count += 1
    try:
      token = self._loop.run_until_complete(
        self.boundary.process_user_request(prompt)
      )

      if token.injection_detected:
        result = {
          "status": "blocked",
          "reason": "Injection detected by quarantine LLM",
          "risk_level": token.risk_level.value,
          "intent": token.intent.value,
        }
      else:
        result = self._loop.run_until_complete(
          self.boundary.execute_with_privilege(token)
        )

      response = json.dumps(result, default=str)

    except ValueError as e:
      response = json.dumps({"status": "blocked", "reason": str(e)})
    except Exception as e:
      response = json.dumps({"status": "error", "reason": str(e)})

    self.conversation_log.append({
      "turn": self.turn_count,
      "prompt": prompt,
      "response": response,
    })
    return response

  def get_summary(self) -> dict:
    blocked = sum(
      1 for entry in self.conversation_log
      if '"blocked"' in entry["response"]
    )
    return {
      "attack_name": self.attack_name,
      "session_id": self.session_id,
      "total_turns": self.turn_count,
      "blocked_count": blocked,
      "conversation_log": self.conversation_log,
    }
