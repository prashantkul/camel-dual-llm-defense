"""Audit trail for all trust boundary crossings."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import ClassVar

from trust_layer.capability_tokens import CapabilityToken


@dataclass
class AuditEntry:
  crossing_id: str
  timestamp: str
  intent: str
  risk_level: str
  injection_detected: bool
  confirmation_required: bool
  outcome: str = "pending"

  @classmethod
  def from_token(cls, token: CapabilityToken) -> AuditEntry:
    return cls(
      crossing_id=uuid.uuid4().hex[:12],
      timestamp=datetime.now(timezone.utc).isoformat(),
      intent=token.intent.value,
      risk_level=token.risk_level.value,
      injection_detected=token.injection_detected,
      confirmation_required=token.user_confirmation_required,
    )


@dataclass
class AuditLog:
  """In-memory audit log for trust boundary crossings. Per-session singleton."""

  _entries: list[AuditEntry] = field(default_factory=list)
  _instance: ClassVar[AuditLog | None] = None

  @classmethod
  def get_instance(cls) -> AuditLog:
    if cls._instance is None:
      cls._instance = cls()
    return cls._instance

  async def record_crossing(self, token: CapabilityToken) -> AuditEntry:
    entry = AuditEntry.from_token(token)
    self._entries.append(entry)
    return entry

  def mark_outcome(self, crossing_id: str, outcome: str) -> None:
    for entry in self._entries:
      if entry.crossing_id == crossing_id:
        entry.outcome = outcome
        return

  @classmethod
  def get_session_crossings(cls) -> list[AuditEntry]:
    return cls.get_instance()._entries

  @classmethod
  def print_all_crossings(cls) -> None:
    for entry in cls.get_session_crossings():
      print(
        f"  [{entry.timestamp}] {entry.crossing_id} | "
        f"intent={entry.intent} risk={entry.risk_level} "
        f"injection={entry.injection_detected} outcome={entry.outcome}"
      )

  @classmethod
  def reset(cls) -> None:
    cls._instance = None
