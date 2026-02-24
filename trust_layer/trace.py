"""Pipeline trace dataclass for eval instrumentation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from trust_layer.audit_log import AuditEntry
from trust_layer.capability_tokens import CapabilityToken


# Recognized layer names for pipeline tracing
LAYER_NAMES = (
  "pii_sanitizer",
  "gliner_extraction",
  "quarantine_llm",
  "token_validation",
  "privilege_check",
  "input_sandbox",
  "api_sandbox",
  "output_sandbox",
)


@dataclass
class LayerResult:
  name: str
  status: str  # "passed", "blocked", "skipped", "warning"
  detail: str
  data: dict[str, Any] = field(default_factory=dict)


@dataclass
class PipelineTrace:
  layers: list[LayerResult] = field(default_factory=list)
  final_status: str = "pending"  # "executed", "blocked", "confirmation_required"
  token: Optional[CapabilityToken] = None
  audit_entry: Optional[AuditEntry] = None
  result: Optional[dict[str, Any]] = None  # Actual agent execution result

  def add(self, name: str, status: str, detail: str, **data: Any) -> None:
    self.layers.append(LayerResult(name=name, status=status, detail=detail, data=data))
