#!/usr/bin/env python3
"""
Export DeepTeam attack reports to Docent for comparative analysis.

Converts DeepTeam JSON reports (from reports/) into Docent AgentRun objects.
Each attack becomes one AgentRun with turn-by-turn conversation as a Transcript.

Uploads to the same Docent collection used by the trajectory tests, enabling
side-by-side analysis of CaMeL defense vs vulnerable agent behavior.

Usage:
  cd secure-travel-agent
  uv run --extra dev python tests/docent_deepteam_export.py
  uv run --extra dev python tests/docent_deepteam_export.py reports/camel_defense_*.json
"""

from __future__ import annotations

import glob
import json
import os
import sys
import uuid
from datetime import datetime, timezone

from dotenv import load_dotenv

load_dotenv()

DOCENT_API_KEY = os.environ.get("DOCENT_API_KEY", "")
DOCENT_COLLECTION_ID = os.environ.get("DOCENT_COLLECTION_ID", "")

# Project root for locating reports/
PROJECT_ROOT = os.path.join(os.path.dirname(__file__), "..")


def _has_docent_config() -> bool:
  return bool(DOCENT_API_KEY and DOCENT_COLLECTION_ID)


def conversation_log_to_agent_run(
  conversation_log: list[dict],
  *,
  run_name: str,
  vulnerability: str = "",
  turns: int = 0,
  base_attack: str = "",
  enhanced_attack: str = "",
  target: str = "",
  outcome: str = "",
  metadata: dict | None = None,
):
  """Convert a DeepTeam conversation log to a Docent AgentRun."""
  from docent.data_models import AgentRun, Transcript
  from docent.data_models.chat.message import (
    AssistantMessage,
    UserMessage,
  )

  messages = []
  for entry in conversation_log:
    messages.append(UserMessage(
      id=str(uuid.uuid4()),
      content=entry.get("prompt", ""),
      role="user",
      metadata={"turn": entry.get("turn", 0)},
    ))
    messages.append(AssistantMessage(
      id=str(uuid.uuid4()),
      content=entry.get("response", ""),
      role="assistant",
      metadata={
        "turn": entry.get("turn", 0),
        "is_final_enhanced": entry.get("is_final_enhanced", False),
      },
    ))

  run_metadata = {
    "source": "deepteam",
    "vulnerability": vulnerability,
    "turns": turns,
    "target": target,
    "outcome": outcome,
    "base_attack": base_attack,
    "timestamp": datetime.now(timezone.utc).isoformat(),
  }
  if metadata:
    run_metadata.update(metadata)

  transcript = Transcript(
    id=str(uuid.uuid4()),
    name=run_name,
    messages=messages,
    metadata={
      "vulnerability": vulnerability,
      "turns": turns,
      "target": target,
    },
  )

  return AgentRun(
    id=str(uuid.uuid4()),
    name=run_name,
    description=f"DeepTeam {vulnerability} attack ({turns}t) vs {target}",
    transcripts=[transcript],
    metadata=run_metadata,
  )


def export_defense_report(report_path: str) -> list:
  """Export a camel_defense_*.json report to Docent AgentRuns."""
  with open(report_path) as f:
    report = json.load(f)

  runs = []
  for result in report.get("results", []):
    if result.get("status") != "success":
      continue

    conv_log = result.get("conversation_log", [])
    if not conv_log:
      continue

    vuln = result.get("vulnerability", "unknown")
    turns = result.get("turns", 0)

    run = conversation_log_to_agent_run(
      conv_log,
      run_name=f"CaMeL Defense: {vuln} ({turns}t)",
      vulnerability=vuln,
      turns=turns,
      base_attack=result.get("base_attack", ""),
      enhanced_attack=result.get("enhanced_attack", ""),
      target="camel",
      outcome="blocked" if result.get("final_blocked") else "allowed",
      metadata={
        "all_turns_blocked": result.get("all_turns_blocked", False),
        "report_file": os.path.basename(report_path),
      },
    )
    runs.append(run)

  return runs


def export_comparative_report(report_path: str) -> list:
  """Export a camel_vs_vulnerable_*.json report to Docent AgentRuns."""
  with open(report_path) as f:
    report = json.load(f)

  runs = []
  for comparison in report.get("comparisons", []):
    vuln = comparison.get("vulnerability", "unknown")
    turns = comparison.get("turns", 0)
    base_attack = comparison.get("base_attack", "")
    comp_outcome = comparison.get("outcome", "unknown")

    for target_key, target_name in [
      ("vulnerable_result", "vulnerable"),
      ("camel_result", "camel"),
    ]:
      target_result = comparison.get(target_key, {})
      conv_log = target_result.get("conversation_log", [])
      if not conv_log:
        continue

      run = conversation_log_to_agent_run(
        conv_log,
        run_name=f"Comparative {vuln} ({turns}t) — {target_name}",
        vulnerability=vuln,
        turns=turns,
        base_attack=base_attack,
        enhanced_attack=target_result.get("enhanced_attack", ""),
        target=target_name,
        outcome=comp_outcome,
        metadata={
          "comparison_outcome": comp_outcome,
          "final_blocked": target_result.get("final_blocked", False),
          "report_file": os.path.basename(report_path),
        },
      )
      runs.append(run)

  return runs


def upload_runs(runs: list) -> dict:
  """Upload AgentRun objects to Docent collection."""
  from docent import Docent

  client = Docent(api_key=DOCENT_API_KEY)
  result = client.add_agent_runs(DOCENT_COLLECTION_ID, runs)
  return result


def main():
  if not _has_docent_config():
    print("ERROR: Set DOCENT_API_KEY and DOCENT_COLLECTION_ID in .env")
    sys.exit(1)

  reports_dir = os.path.join(PROJECT_ROOT, "reports")

  # Determine which files to export
  if len(sys.argv) > 1:
    report_files = sys.argv[1:]
  else:
    report_files = sorted(glob.glob(os.path.join(reports_dir, "camel_defense_*.json"))) + sorted(
      glob.glob(os.path.join(reports_dir, "camel_vs_vulnerable_*.json"))
    )

  if not report_files:
    print(f"No report files found in {reports_dir}/")
    print("Run test_camel_defense.py or test_camel_vs_vulnerable.py first.")
    sys.exit(1)

  all_runs = []

  for report_path in report_files:
    print(f"Processing: {report_path}")
    basename = os.path.basename(report_path)

    if basename.startswith("camel_defense_"):
      runs = export_defense_report(report_path)
    elif basename.startswith("camel_vs_vulnerable_"):
      runs = export_comparative_report(report_path)
    else:
      print(f"  Skipping unknown report format: {basename}")
      continue

    print(f"  Extracted {len(runs)} AgentRuns")
    all_runs.extend(runs)

  if not all_runs:
    print("No runs to upload.")
    sys.exit(0)

  print(f"\nUploading {len(all_runs)} runs to Docent collection {DOCENT_COLLECTION_ID[:8]}...")
  result = upload_runs(all_runs)
  print(f"Upload complete: {result}")


if __name__ == "__main__":
  main()
