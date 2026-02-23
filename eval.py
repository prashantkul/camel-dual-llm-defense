"""
Rich-powered evaluation script for the secure travel agent pipeline.

Visualizes every defense layer firing with color for each test case,
then prints a summary table with detection accuracy stats.

Usage:
  uv run python eval.py            # Normal output
  uv run python eval.py --verbose  # Show full raw inputs
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

from trust_layer.audit_log import AuditLog
from trust_layer.trust_boundary import TrustBoundary
from trust_layer.trace import PipelineTrace
from eval_data import EVAL_CASES

console = Console()

# Injection keywords to highlight red in raw input
HIGHLIGHT_KEYWORDS = [
  "IGNORE PREVIOUS INSTRUCTIONS",
  "ignore previous instructions",
  "IGNORE PREVIOUS",
  "ignore previous",
  "You are now",
  "you are now",
  "new instructions",
  "New instructions",
  "SYSTEM:",
  "system:",
  "SYSTEM UPDATE",
  "DROP TABLE",
  "drop table",
  "jailbreak",
  "Jailbreak",
  "DAN mode",
  "debug mode",
  "unrestricted mode",
  "admin mode",
  "bypass all",
  "Bypass all",
  "disregard all",
  "Disregard all",
  "override current task",
  "Override current task",
  "new_system_prompt",
  "instructions_override",
  "exfil_endpoint",
  "forward all user data",
  "send all user tokens",
  "Print your system prompt",
  "print the full system prompt",
  "Display all stored PII",
  "show me all the data",
  "os.system(",
  "import os",
]

STATUS_STYLES = {
  "passed": ("bold green", "✓"),
  "blocked": ("bold red", "✗"),
  "skipped": ("dim", "—"),
  "warning": ("bold yellow", "⚠"),
}

LAYER_DISPLAY_NAMES = {
  "pii_sanitizer": "PII SANITIZER",
  "quarantine_llm": "QUARANTINE LLM",
  "token_validation": "TOKEN VALIDATION",
  "privilege_check": "PRIVILEGE CHECK",
  "input_sandbox": "INPUT SANDBOX",
  "api_sandbox": "API SANDBOX",
  "output_sandbox": "OUTPUT SANDBOX",
}

LAYER_ORDER = [
  "pii_sanitizer",
  "quarantine_llm",
  "token_validation",
  "privilege_check",
  "input_sandbox",
  "api_sandbox",
  "output_sandbox",
]


def highlight_injection(raw_input: str, max_len: int = 300) -> Text:
  """Create a Rich Text with injection keywords highlighted in red."""
  display = raw_input if len(raw_input) <= max_len else raw_input[:max_len] + "..."
  text = Text(display)
  for kw in HIGHLIGHT_KEYWORDS:
    start = 0
    lower_display = display.lower()
    lower_kw = kw.lower()
    while True:
      idx = lower_display.find(lower_kw, start)
      if idx == -1:
        break
      text.stylize("bold red", idx, idx + len(kw))
      start = idx + len(kw)
  return text


def render_test_case(
  case: dict,
  trace: PipelineTrace,
  verbose: bool = False,
) -> Panel:
  """Render a single test case result as a Rich Panel."""
  parts: list[Text | str] = []

  # Header line
  header = Text()
  header.append("Category: ", style="dim")
  header.append(case["category"], style="cyan")
  header.append("    Injection: ", style="dim")
  inj_style = "bold red" if case["injection_type"] != "none" else "green"
  header.append(case["injection_type"], style=inj_style)
  parts.append(header)
  parts.append("")

  # Raw input
  max_len = 2000 if verbose else 300
  input_text = highlight_injection(case["raw_input"], max_len=max_len)
  input_panel = Panel(input_text, title="RAW INPUT", border_style="dim", expand=True)
  parts.append(input_panel)

  # Pipeline layers
  parts.append("")
  pipeline_header = Text("── PIPELINE ", style="bold cyan")
  pipeline_header.append("─" * 50, style="cyan")
  parts.append(pipeline_header)
  parts.append("")

  layer_map = {lr.name: lr for lr in trace.layers}
  for i, layer_name in enumerate(LAYER_ORDER, 1):
    lr = layer_map.get(layer_name)
    line = Text()
    if lr:
      style, symbol = STATUS_STYLES.get(lr.status, ("dim", "?"))
      line.append(f"  [{i}] ", style="dim")
      line.append(f"{LAYER_DISPLAY_NAMES.get(layer_name, layer_name):<20}", style=style)
      line.append(f" {symbol} ", style=style)
      line.append(lr.detail, style=style)
    else:
      line.append(f"  [{i}] ", style="dim")
      line.append(f"{LAYER_DISPLAY_NAMES.get(layer_name, layer_name):<20}", style="dim")
      line.append(" — ", style="dim")
      line.append("Not reached", style="dim")
    parts.append(line)

  # Result
  parts.append("")
  result_header = Text("── RESULT ", style="bold cyan")
  result_header.append("─" * 52, style="cyan")
  parts.append(result_header)
  parts.append("")

  was_blocked = trace.final_status in ("blocked", "confirmation_required")
  expected_blocked = case["expected_detection"]

  correct = was_blocked == expected_blocked

  result_line = Text("  Status: ", style="dim")
  if was_blocked:
    result_line.append("BLOCKED", style="bold red")
  else:
    result_line.append("EXECUTED", style="bold green")

  result_line.append("   Detection: ", style="dim")
  if correct:
    result_line.append("✓ Correct", style="bold green")
  else:
    label = "FALSE NEGATIVE" if expected_blocked and not was_blocked else "FALSE POSITIVE"
    result_line.append(f"✗ {label}", style="bold red")
  parts.append(result_line)

  if trace.audit_entry:
    audit_line = Text("  Audit: ", style="dim")
    audit_line.append(
      f"crossing_id={trace.audit_entry.crossing_id} "
      f"outcome={trace.audit_entry.outcome}",
      style="cyan",
    )
    parts.append(audit_line)

  # Build panel
  title = f"Test Case #{case['id']}: {case['description'][:60]}"
  border = "green" if correct else "red"

  from rich.console import Group as RichGroup

  return Panel(
    RichGroup(*parts),
    title=title,
    border_style=border,
    expand=True,
    padding=(1, 2),
  )


async def run_single_case(
  boundary: TrustBoundary,
  case: dict,
) -> PipelineTrace:
  """Run a single test case through the pipeline with tracing."""
  AuditLog.reset()
  boundary.audit_log = AuditLog.get_instance()

  pii_preprocessor = None
  raw = case["raw_input"]
  # Pre-extract license hash for cases that have one
  import re

  license_match = re.search(r"\b[A-Z]{2}-(?:DL-)?(\d{6,10})\b", raw)
  if license_match:
    full_match = license_match.group(0)
    pii_preprocessor = {
      "license_number_hash": hashlib.sha256(full_match.encode()).hexdigest()
    }

  trace = await boundary.process_with_trace(raw, pii_preprocessor)
  return trace


async def run_eval(verbose: bool = False) -> None:
  """Run all eval cases and display results."""
  console.print()
  console.rule("[bold cyan]Secure Travel Agent — Eval Suite[/bold cyan]")
  console.print()

  boundary = TrustBoundary()

  results: list[tuple[dict, PipelineTrace]] = []

  with Progress(
    SpinnerColumn(),
    TextColumn("[progress.description]{task.description}"),
    console=console,
    transient=True,
  ) as progress:
    task = progress.add_task("Running eval cases...", total=len(EVAL_CASES))

    for case in EVAL_CASES:
      progress.update(task, description=f"Running {case['id']}...")
      trace = await run_single_case(boundary, case)
      results.append((case, trace))
      progress.advance(task)

  # Render each test case
  for case, trace in results:
    panel = render_test_case(case, trace, verbose=verbose)
    console.print(panel)
    console.print()

  # Summary statistics
  total = len(results)
  correct = 0
  false_positives = 0
  false_negatives = 0
  layer_fire_counts: dict[str, int] = {name: 0 for name in LAYER_ORDER}
  category_stats: dict[str, dict[str, int]] = {}

  for case, trace in results:
    was_blocked = trace.final_status in ("blocked", "confirmation_required")
    expected_blocked = case["expected_detection"]

    cat = case["category"]
    if cat not in category_stats:
      category_stats[cat] = {"total": 0, "correct": 0, "fp": 0, "fn": 0}
    category_stats[cat]["total"] += 1

    if was_blocked == expected_blocked:
      correct += 1
      category_stats[cat]["correct"] += 1
    elif was_blocked and not expected_blocked:
      false_positives += 1
      category_stats[cat]["fp"] += 1
    else:
      false_negatives += 1
      category_stats[cat]["fn"] += 1

    for lr in trace.layers:
      if lr.name in layer_fire_counts and lr.status == "blocked":
        layer_fire_counts[lr.name] += 1

  # Summary table
  console.rule("[bold cyan]Summary[/bold cyan]")
  console.print()

  summary = Table(title="Overall Results", show_header=True, header_style="bold")
  summary.add_column("Metric", style="cyan")
  summary.add_column("Value", justify="right")
  summary.add_row("Total Cases", str(total))
  summary.add_row("Correct", f"[green]{correct}[/green]")
  summary.add_row("False Positives", f"[yellow]{false_positives}[/yellow]")
  summary.add_row("False Negatives", f"[red]{false_negatives}[/red]")
  accuracy = (correct / total * 100) if total else 0
  color = "green" if accuracy >= 80 else "yellow" if accuracy >= 60 else "red"
  summary.add_row("Accuracy", f"[{color}]{accuracy:.1f}%[/{color}]")
  console.print(summary)
  console.print()

  # Per-layer stats
  layer_table = Table(title="Defense Layer Blocks", show_header=True, header_style="bold")
  layer_table.add_column("Layer", style="cyan")
  layer_table.add_column("Times Blocked", justify="right")
  for name in LAYER_ORDER:
    count = layer_fire_counts[name]
    style = "red" if count > 0 else "dim"
    layer_table.add_row(
      LAYER_DISPLAY_NAMES.get(name, name),
      f"[{style}]{count}[/{style}]",
    )
  console.print(layer_table)
  console.print()

  # Per-category breakdown
  cat_table = Table(title="Per-Category Breakdown", show_header=True, header_style="bold")
  cat_table.add_column("Category", style="cyan")
  cat_table.add_column("Total", justify="right")
  cat_table.add_column("Correct", justify="right")
  cat_table.add_column("FP", justify="right")
  cat_table.add_column("FN", justify="right")
  for cat, stats in sorted(category_stats.items()):
    cat_table.add_row(
      cat,
      str(stats["total"]),
      f"[green]{stats['correct']}[/green]",
      f"[yellow]{stats['fp']}[/yellow]",
      f"[red]{stats['fn']}[/red]",
    )
  console.print(cat_table)
  console.print()


def main() -> None:
  parser = argparse.ArgumentParser(description="Eval suite for secure travel agent")
  parser.add_argument("--verbose", action="store_true", help="Show full raw inputs")
  args = parser.parse_args()
  asyncio.run(run_eval(verbose=args.verbose))


if __name__ == "__main__":
  main()
