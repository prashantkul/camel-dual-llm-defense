"""Shared pytest configuration and Docent integration hooks."""

from __future__ import annotations


def pytest_addoption(parser):
  parser.addoption(
    "--docent", action="store_true", default=False,
    help="Export trajectory runs to Docent after test session",
  )


# Accumulated AgentRun objects from trajectory tests
docent_runs: list = []


def pytest_sessionfinish(session, exitstatus):
  """Upload collected trajectories to Docent after test session ends."""
  if not session.config.getoption("--docent", default=False):
    return
  if not docent_runs:
    return

  from tests.docent_export import _has_docent_config, upload_runs

  if not _has_docent_config():
    print("\n[docent] Skipping upload — DOCENT_API_KEY/DOCENT_COLLECTION_ID not set")
    return

  print(f"\n[docent] Uploading {len(docent_runs)} trajectory runs to Docent...")
  try:
    result = upload_runs(docent_runs)
    print(f"[docent] Upload complete: {result}")
  except Exception as e:
    print(f"[docent] Upload failed: {e}")
