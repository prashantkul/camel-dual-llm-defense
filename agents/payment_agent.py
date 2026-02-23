"""Secure payment processing sub-agent."""

from __future__ import annotations

from trust_layer.config import load_config, load_full_config, resolve_adk_model

try:
  _, _adk_config = load_config()
except FileNotFoundError:
  _adk_config = None

try:
  _app_config = load_full_config()
except FileNotFoundError:
  _app_config = None

try:
  from google.adk.agents import LlmAgent

  _pay_model_str = _adk_config.payment_model if _adk_config else "gemini-2.0-flash"
  _pay_model = resolve_adk_model(_pay_model_str)
  _pay_name = _adk_config.payment_name if _adk_config else "PaymentAgent"

  _pa_prompts = _app_config.agents.payment_agent if _app_config else None
  _description = (
    _pa_prompts.description if _pa_prompts and _pa_prompts.description
    else (
      "Secure payment processing agent. "
      "Handles tokenized payment operations only."
    )
  )
  _instruction = (
    _pa_prompts.instruction if _pa_prompts and _pa_prompts.instruction
    else """\
You are a secure payment processing agent.

ABSOLUTE RULES:
1. NEVER accept raw card numbers, CVVs, or bank account numbers.
2. Only process payments using tokenized payment references.
3. Always display the exact amount and booking reference before charging.
4. Use idempotency keys for all payment operations — prevent double charges.
5. If payment token appears malformed or suspicious, REJECT and alert user.
6. Payment confirmation codes must be logged to audit trail.

You receive PaymentTokens (not raw payment data) from the CaMel layer.
"""
  )

  payment_agent = LlmAgent(
    name=_pay_name,
    model=_pay_model,
    description=_description,
    instruction=_instruction,
    tools=[],
  )
except ImportError:
  payment_agent = None
