"""ADK Web entry point — exposes root_agent for `adk web` discovery."""

from agents.travel_agent import travel_agent as root_agent

__all__ = ["root_agent"]
