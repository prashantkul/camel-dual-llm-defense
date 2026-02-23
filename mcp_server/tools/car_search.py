"""Simulated car rental search engine."""

from __future__ import annotations

import uuid
from typing import Any


class CarSearchEngine:
  """Simulated third-party car rental API."""

  MOCK_INVENTORY = [
    {
      "car_id": "car-001",
      "make": "Toyota",
      "model": "Corolla",
      "year": 2025,
      "class": "economy",
      "daily_rate_cents": 4500,
      "currency": "USD",
      "features": ["bluetooth", "backup_camera"],
      "availability": True,
    },
    {
      "car_id": "car-002",
      "make": "Honda",
      "model": "Accord",
      "year": 2025,
      "class": "midsize",
      "daily_rate_cents": 6500,
      "currency": "USD",
      "features": ["bluetooth", "backup_camera", "lane_assist"],
      "availability": True,
    },
    {
      "car_id": "car-003",
      "make": "Ford",
      "model": "Explorer",
      "year": 2025,
      "class": "suv",
      "daily_rate_cents": 9500,
      "currency": "USD",
      "features": ["bluetooth", "backup_camera", "4wd", "third_row"],
      "availability": True,
    },
    {
      "car_id": "car-004",
      "make": "BMW",
      "model": "5 Series",
      "year": 2025,
      "class": "luxury",
      "daily_rate_cents": 15000,
      "currency": "USD",
      "features": ["bluetooth", "backup_camera", "heated_seats", "sunroof"],
      "availability": True,
    },
  ]

  @classmethod
  async def search(cls, params: dict[str, Any]) -> dict[str, Any]:
    """Simulate a car search API call."""
    car_class = params.get("car_class", "any")

    if car_class == "any":
      results = cls.MOCK_INVENTORY
    else:
      results = [c for c in cls.MOCK_INVENTORY if c["class"] == car_class]

    for car in results:
      car["pickup_location"] = params.get("pickup_location", "")
      car["dropoff_location"] = params.get("dropoff_location", "")

    return {
      "cars": results,
      "search_id": uuid.uuid4().hex[:36],
    }
