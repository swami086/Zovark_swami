"""HYDRA Python SDK — client library for the HYDRA SOC automation platform."""

from hydra.client import HydraClient
from hydra.models import Task, Alert, User, Stats
from hydra.exceptions import HydraAPIError, AuthenticationError, RateLimitError

__version__ = "0.1.0"
__all__ = [
    "HydraClient",
    "Task",
    "Alert",
    "User",
    "Stats",
    "HydraAPIError",
    "AuthenticationError",
    "RateLimitError",
]
