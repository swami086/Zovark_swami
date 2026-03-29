"""Zovark SDK data models.

Simple data classes (no external dependencies) representing API resources.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Task:
    """Represents an investigation task."""

    task_id: str
    status: str
    task_type: str = ""
    input: Optional[Dict[str, Any]] = None
    output: Optional[Dict[str, Any]] = None
    created_at: Optional[str] = None
    completed_at: Optional[str] = None
    tokens_used_input: Optional[int] = None
    tokens_used_output: Optional[int] = None
    execution_ms: Optional[int] = None
    severity: Optional[str] = None
    step_count: int = 0
    current_step: Optional[int] = None
    workflow_id: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict) -> "Task":
        """Create a Task from an API response dict."""
        return cls(
            task_id=data.get("task_id") or data.get("id", ""),
            status=data.get("status", "unknown"),
            task_type=data.get("task_type", ""),
            input=data.get("input"),
            output=data.get("output"),
            created_at=data.get("created_at"),
            completed_at=data.get("completed_at"),
            tokens_used_input=data.get("tokens_used_input"),
            tokens_used_output=data.get("tokens_used_output"),
            execution_ms=data.get("execution_ms"),
            severity=data.get("severity"),
            step_count=data.get("step_count", 0),
            current_step=data.get("current_step"),
            workflow_id=data.get("workflow_id"),
        )

    @property
    def is_complete(self) -> bool:
        return self.status in ("completed", "failed", "awaiting_approval")

    @property
    def is_success(self) -> bool:
        return self.status == "completed"


@dataclass
class Alert:
    """Represents a SIEM alert."""

    id: str
    title: str = ""
    severity: str = ""
    status: str = "new"
    source: Optional[str] = None
    description: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None
    created_at: Optional[str] = None
    tenant_id: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict) -> "Alert":
        return cls(
            id=data.get("id", ""),
            title=data.get("title", ""),
            severity=data.get("severity", ""),
            status=data.get("status", "new"),
            source=data.get("source"),
            description=data.get("description"),
            raw_data=data.get("raw_data"),
            created_at=data.get("created_at"),
            tenant_id=data.get("tenant_id"),
        )


@dataclass
class User:
    """Represents an authenticated user."""

    id: str
    email: str
    role: str
    tenant_id: str

    @classmethod
    def from_dict(cls, data: dict) -> "User":
        return cls(
            id=data.get("id", ""),
            email=data.get("email", ""),
            role=data.get("role", ""),
            tenant_id=data.get("tenant_id", ""),
        )


@dataclass
class Stats:
    """Platform statistics."""

    total_tasks: int = 0
    completed: int = 0
    failed: int = 0
    pending: int = 0
    executing: int = 0
    total_tokens_input: int = 0
    total_tokens_output: int = 0
    type_distribution: Optional[Dict[str, int]] = None
    siem_alerts_total: int = 0
    siem_alerts_new: int = 0
    recent_activity: Optional[List[Dict[str, Any]]] = None

    @classmethod
    def from_dict(cls, data: dict) -> "Stats":
        return cls(
            total_tasks=data.get("total_tasks", 0),
            completed=data.get("completed", 0),
            failed=data.get("failed", 0),
            pending=data.get("pending", 0),
            executing=data.get("executing", 0),
            total_tokens_input=data.get("total_tokens_input", 0),
            total_tokens_output=data.get("total_tokens_output", 0),
            type_distribution=data.get("type_distribution"),
            siem_alerts_total=data.get("siem_alerts_total", 0),
            siem_alerts_new=data.get("siem_alerts_new", 0),
            recent_activity=data.get("recent_activity"),
        )

    @property
    def success_rate(self) -> float:
        if self.total_tasks == 0:
            return 0.0
        return self.completed / self.total_tasks


@dataclass
class TaskList:
    """Paginated list of tasks."""

    tasks: List[Task] = field(default_factory=list)
    total: int = 0
    page: int = 1
    limit: int = 20
    pages: int = 0

    @classmethod
    def from_dict(cls, data: dict) -> "TaskList":
        tasks = [Task.from_dict(t) for t in data.get("tasks", [])]
        return cls(
            tasks=tasks,
            total=data.get("total", 0),
            page=data.get("page", 1),
            limit=data.get("limit", 20),
            pages=data.get("pages", 0),
        )
