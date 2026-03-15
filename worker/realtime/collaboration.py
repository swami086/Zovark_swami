"""WebSocket-based real-time collaboration for investigations.

Enables multiple analysts to work on the same investigation simultaneously
with live cursor tracking, entity locking, and comment broadcasting.
"""
import asyncio
import json
import logging
import time
from typing import Dict, Set, Optional

logger = logging.getLogger(__name__)

LOCK_TTL = 300  # 5-minute entity lock TTL


class InvestigationCollaboration:
    """Manages real-time collaboration state for investigations."""

    def __init__(self):
        self.active_investigations: Dict[str, Set] = {}
        self.analyst_cursors: Dict[str, Dict] = {}
        self.entity_locks: Dict[str, Dict] = {}
        self._lock = asyncio.Lock()

    async def connect(self, websocket, investigation_id: str, analyst_id: str, tenant_id: str):
        """Register a new WebSocket connection."""
        async with self._lock:
            if investigation_id not in self.active_investigations:
                self.active_investigations[investigation_id] = set()
            self.active_investigations[investigation_id].add(websocket)

        # Broadcast analyst joined
        await self.broadcast(investigation_id, {
            "type": "analyst_joined",
            "analyst_id": analyst_id,
            "timestamp": time.time(),
            "active_analysts": await self._get_analyst_count(investigation_id),
        }, exclude=websocket)

        # Send current state to new connection
        await self._send(websocket, {
            "type": "state_sync",
            "cursors": self._get_cursors(investigation_id),
            "locks": self._get_locks(investigation_id),
            "active_analysts": await self._get_analyst_count(investigation_id),
        })

    async def disconnect(self, websocket, investigation_id: str, analyst_id: str):
        """Remove a WebSocket connection and clean up."""
        async with self._lock:
            if investigation_id in self.active_investigations:
                self.active_investigations[investigation_id].discard(websocket)
                if not self.active_investigations[investigation_id]:
                    del self.active_investigations[investigation_id]

        # Release any locks held by this analyst
        await self._release_analyst_locks(investigation_id, analyst_id)

        # Remove cursor
        cursor_key = f"{investigation_id}:{analyst_id}"
        self.analyst_cursors.pop(cursor_key, None)

        await self.broadcast(investigation_id, {
            "type": "analyst_left",
            "analyst_id": analyst_id,
            "timestamp": time.time(),
        })

    async def broadcast(self, investigation_id: str, message: dict, exclude=None):
        """Broadcast message to all connected analysts."""
        connections = self.active_investigations.get(investigation_id, set()).copy()
        disconnected = set()
        data = json.dumps(message)

        for ws in connections:
            if ws == exclude:
                continue
            try:
                await ws.send_text(data)
            except Exception:
                disconnected.add(ws)

        # Clean up disconnected sockets
        if disconnected:
            async with self._lock:
                if investigation_id in self.active_investigations:
                    self.active_investigations[investigation_id] -= disconnected

    async def handle_cursor_move(self, investigation_id: str, analyst_id: str, position: dict):
        """Update and broadcast cursor position."""
        cursor_key = f"{investigation_id}:{analyst_id}"
        self.analyst_cursors[cursor_key] = {
            "analyst_id": analyst_id,
            "position": position,
            "timestamp": time.time(),
        }
        await self.broadcast(investigation_id, {
            "type": "cursor_move",
            "analyst_id": analyst_id,
            "position": position,
        })

    async def lock_entity(self, investigation_id: str, analyst_id: str, entity_id: str) -> bool:
        """Acquire exclusive lock on an entity."""
        lock_key = f"{investigation_id}:{entity_id}"

        async with self._lock:
            existing = self.entity_locks.get(lock_key)
            if existing and existing["analyst_id"] != analyst_id:
                # Check TTL
                if time.time() - existing["locked_at"] < LOCK_TTL:
                    return False
                # Lock expired, allow override

            self.entity_locks[lock_key] = {
                "analyst_id": analyst_id,
                "entity_id": entity_id,
                "locked_at": time.time(),
            }

        await self.broadcast(investigation_id, {
            "type": "entity_locked",
            "entity_id": entity_id,
            "analyst_id": analyst_id,
        })
        return True

    async def unlock_entity(self, investigation_id: str, analyst_id: str, entity_id: str):
        """Release lock on an entity."""
        lock_key = f"{investigation_id}:{entity_id}"

        async with self._lock:
            existing = self.entity_locks.get(lock_key)
            if existing and existing["analyst_id"] == analyst_id:
                del self.entity_locks[lock_key]

        await self.broadcast(investigation_id, {
            "type": "entity_unlocked",
            "entity_id": entity_id,
            "analyst_id": analyst_id,
        })

    async def handle_comment(self, investigation_id: str, analyst_id: str, comment: str):
        """Broadcast a comment to all connected analysts."""
        await self.broadcast(investigation_id, {
            "type": "comment",
            "analyst_id": analyst_id,
            "comment": comment,
            "timestamp": time.time(),
        })

    async def handle_message(self, websocket, investigation_id: str,
                             analyst_id: str, message: dict):
        """Route incoming WebSocket messages."""
        msg_type = message.get("type", "")

        if msg_type == "cursor_move":
            await self.handle_cursor_move(investigation_id, analyst_id, message.get("position", {}))
        elif msg_type == "lock_entity":
            success = await self.lock_entity(investigation_id, analyst_id, message.get("entity_id", ""))
            await self._send(websocket, {"type": "lock_result", "success": success, "entity_id": message.get("entity_id")})
        elif msg_type == "unlock_entity":
            await self.unlock_entity(investigation_id, analyst_id, message.get("entity_id", ""))
        elif msg_type == "comment":
            await self.handle_comment(investigation_id, analyst_id, message.get("comment", ""))
        else:
            await self._send(websocket, {"type": "error", "message": f"Unknown message type: {msg_type}"})

    async def _send(self, websocket, message: dict):
        try:
            await websocket.send_text(json.dumps(message))
        except Exception:
            pass

    async def _get_analyst_count(self, investigation_id: str) -> int:
        return len(self.active_investigations.get(investigation_id, set()))

    def _get_cursors(self, investigation_id: str) -> list:
        prefix = f"{investigation_id}:"
        return [v for k, v in self.analyst_cursors.items() if k.startswith(prefix)]

    def _get_locks(self, investigation_id: str) -> list:
        prefix = f"{investigation_id}:"
        return [v for k, v in self.entity_locks.items() if k.startswith(prefix)]

    async def _release_analyst_locks(self, investigation_id: str, analyst_id: str):
        prefix = f"{investigation_id}:"
        to_remove = []
        async with self._lock:
            for key, lock_data in self.entity_locks.items():
                if key.startswith(prefix) and lock_data["analyst_id"] == analyst_id:
                    to_remove.append(key)
            for key in to_remove:
                entity_id = self.entity_locks[key]["entity_id"]
                del self.entity_locks[key]
                await self.broadcast(investigation_id, {
                    "type": "entity_unlocked",
                    "entity_id": entity_id,
                    "analyst_id": analyst_id,
                })


# Module-level singleton
_collab = InvestigationCollaboration()


def get_collaboration() -> InvestigationCollaboration:
    return _collab
