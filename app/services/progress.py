from typing import Dict, Any
import asyncio

_progress: Dict[str, Dict[str, Any]] = {}
_lock = asyncio.Lock()

async def init(request_id: str, total_steps: int) -> None:
	async with _lock:
		_progress[request_id] = {"total": max(1, total_steps), "completed": 0, "status": "running"}

async def increment(request_id: str, step: int = 1) -> None:
	async with _lock:
		p = _progress.get(request_id)
		if not p:
			return
		p["completed"] = min(p["total"], p.get("completed", 0) + step)

async def complete(request_id: str) -> None:
	async with _lock:
		p = _progress.get(request_id)
		if not p:
			return
		p["completed"] = p["total"]
		p["status"] = "completed"

async def get(request_id: str) -> Dict[str, Any]:
	async with _lock:
		p = _progress.get(request_id)
		if not p:
			return {"total": 1, "completed": 0, "status": "unknown"}
		percent = int((p["completed"] / p["total"]) * 100) if p["total"] else 0
		return {"total": p["total"], "completed": p["completed"], "percent": percent, "status": p.get("status", "running")}
