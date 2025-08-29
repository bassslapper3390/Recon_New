import asyncio
import shutil
from typing import Dict, Optional
import os
from pathlib import Path

TOOLS = [
	"nmap", "masscan", "naabu", "nikto", "nuclei", "whatweb", "wafw00f",
	"theHarvester", "subfinder", "amass", "sublist3r", "dnsx", "httpx",
	"gobuster", "ffuf", "feroxbuster", "aquatone", "sn1per", "sniper"
]

COMMON_DIRS = [
	str(Path.home() / "go" / "bin"),
	str(Path.home() / "scoop" / "shims"),
	"C:/Program Files (x86)/Nmap",
	"C:/Program Files/Nmap",
]

EXTS = ["", ".exe", ".bat", ".cmd"]

async def resolve_executable(name: str) -> Optional[str]:
	# PATH first
	path = shutil.which(name)
	if path:
		return path
	# Check common dirs
	for base in COMMON_DIRS:
		for ext in EXTS:
			candidate = os.path.join(base, name + ext)
			if os.path.isfile(candidate):
				return candidate
	return None

async def get_tools_status() -> Dict[str, str]:
	status: Dict[str, str] = {}
	for t in TOOLS:
		resolved = await resolve_executable(t)
		status[t] = 'windows' if resolved else 'missing'
	return status
