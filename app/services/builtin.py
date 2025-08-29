import asyncio
from typing import List, Tuple

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 123, 135, 139, 143, 161, 389, 443, 445, 465, 587, 993, 995, 1433, 1521, 1723, 2375, 2376, 27017, 3306, 3389, 5432, 5900, 6379, 8000, 8008, 8080, 8443]

async def _probe(host: str, port: int, timeout: float = 1.5) -> Tuple[int, bool]:
	try:
		reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
		writer.write(b"\r\n")
		await asyncio.sleep(0.1)
		writer.close()
		return (port, True)
	except Exception:
		return (port, False)

async def tcp_scan(host: str) -> str:
	if not host:
		return "no host provided"
	tasks = [asyncio.create_task(_probe(host, p)) for p in COMMON_PORTS]
	open_ports: List[int] = []
	for fut in asyncio.as_completed(tasks):
		port, is_open = await fut
		if is_open:
			open_ports.append(port)
	open_ports.sort()
	if not open_ports:
		return "No common TCP ports discovered open."
	return "Open ports: " + ", ".join(str(p) for p in open_ports)
