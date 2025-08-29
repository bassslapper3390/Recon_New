import socket
from typing import Dict, Any, List, Optional
import ssl as ssl_lib
import httpx
import whois
import dns.resolver
import asyncio

async def resolve_dns(domain: str) -> Dict[str, Any]:
	results: Dict[str, Any] = {}

	async def _resolve(record: str):
		try:
			answers = await asyncio.to_thread(dns.resolver.resolve, domain, record)
			if record == 'A':
				results['A'] = [rdata.address for rdata in answers]
			else:
				results[record] = [str(r.to_text()) for r in answers]
		except Exception as e:
			key = 'A_error' if record == 'A' else f'{record}_error'
			results[key] = str(e)

	# Run common records concurrently without blocking the event loop
	await asyncio.gather(
		_resolve('A'),
		_resolve('AAAA'),
		_resolve('MX'),
		_resolve('NS'),
		_resolve('TXT'),
	)
	return results

async def lookup_whois(domain: Optional[str], ip: Optional[str]) -> Dict[str, Any]:
	try:
		target = domain or ip
		if not target:
			return {"error": "no target"}
		# WHOIS is blocking; offload to a thread to avoid blocking the event loop
		data = await asyncio.to_thread(whois.whois, target)
		return {k: (str(v) if not isinstance(v, (dict, list)) else v) for k, v in data.items()}
	except Exception as e:
		return {"error": str(e)}

async def fetch_ssl_info(domain: Optional[str]) -> Dict[str, Any]:
	if not domain:
		return {"error": "no domain"}
	try:
		ctx = ssl_lib.create_default_context()
		with socket.create_connection((domain, 443), timeout=5) as sock:
			with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
				cert = ssock.getpeercert()
				return {"subject": cert.get("subject"), "issuer": cert.get("issuer"), "notAfter": cert.get("notAfter")}
	except Exception as e:
		return {"error": str(e)}

async def fetch_http_info(domain_or_ip: str) -> Dict[str, Any]:
	urls = []
	if domain_or_ip:
		urls = [f"http://{domain_or_ip}", f"https://{domain_or_ip}"]
	results: Dict[str, Any] = {}
	async with httpx.AsyncClient(follow_redirects=True, timeout=5) as client:
		for url in urls:
			try:
				resp = await client.get(url)
				results[url] = {"status": resp.status_code, "headers": dict(resp.headers)}
			except Exception as e:
				results[url] = {"error": str(e)}
	return results

async def fetch_robots(domain: Optional[str]) -> Optional[str]:
	if not domain:
		return None
	try:
		async with httpx.AsyncClient(timeout=5) as client:
			resp = await client.get(f"https://{domain}/robots.txt")
			if resp.status_code == 200:
				return resp.text
			return None
	except Exception:
		return None

async def fetch_ct_logs(domain: Optional[str]) -> List[Dict[str, Any]]:
	if not domain:
		return []
	url = f"https://crt.sh/?q=%25.{domain}&output=json"
	try:
		async with httpx.AsyncClient(timeout=10) as client:
			resp = await client.get(url)
			if resp.status_code == 200:
				return resp.json()
			return []
	except Exception:
		return []
