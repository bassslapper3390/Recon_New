import asyncio
import os
from pathlib import Path
from typing import List
from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.models import ScanRequest, PassiveResults, ToolResult
from app.services import passive as passive_svc
from app.services import external as ext
from app.services.summary import summarize_text
from app.services.progress import increment as progress_inc, complete as progress_complete
from app.services.builtin import tcp_scan

# Vercel-compatible paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
TEMPLATES_DIR = BASE_DIR / 'templates'

# Use temporary directory for reports in Vercel
if os.environ.get('VERCEL'):
    REPORTS_DIR = Path('/tmp/reports')
else:
    REPORTS_DIR = BASE_DIR / 'reports'

REPORTS_DIR.mkdir(parents=True, exist_ok=True)

env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)), autoescape=select_autoescape(['html']))

def _target_host(req: ScanRequest) -> str:
    return req.domain or req.ip or ''

async def run_passive(req: ScanRequest) -> PassiveResults:
    domain = req.domain
    target = _target_host(req)

    dns_task = asyncio.create_task(passive_svc.resolve_dns(domain)) if domain else None
    whois_task = asyncio.create_task(passive_svc.lookup_whois(domain, req.ip))
    ssl_task = asyncio.create_task(passive_svc.fetch_ssl_info(domain)) if domain else None
    http_task = asyncio.create_task(passive_svc.fetch_http_info(target)) if target else None
    robots_task = asyncio.create_task(passive_svc.fetch_robots(domain)) if domain else None
    ct_task = asyncio.create_task(passive_svc.fetch_ct_logs(domain)) if domain else None

    results = PassiveResults(
        dns = await dns_task if dns_task else None,
        whois = await whois_task,
        ssl = await ssl_task if ssl_task else None,
        http = await http_task if http_task else None,
        robots = await robots_task if robots_task else None,
        ct_logs = await ct_task if ct_task else None,
    )
    # Increment a few steps after passive phase
    await progress_inc(req.request_id, step=5)
    return results

async def run_tools(req: ScanRequest) -> List[ToolResult]:
    target = _target_host(req)
    results: List[ToolResult] = []
    if not target:
        return results

    # In Vercel, we'll limit the tools to avoid timeout issues
    # Focus on Python-based tools and simple network operations
    tasks = []
    
    # Core tools that work well in serverless
    tasks.append(("nuclei", ext.nuclei_scan(target)))
    tasks.append(("httpx", ext.httpx_probe(target)))
    tasks.append(("whatweb", ext.whatweb_scan(target)))
    tasks.append(("wafw00f", ext.wafw00f_scan(target)))
    
    # Simple port scanning
    tasks.append(("naabu", ext.naabu_scan(target)))
    
    # Directory scanning
    tasks.append(("feroxbuster", ext.feroxbuster_dirs(target)))
    
    # Domain-specific tools (only if domain provided)
    if req.domain:
        tasks.append(("dnsx", ext.dnsx_check(req.domain)))
        tasks.append(("ffuf-vhost", ext.ffuf_vhost(req.domain)))

    async def run_named(name: str, coro):
        try:
            # Shorter timeout for Vercel
            success, output = await asyncio.wait_for(coro, timeout=15)
            return ToolResult(name=name, success=success, output=output if success else None, error=None if success else output)
        except asyncio.TimeoutError:
            return ToolResult(name=name, success=False, error="timeout after 15s")
        except Exception as e:
            return ToolResult(name=name, success=False, error=str(e))

    # Always include built-in TCP scan
    async def run_builtin():
        try:
            output = await tcp_scan(target)
            return ToolResult(name='builtin-tcp', success=True, output=output)
        except Exception as e:
            return ToolResult(name='builtin-tcp', success=False, error=str(e))

    coros = [run_named(name, coro) for name, coro in tasks]
    coros.append(run_builtin())
    
    for fut in asyncio.as_completed(coros):
        res = await fut
        results.append(res)
        await progress_inc(req.request_id, step=1)
    return results

async def run_full_scan(req: ScanRequest) -> None:
    passive = await run_passive(req)
    tools = await run_tools(req)

    # Ensure passive dict doesn't contain non-serializable types
    def safe(obj):
        try:
            import json
            json.dumps(obj)
            return obj
        except Exception:
            return str(obj)
    passive_dict = {k: safe(v) for k, v in passive.model_dump().items()}

    template = env.get_template('report.html')
    html = template.render(request=req.model_dump(), passive=passive_dict, tools=[t.model_dump() for t in tools])
    report_path = REPORTS_DIR / f"{req.request_id}.html"
    
    try:
        report_path.write_text(html, encoding='utf-8')
    except Exception as e:
        # If we can't write to file, we'll skip the summary for now
        print(f"Warning: Could not write report file: {e}")
        await progress_complete(req.request_id)
        return

    # Try to add summary if possible
    joined = []
    if passive.whois:
        joined.append(str(passive.whois))
    if passive.dns:
        joined.append(str(passive.dns))
    for t in tools:
        if t.output:
            joined.append(f"[{t.name}]\n" + t.output[:15000])
    text = '\n\n'.join(joined)[:100000]
    
    try:
        summary = await summarize_text(text)
        if summary:
            append_html = env.get_template('summary_snippet.html').render(summary=summary)
            with report_path.open('a', encoding='utf-8') as f:
                f.write(append_html)
    except Exception:
        pass
    
    await progress_complete(req.request_id)
