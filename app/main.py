from fastapi import FastAPI, Request, BackgroundTasks, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
import uuid
import sys
import asyncio

# Ensure Windows supports asyncio subprocess
if sys.platform.startswith('win'):
	try:
		asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
	except Exception:
		pass

from app.models import ScanRequest
from app.services.orchestrator import run_full_scan
from app.services.progress import init as progress_init, get as progress_get
from app.services.tools import get_tools_status

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="Recon Pro", version="0.1.0")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
	return templates.TemplateResponse("index.html", {"request": request})

@app.post("/scan", response_model=dict)
async def scan(background_tasks: BackgroundTasks, domain: str = Form(None), ip: str = Form(None)):
	request_id = str(uuid.uuid4())
	scan_request = ScanRequest(domain=domain or None, ip=ip or None, request_id=request_id)
	# Estimate steps: passive parts (~6) + number of external tasks (~13)
	await progress_init(request_id, total_steps=20)
	background_tasks.add_task(run_full_scan, scan_request)
	return {"request_id": request_id, "status": "started"}

@app.get("/progress/{request_id}")
async def progress(request_id: str):
	return await progress_get(request_id)

@app.get("/report/{request_id}", response_class=HTMLResponse)
async def report(request: Request, request_id: str):
	report_file = REPORTS_DIR / f"{request_id}.html"
	if not report_file.exists():
		return templates.TemplateResponse("report_pending.html", {"request": request, "request_id": request_id})
	content = report_file.read_text(encoding="utf-8")
	return HTMLResponse(content)

@app.get("/tools")
async def tools():
	return await get_tools_status()
