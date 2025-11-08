from fastapi import FastAPI, Request, BackgroundTasks, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
import uuid
import sys
import asyncio
import json

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
async def scan(background_tasks: BackgroundTasks, target: str = Form(...)):
	request_id = str(uuid.uuid4())
	
	# Parse target to determine if it's a domain or IP
	domain = None
	ip = None
	
	if target:
		# Simple check: if it contains dots and no spaces, treat as domain/IP
		if '.' in target and ' ' not in target:
			# Check if it looks like an IP address
			parts = target.split('.')
			if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
				ip = target
			else:
				domain = target
	
	scan_request = ScanRequest(domain=domain, ip=ip, request_id=request_id)
	
	# Estimate steps: passive parts (~6) + external tasks (~25) + advanced scans (~9)
	await progress_init(request_id, total_steps=40)
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

@app.get("/report/{request_id}/pdf")
async def report_pdf(request_id: str):
	"""Generate and return PDF report"""
	import traceback
	from app.services.pdf_generator import generate_pdf_report
	
	findings_path = REPORTS_DIR / f"{request_id}_findings.json"
	if not findings_path.exists():
		# Try to generate from HTML report if findings JSON doesn't exist
		report_file = REPORTS_DIR / f"{request_id}.html"
		if not report_file.exists():
			raise HTTPException(status_code=404, detail="Report not found. Please wait for the scan to complete.")
		raise HTTPException(status_code=404, detail="Findings data not found. This report was generated before PDF support was added.")
	
	try:
		# Load findings data
		with findings_path.open('r', encoding='utf-8') as f:
			data = json.load(f)
		
		# Ensure findings is a dict (handle None or empty)
		if not isinstance(data.get('findings'), dict):
			data['findings'] = {}
		
		# Generate PDF
		pdf_path = REPORTS_DIR / f"{request_id}.pdf"
		success = generate_pdf_report(
			request=data.get('request', {}),
			findings=data.get('findings', {}),
			passive=data.get('passive', {}),
			tools=data.get('tools', []),
			output_path=pdf_path
		)
		
		if not success:
			raise HTTPException(status_code=500, detail="Failed to generate PDF. Check server logs for details.")
		
		if not pdf_path.exists():
			raise HTTPException(status_code=500, detail="PDF file was not created. Check server logs for details.")
		
		return FileResponse(
			path=str(pdf_path),
			media_type='application/pdf',
			filename=f"recon_report_{request_id}.pdf"
		)
	except HTTPException:
		raise
	except Exception as e:
		import traceback
		error_msg = f"Error generating PDF: {str(e)}"
		print(f"PDF Generation Error: {error_msg}")
		print(traceback.format_exc())
		raise HTTPException(status_code=500, detail=error_msg)
