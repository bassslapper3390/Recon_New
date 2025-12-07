# Recon Pro

Fast, user-friendly recon tool with passive/active scans, reporting, and AI insights.

## Features
- Passive: DNS, WHOIS, SSL, HTTP headers, robots.txt, CT logs
- External tools: nmap, nikto, theHarvester, sn1per (if installed)
- Async orchestration, HTML report, optional AI summary
- Clean UI built with FastAPI + Jinja templates

## Windows Setup
1. Install Python 3.11+ from Microsoft Store or python.org
2. Open PowerShell and run:
```powershell
cd "C:\Users\Dhruv Tandon\Desktop\Recon_New"
python -m venv .venv
. .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
3. Optional: Install external tools (admin PowerShell)
   - nmap: winget install -e --id Insecure.Nmap
   - nikto: Requires Perl and nikto (manual install) or WSL
   - theHarvester: `pip install theHarvester` may work; or use WSL package
   - sn1per: Generally Linux/WSL recommended

> Tip: For best compatibility, enable WSL and install tools inside WSL. The app will still run on Windows and call them if in PATH.

## Install External Tools
Windows PowerShell:
```powershell
# Native tools and Python CLIs
scripts\install_tools.ps1
# Or include WSL installations as well
scripts\install_tools.ps1 -WSL
```
Then restart your terminal.

The homepage shows a Tools Availability panel indicating Windows, WSL, or Missing.

If you use WSL, the app will attempt to run missing tools via `wsl bash -lc` automatically.

## Tools Supported (auto-detected if installed)
- nmap, masscan, naabu
- nikto, nuclei, whatweb, wafw00f
- theHarvester, subfinder, amass, sublist3r, dnsx
- httpx (ProjectDiscovery), gobuster, ffuf, feroxbuster, aquatone, sn1per

## Docker (recommended to get all tools)
Build and run:
```powershell
# from project root
docker compose build
docker compose up -d
# Open http://localhost:8088
```
The container includes: nmap, masscan, naabu, nikto, nuclei, whatweb, wafw00f, subfinder, amass, sublist3r, dnsx, httpx, gobuster, ffuf, feroxbuster. Tools panel reflects availability inside the container.

### Using CLI with Docker
The CLI tool **automatically detects and uses Docker** if the container is running (recommended - has all tools):
```powershell
# Make sure Docker container is running
docker compose up -d

# Run CLI - it will automatically use Docker if available
python cli_full_scan.py -t example.com -o reports/scan.pdf

# Force local execution (skip Docker)
python cli_full_scan.py -t example.com --no-docker
```

**Benefits of using Docker:**
- All tools are available (nmap, nikto, nuclei, subfinder, etc.)
- Reports are saved to `./reports` on your host machine via volume mount
- No need to install tools on your Windows machine

**Manual Docker execution** (if you prefer):
```powershell
docker compose exec recon python cli_full_scan.py -t example.com -o reports/scan.pdf
```

## Run (port 8088)
```powershell
uvicorn app.main:app --reload --host 0.0.0.0 --port 8088
```
Open `http://localhost:8088` or `http://127.0.0.1:8088` and start a scan.

**Note:** If `localhost` doesn't work, use `127.0.0.1:8088` instead. This is usually a Windows hosts file issue.

## Environment
- Optional: `OPENAI_API_KEY` for AI summary

## Exporting Reports
- Reports saved to `reports/{request_id}.html`
- You can print to PDF from the browser

## Notes
- External tools are optional; the app gracefully handles when they are not installed.
- Scans honor simple timeouts to avoid hanging.
