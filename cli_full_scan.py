"""
Run the full Recon Pro scan pipeline from the CLI (same as the web app),
with an ASCII banner and optional output copy location.

Usage:
    python cli_full_scan.py --target example.com
    python cli_full_scan.py -t 192.0.2.10 -o reports/my-report.html
"""

import argparse
import asyncio
import sys
import uuid
import shutil
import json
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from app.models import ScanRequest
from app.services.orchestrator import run_full_scan, REPORTS_DIR
from app.services.progress import init as progress_init, get as progress_get
from app.services.pdf_generator import generate_pdf_report

# Ensure Windows supports asyncio subprocess if needed
if sys.platform.startswith("win"):
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    except Exception:
        pass

console = Console()

BANNER = r"""
                                                   
  @@@@@@    @@@@@@@   @@@@@@   @@@@@@@   @@@@@@@@  
 @@@@@@@   @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  
 !@@       !@@       @@!  @@@  @@!  @@@  @@!       
 !@!       !@!       !@!  @!@  !@!  @!@  !@!       
 !!@@!!    !@!       @!@  !@!  @!@@!@!   @!!!:!    
  !!@!!!   !!!       !@!  !!!  !!@!!!    !!!!!:    
      !:!  :!!       !!:  !!!  !!:       !!:       
     !:!   :!:       :!:  !:!  :!:       :!:       
 :::: ::    ::: :::  ::::: ::   ::        :: ::::  
 :: : :     :: :: :   : :  :    :        : :: ::   
                                                     
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Full Recon Pro scan from CLI (same pipeline as web)."
    )
    parser.add_argument(
        "--target",
        "-t",
        help="Target domain or IP address",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output path for the PDF report (default: reports/<request_id>.pdf)",
    )
    parser.add_argument(
        "--html-only",
        action="store_true",
        help="Skip PDF generation and only save HTML report",
    )
    parser.add_argument(
        "--request-id",
        help="Optional request id to reuse (defaults to a new UUID4)",
    )
    parser.add_argument(
        "--no-docker",
        action="store_true",
        help="Force local execution even if Docker is available",
    )
    return parser.parse_args()


def parse_target(target: str):
    """Return (domain, ip) following the same logic as the web entrypoint."""
    domain = None
    ip = None
    if target and '.' in target and ' ' not in target:
        parts = target.split('.')
        if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
            ip = target
        else:
            domain = target
    return domain, ip


def check_docker_available() -> bool:
    """Check if Docker is available and container is running."""
    try:
        # Check if docker command exists
        docker_cmd = shutil.which('docker') or shutil.which('docker.exe')
        if not docker_cmd:
            return False
        
        # Check if docker compose is available
        try:
            result = subprocess.run(
                [docker_cmd, 'compose', 'ps', '--format', 'json'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                return False
            
            # Check if recon container is running
            import json as json_lib
            containers = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        containers.append(json_lib.loads(line))
                    except:
                        pass
            
            # Look for recon service
            for container in containers:
                if container.get('Service') == 'recon' and container.get('State') == 'running':
                    return True
            
            return False
        except subprocess.TimeoutExpired:
            return False
        except Exception:
            return False
    except Exception:
        return False


def run_in_docker(target: str, output_path: Optional[str], request_id: Optional[str], html_only: bool) -> int:
    """Run the CLI scan inside Docker container."""
    docker_cmd = shutil.which('docker') or shutil.which('docker.exe')
    if not docker_cmd:
        return 1
    
    try:
        # Check if stdout is a TTY to determine if we can use interactive mode
        use_tty = sys.stdout.isatty() and sys.stdin.isatty()
        
        # Adjust docker command based on TTY availability
        if not use_tty:
            # Non-interactive mode - add -T flag back
            docker_base = [docker_cmd, 'compose', 'exec', '-T', 'recon']
        else:
            # Interactive mode - allow TTY for rich output
            docker_base = [docker_cmd, 'compose', 'exec', 'recon']
        
        # Rebuild command with proper docker base
        cmd = docker_base + ['/opt/venv/bin/python', '-u', 'cli_full_scan.py', '--no-docker']
        if target:
            cmd.extend(['-t', target])
        if output_path:
            # Convert host path to container path
            output_path_str = str(output_path)
            reports_dir = str(Path.cwd() / 'reports')
            
            # Normalize paths for comparison
            try:
                output_path_resolved = str(Path(output_path).resolve())
                reports_dir_resolved = str(Path(reports_dir).resolve())
                
                if output_path_resolved.startswith(reports_dir_resolved):
                    # Convert to container path
                    container_path = '/app/reports/' + Path(output_path).name
                    cmd.extend(['-o', container_path])
                else:
                    # Use relative path (will be relative to /app in container)
                    # Extract just the filename if it's an absolute path
                    if Path(output_path).is_absolute():
                        container_path = '/app/reports/' + Path(output_path).name
                        cmd.extend(['-o', container_path])
                    else:
                        cmd.extend(['-o', str(output_path)])
            except Exception:
                # Fallback: just use the filename in reports directory
                container_path = '/app/reports/' + Path(output_path).name
                cmd.extend(['-o', container_path])
        if html_only:
            cmd.append('--html-only')
        if request_id:
            cmd.extend(['--request-id', request_id])
        
        # Run the command and stream output
        # Use unbuffered Python (-u flag) for real-time output
        process = subprocess.Popen(
            cmd,
            stdout=sys.stdout,
            stderr=sys.stderr,
            stdin=sys.stdin if use_tty else subprocess.DEVNULL,
            text=True,
            bufsize=0  # Unbuffered for immediate output
        )
        
        try:
            exit_code = process.wait()
        except KeyboardInterrupt:
            # User cancelled - terminate the Docker process
            console.print("\n[yellow]Cancelling scan in Docker container...[/yellow]")
            try:
                process.terminate()
                # Wait a bit for graceful termination
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            except Exception:
                pass
            console.print("[yellow]Scan cancelled by user.[/yellow]")
            return 130  # Standard exit code for SIGINT
        
        # Check if the error was due to missing file
        if exit_code != 0:
            # Try to check if file exists in container
            try:
                check_cmd = [docker_cmd, 'compose', 'exec', 'recon', 'test', '-f', '/app/cli_full_scan.py']
                check_result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=5)
                if check_result.returncode != 0:
                    console.print("\n[yellow]⚠️  cli_full_scan.py not found in container.[/yellow]")
                    console.print("[yellow]Rebuilding Docker container to include the CLI tool...[/yellow]")
                    console.print("[cyan]Run: docker compose build[/cyan]")
                    console.print("[cyan]Then: docker compose up -d[/cyan]")
                    console.print("[yellow]Or use --no-docker to run locally[/yellow]")
            except Exception:
                pass  # Ignore check errors
        
        return exit_code
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan cancelled by user.[/yellow]")
        return 130
    except Exception as e:
        console.print(f"[red]Error running in Docker: {e}[/red]")
        console.print("[yellow]Try rebuilding the container: docker compose build[/yellow]")
        return 1


async def run(target: str, output_override: Optional[Path], request_id: Optional[str], html_only: bool):
    rid = request_id or str(uuid.uuid4())
    domain, ip = parse_target(target)

    # Init progress similar to /scan endpoint
    await progress_init(rid, total_steps=40)

    scan_req = ScanRequest(domain=domain, ip=ip, request_id=rid)
    console.log(f"Starting scan for {target} (request_id={rid})")
    start = datetime.now(timezone.utc)
    # Run scan and monitor progress concurrently
    async def monitor():
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None),
            TextColumn("{task.completed}/{task.total}"),
            TextColumn("• {task.percentage:>5.1f}%"),
            TimeElapsedColumn(),
            transient=True,
            console=console,
        ) as progress:
            task_id = progress.add_task("Scanning...", total=40)
            while True:
                p = await progress_get(rid)
                progress.update(task_id, completed=p.get("completed", 0), total=p.get("total", 40))
                if p.get("status") == "completed" or progress.tasks[0].completed >= progress.tasks[0].total:
                    break
                await asyncio.sleep(1)

    await asyncio.gather(run_full_scan(scan_req), monitor())
    end = datetime.now(timezone.utc)

    report_path = REPORTS_DIR / f"{rid}.html"
    if not report_path.exists():
        raise FileNotFoundError(f"Expected report not found: {report_path}")

    # Generate PDF report
    pdf_path = None
    if not html_only:
        findings_path = REPORTS_DIR / f"{rid}_findings.json"
        if findings_path.exists():
            console.print("[cyan]Generating PDF report...[/cyan]")
            try:
                # Load findings data
                with findings_path.open('r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Ensure findings is a dict
                if not isinstance(data.get('findings'), dict):
                    data['findings'] = {}
                
                # Determine PDF output path
                if output_override:
                    pdf_path = output_override
                    if pdf_path.suffix.lower() != '.pdf':
                        pdf_path = pdf_path.with_suffix('.pdf')
                else:
                    pdf_path = REPORTS_DIR / f"{rid}.pdf"
                
                pdf_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Generate PDF
                success = generate_pdf_report(
                    request=data.get('request', {}),
                    findings=data.get('findings', {}),
                    passive=data.get('passive', {}),
                    tools=data.get('tools', []),
                    output_path=pdf_path
                )
                
                if success and pdf_path.exists():
                    console.print(f"[green]PDF report generated:[/green] {pdf_path}")
                else:
                    console.print("[yellow]PDF generation failed, but HTML report is available.[/yellow]")
                    pdf_path = None
            except Exception as e:
                console.print(f"[yellow]PDF generation error: {e}[/yellow]")
                pdf_path = None
        else:
            console.print("[yellow]Findings JSON not found, skipping PDF generation.[/yellow]")
    
    # Handle HTML output copy if specified and PDF wasn't requested
    if output_override and html_only:
        output_override.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(report_path, output_override)
        final_path = output_override
    elif pdf_path:
        final_path = pdf_path
    else:
        final_path = report_path

    console.print("")
    console.print(f"[bold cyan]Target:[/bold cyan] {target}")
    console.print(f"[bold cyan]Request ID:[/bold cyan] {rid}")
    console.print(f"[bold cyan]HTML Report:[/bold cyan] {report_path}")
    if pdf_path:
        console.print(f"[bold cyan]PDF Report:[/bold cyan] {pdf_path}")
    console.print(f"[bold cyan]Duration:[/bold cyan] {(end - start).total_seconds():.1f}s")


def main():
    args = parse_args()

    target = args.target
    if not target:
        target = input("Enter target domain or IP: ").strip()

    if not target:
        console.print("[red]No target provided. Exiting.[/red]")
        sys.exit(1)

    out_path = Path(args.output).resolve() if args.output else None
    req_id = args.request_id
    html_only = args.html_only

    # Check if Docker is available and use it if possible (unless --no-docker is set)
    use_docker = check_docker_available() and not args.no_docker
    
    if use_docker:
        console.print(Panel(BANNER, style="cyan", expand=False))
        console.print("[bold green]🐳 Docker detected - running scan in container with all tools[/bold green]")
        console.print(f"[bold cyan]Target:[/bold cyan] {target}")
        if out_path:
            console.print(f"[bold cyan]Output:[/bold cyan] {out_path}")
        if html_only:
            console.print("[yellow]HTML-only mode: PDF generation disabled[/yellow]")
        if req_id:
            console.print(f"[bold cyan]Request ID:[/bold cyan] {req_id}")
        console.print("")
        
        # Run in Docker
        exit_code = run_in_docker(
            target,
            str(out_path) if out_path else None,
            req_id,
            html_only
        )
        sys.exit(exit_code)
    else:
        # Fall back to local execution
        console.print(Panel(BANNER, style="cyan", expand=False))
        if not check_docker_available():
            console.print("[yellow]💡 Tip: Start Docker container for access to all tools: docker compose up -d[/yellow]")
        console.print(f"[bold cyan]Target:[/bold cyan] {target}")
        if out_path:
            console.print(f"[bold cyan]Output:[/bold cyan] {out_path}")
        if html_only:
            console.print("[yellow]HTML-only mode: PDF generation disabled[/yellow]")
        if req_id:
            console.print(f"[bold cyan]Request ID:[/bold cyan] {req_id}")
        console.print("")

        try:
            asyncio.run(run(target, out_path, req_id, html_only))
            console.print("\n[green]Scan complete.[/green]")
        except KeyboardInterrupt:
            console.print("\n[yellow]Scan cancelled by user.[/yellow]")
            sys.exit(1)
        except Exception as exc:
            console.print(f"[red]Scan failed: {exc}[/red]")
            sys.exit(1)


if __name__ == "__main__":
    main()

