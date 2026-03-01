import argparse
import json
import os
import sys
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.panel import Panel
from rich import box

from .scanners import registry
from .utils import check_dependencies

console = Console()

# --- Configuration ---
TESTSSL_PATH = "./testssl.sh/testssl.sh"
NMAP_PATH = "nmap"
DEFAULT_OUTPUT_FILENAME = "report.json"

def print_summary(report):
    """Prints a beautiful summary of the scan results using Rich."""
    console.print(Panel(f"[bold cyan]SCAN SUMMARY:[/bold cyan] [green]{report['scan_target']}[/green]", box=box.DOUBLE))

    # 1. PageSpeed
    ps = report["reports"].get("pagespeed", {})
    if ps.get("status") == "success":
        scores = ps.get("scores", {})
        table = Table(title="Google PageSpeed", box=box.SIMPLE)
        table.add_column("Category", style="cyan")
        table.add_column("Score", justify="right")
        for cat, score in scores.items():
            color = "green" if score >= 90 else "yellow" if score >= 70 else "red"
            table.add_row(cat.replace("_", " ").title(), f"[{color}]{score}/100[/{color}]")
        console.print(table)
    else:
        console.print(f"[bold red]![/bold red] PageSpeed: {ps.get('details', 'Skipped')}")

    # 2. Tech Stack & Headers
    grid = Table.grid(expand=True)
    grid.add_column(); grid.add_column()
    
    tech = report["reports"].get("tech_stack", {})
    tech_content = "\n".join([f"• {t}" for t in tech.get("technologies", [])]) if tech.get("status") == "success" and tech.get("technologies") else "[dim]No technologies detected[/dim]"
    if tech.get("status") != "success": tech_content = f"[red]Scan Failed: {tech.get('details')}[/red]"

    headers = report["reports"].get("security_headers", {})
    header_content = "[green]All key headers found![/green]"
    if headers.get("status") == "success":
        missing = headers.get("missing_headers", [])
        if missing: header_content = "[red]Missing Headers:[/red]\n" + "\n".join([f"• {h}" for h in missing])
    else:
        header_content = f"[red]Scan Failed: {headers.get('details')}[/red]"

    grid.add_row(
        Panel(tech_content, title="[bold]Identified Technologies[/bold]", border_style="blue"),
        Panel(header_content, title="[bold]Security Headers[/bold]", border_style="magenta")
    )
    console.print(grid)

    # 3. Broken Links & DNS
    grid2 = Table.grid(expand=True)
    grid2.add_column(); grid2.add_column()

    links = report["reports"].get("linkchecker", {})
    link_content = "[green]No broken links found.[/green]"
    if links.get("status") == "success":
        count = links.get("summary", {}).get("broken_count", 0)
        if count > 0:
            link_content = f"[red]Found {count} broken links.[/red]\n" + "\n".join([f"• {l['status_code']}: {l['url']}" for l in links.get('broken_links', [])[:3]])
    else:
        link_content = f"[red]Scan Failed: {links.get('details')}[/red]"

    dns_rep = report["reports"].get("dns", {})
    dns_content = ""
    if dns_rep.get("status") == "success":
        records = dns_rep.get("records", {})
        dns_content = "\n".join([f"[bold]{k}:[/bold] {', '.join(v[:2])}{'...' if len(v)>2 else ''}" for k, v in records.items()])
    else:
        dns_content = f"[red]Scan Failed: {dns_rep.get('details')}[/red]"

    grid2.add_row(
        Panel(link_content, title="[bold]Broken Links[/bold]", border_style="yellow"),
        Panel(dns_content, title="[bold]DNS Records[/bold]", border_style="cyan")
    )
    console.print(grid2)

    # 4. Infrastructure
    nmap = report["reports"].get("nmap", {})
    ssl = report["reports"].get("testssl", {})
    infra_table = Table(title="Infrastructure Security", box=box.SIMPLE, expand=True)
    infra_table.add_column("Scanner", style="bold"); infra_table.add_column("Result")
    
    if nmap.get("status") == "success":
        ports = nmap.get("open_ports", [])
        res = ", ".join([f"{p['portid']}/{p['service']}" for p in ports]) if ports else "No open ports found"
        infra_table.add_row("Nmap (Ports)", res)
    else:
        infra_table.add_row("Nmap (Ports)", f"[dim]{nmap.get('status', 'Skipped')}[/dim]")

    if ssl.get("status") == "success":
        infra_table.add_row("SSL/TLS", "[green]Scan complete. See JSON for details.[/green]")
    else:
        infra_table.add_row("SSL/TLS", f"[dim]{ssl.get('status', 'Skipped')}[/dim]")

    console.print(infra_table)
    console.print("\n" + "=" * 40 + "\n")

def main():
    parser = argparse.ArgumentParser(description="Run a full website health check and audit.")
    parser.add_argument("url", type=str, help="The target URL to scan")
    parser.add_argument("--output", type=str, default=DEFAULT_OUTPUT_FILENAME, help="JSON output report.")
    parser.add_argument("--api-key", type=str, default=os.environ.get("PAGESPEED_API_KEY"), help="Google PageSpeed API key.")
    parser.add_argument("--summary", action="store_true", help="Print summary to terminal.")
    parser.add_argument("--fast", action="store_true", help="Skip slow scans (nmap, testssl).")

    args = parser.parse_args()
    
    missing = check_dependencies(NMAP_PATH, TESTSSL_PATH, skip_slow_tools=args.fast)
    if missing:
        console.print(Panel(f"[bold red]Missing Dependencies:[/bold red]\n" + "\n".join([f"• {m}" for m in missing]), title="Error"))
        sys.exit(1)

    if not args.url.startswith(("http://", "https://")): args.url = f"https://{args.url}"
    args.url = args.url.rstrip(')/"')
    target_hostname = urlparse(args.url).hostname.replace("www.", "")

    master_report = {
        "scan_target": args.url,
        "scan_timestamp": datetime.now().isoformat(),
        "reports": {},
    }

    scanners = registry.get_scanners(fast_only=args.fast)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        overall_task = progress.add_task("[cyan]Running scans...", total=len(scanners))
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_scanner = {
                executor.submit(
                    s.run, 
                    args.url, 
                    api_key=args.api_key, 
                    nmap_path=NMAP_PATH, 
                    testssl_path=TESTSSL_PATH
                ): s for s in scanners
            }
            
            for future in as_completed(future_to_scanner):
                scanner = future_to_scanner[future]
                try:
                    master_report["reports"][scanner.name] = future.result()
                except Exception as e:
                    master_report["reports"][scanner.name] = {"status": "error", "details": str(e)}
                progress.update(overall_task, advance=1)

    if args.output == DEFAULT_OUTPUT_FILENAME:
        safe_hostname = target_hostname.replace(".", "-")
        args.output = f"site-scan-{safe_hostname}-{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    safe_output_path = os.path.basename(args.output)
    try:
        with open(safe_output_path, "w", encoding="utf-8") as f:
            json.dump(master_report, f, indent=4)
        console.print(f"\n[bold green]✓[/bold green] Master report saved to [bold cyan]{safe_output_path}[/bold cyan]")
        if args.summary: print_summary(master_report)
    except Exception as e:
        console.print(f"[bold red]Error saving report:[/bold red] {e}")

if __name__ == "__main__":
    main()
