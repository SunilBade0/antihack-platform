import asyncio
import anthropic
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich import print as rprint

from agents.base_agent import Finding, Severity
from agents.recon import DNSReconAgent, WHOISAgent, PortScannerAgent
from agents.web import (
    SQLInjectionAgent, XSSAgent, CSRFAgent, SSRFAgent,
    AuthAgent, APIAgent, DirectoryTraversalAgent, SecretsAgent,
)
from agents.infra import SSLAgent, TechFingerprintAgent
from agents.report import ReportAgent

console = Console()

SEVERITY_COLOR = {
    "Critical": "bold red",
    "High": "red",
    "Medium": "yellow",
    "Low": "green",
    "Info": "blue",
}

_AUTHORIZATION_BANNER = """
╔══════════════════════════════════════════════════════════════════════════╗
║          AI-POWERED PENETRATION TESTING PLATFORM                         ║
║                  ⚠  AUTHORIZATION REQUIRED ⚠                            ╠
╠══════════════════════════════════════════════════════════════════════════╣
║  This tool performs active security testing including:                   ║
║  • Port scanning and service fingerprinting                              ║
║  • HTTP probing, form submission, and injection testing                  ║
║  • Authentication bypass attempts                                        ║
║  • Directory and file enumeration                                        ║
║                                                                          ║
║  You MUST have explicit written authorization to test this target.       ║
║  Unauthorized testing is illegal and unethical.                          ║
║                                                                          ║
║  By proceeding you confirm:                                              ║
║    [1] You own this target, OR                                           ║
║    [2] You have written permission from the owner to perform this test   ║
╚══════════════════════════════════════════════════════════════════════════╝
"""


def authorization_gate(target: str) -> bool:
    console.print(Panel(_AUTHORIZATION_BANNER, style="bold yellow"))
    console.print(f"[bold]Target:[/bold] {target}\n")

    response = input(
        "Do you confirm you own this target or have written authorization to test it?\n"
        "Type exactly 'I CONFIRM' to proceed: "
    ).strip()

    if response != "I CONFIRM":
        console.print("\n[bold red]Authorization not confirmed. Aborting.[/bold red]")
        return False

    console.print("\n[bold green]Authorization confirmed. Starting security assessment...[/bold green]\n")
    return True


class Orchestrator:
    def __init__(self, target: str, output_dir: str = "reports", api_key: str = None):
        self.target = target.rstrip("/")
        self.output_dir = output_dir
        self.client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
        self.all_findings: list[Finding] = []

    def _make_agents(self):
        args = (self.target, self.client)
        return {
            "Recon Phase": [
                DNSReconAgent(*args),
                WHOISAgent(*args),
                PortScannerAgent(*args),
            ],
            "Web Security Phase": [
                SSLAgent(*args),
                TechFingerprintAgent(*args),
                SQLInjectionAgent(*args),
                XSSAgent(*args),
                CSRFAgent(*args),
                SSRFAgent(*args),
                AuthAgent(*args),
                APIAgent(*args),
                DirectoryTraversalAgent(*args),
                SecretsAgent(*args),
            ],
        }

    async def _run_agent(self, agent, progress, task_id):
        try:
            findings = await agent.run()
            self.all_findings.extend(findings)
            crits = sum(1 for f in findings if f.severity == Severity.CRITICAL)
            highs = sum(1 for f in findings if f.severity == Severity.HIGH)
            status = ""
            if crits:
                status = f" [bold red]({crits} CRITICAL)[/bold red]"
            elif highs:
                status = f" [red]({highs} HIGH)[/red]"
            progress.update(task_id, description=f"[green]✓[/green] {agent.name}{status}")
        except Exception as e:
            progress.update(task_id, description=f"[red]✗ {agent.name} failed: {e}[/red]")

    async def run(self) -> dict:
        if not authorization_gate(self.target):
            return {}

        console.print(f"[bold cyan]Target:[/bold cyan] {self.target}")
        console.print(f"[bold cyan]Output directory:[/bold cyan] {self.output_dir}\n")

        phases = self._make_agents()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console,
        ) as progress:
            for phase_name, agents in phases.items():
                console.print(f"\n[bold underline]{phase_name}[/bold underline]")

                tasks = []
                task_ids = []
                for agent in agents:
                    tid = progress.add_task(f"  {agent.name}...", total=None)
                    task_ids.append(tid)
                    tasks.append(self._run_agent(agent, progress, tid))

                # Run all agents in this phase concurrently
                await asyncio.gather(*tasks)

        # Generate report
        console.print("\n[bold cyan]Generating comprehensive report...[/bold cyan]")
        report_agent = ReportAgent(
            target=self.target,
            client=self.client,
            all_findings=self.all_findings,
            output_dir=self.output_dir,
        )
        result = await report_agent.run()

        self._print_summary(result)
        return result

    def _print_summary(self, result: dict):
        counts = result.get("counts", {})
        risk_score = result.get("risk_score", 0)

        console.print("\n")
        console.rule("[bold]Assessment Complete[/bold]")

        # Risk score color
        if risk_score >= 80:
            score_style = "bold red"
        elif risk_score >= 50:
            score_style = "red"
        elif risk_score >= 25:
            score_style = "yellow"
        else:
            score_style = "green"

        console.print(f"\n[bold]Risk Score:[/bold] [{score_style}]{risk_score}/100[/{score_style}]")

        table = Table(title="Finding Summary", show_header=True, header_style="bold cyan")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        for sev, style in SEVERITY_COLOR.items():
            count = counts.get(sev, 0)
            if count > 0:
                table.add_row(f"[{style}]{sev}[/{style}]", str(count))

        console.print(table)

        # Print critical/high findings preview
        critical_findings = [f for f in self.all_findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]
        if critical_findings:
            console.print("\n[bold red]Critical & High Findings:[/bold red]")
            for f in critical_findings[:10]:
                icon = "🔴" if f.severity == Severity.CRITICAL else "🟠"
                console.print(f"  {icon} [{SEVERITY_COLOR[f.severity.value]}]{f.severity.value}[/{SEVERITY_COLOR[f.severity.value]}] — {f.title}")
                console.print(f"     [dim]{f.agent}[/dim]")

        console.print("\n[bold]Reports saved:[/bold]")
        for fmt in ["markdown", "json", "html"]:
            path = result.get(fmt, "")
            if path:
                console.print(f"  [cyan]{fmt.upper():8}[/cyan]  {path}")

        console.print(f"\n[dim]Executive Summary:[/dim]\n")
        summary = result.get("executive_summary", "")
        if summary:
            for line in summary.split("\n")[:8]:
                console.print(f"  {line}")
