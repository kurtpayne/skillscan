from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from skillscan.models import ScanReport, Verdict

VERDICT_STYLE = {
    Verdict.ALLOW: "bold green",
    Verdict.WARN: "bold yellow",
    Verdict.BLOCK: "bold red",
}


def render_report(report: ScanReport, console: Console | None = None) -> None:
    console = console or Console()

    summary = (
        f"[bold]Target:[/bold] {report.metadata.target}\n"
        f"[bold]Policy:[/bold] {report.metadata.policy_profile}\n"
        f"[bold]Ecosystems:[/bold] {', '.join(report.metadata.ecosystem_hints)}\n"
        f"[bold]Score:[/bold] {report.score}\n"
        f"[bold]Findings:[/bold] {len(report.findings)}"
    )
    console.print(
        Panel(
            summary,
            title=f"Verdict: [{VERDICT_STYLE[report.verdict]}]{report.verdict.value.upper()}[/]",
            border_style=VERDICT_STYLE[report.verdict],
        )
    )

    findings = Table(title="Top Findings", show_lines=True)
    findings.add_column("ID", style="cyan")
    findings.add_column("Severity")
    findings.add_column("Category")
    findings.add_column("Evidence")
    findings.add_column("Snippet")
    for finding in report.findings[:20]:
        findings.add_row(
            finding.id,
            finding.severity.value,
            finding.category,
            f"{finding.evidence_path}:{finding.line or '-'}",
            finding.snippet[:90],
        )
    if report.findings:
        console.print(findings)

    caps = Table(title="Capabilities")
    caps.add_column("Capability", style="magenta")
    caps.add_column("Evidence")
    for cap in report.capabilities[:20]:
        caps.add_row(cap.name, cap.evidence_path)
    if report.capabilities:
        console.print(caps)

    ioc = Table(title="Network Indicators")
    ioc.add_column("Type")
    ioc.add_column("Value")
    ioc.add_column("Listed")
    ioc.add_column("Source")
    for entry in report.iocs[:30]:
        ioc.add_row(entry.kind, entry.value, "yes" if entry.listed else "no", entry.source_path)
    if report.iocs:
        console.print(ioc)

    dep = Table(title="Dependency Vulnerabilities")
    dep.add_column("Ecosystem")
    dep.add_column("Package")
    dep.add_column("Version")
    dep.add_column("Vuln")
    dep.add_column("Severity")
    dep.add_column("Fixed")
    for d in report.dependency_findings:
        dep.add_row(
            d.ecosystem,
            d.name,
            d.version,
            d.vulnerability_id,
            d.severity.value,
            d.fixed_version or "-",
        )
    if report.dependency_findings:
        console.print(dep)
