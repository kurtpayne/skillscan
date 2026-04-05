# analysis/_scanner.py — the scan() entry point
from __future__ import annotations

import concurrent.futures
import os
from pathlib import Path

from skillscan import __version__
from skillscan.analysis_pkg._archive import (
    SCRIPT_SUFFIXES,
    prepare_target,
)
from skillscan.analysis_pkg._text import (
    _CHAIN_WINDOW_LINES,
    _LANG_EXTENSIONS,
    RISKY_NPM_SCRIPT_RE,
    SEVERITY_SCORE,
    _binary_artifact_findings,
    _extract_actions_windowed,
    _extract_iocs,
    _find_unpinned_requirements,
    _ip_in_cidrs,
    _is_unpinned_npm,
    _load_builtin_ioc_db,
    _load_builtin_vuln_db,
    _merge_user_intel,
    _parse_package_json,
    _parse_package_scripts,
    _parse_requirements,
    _prepare_analysis_text,
    _safe_read_text,
    iter_text_files,
)
from skillscan.clamav import scan_paths as clamav_scan_paths
from skillscan.detectors.ast_flows import detect_python_ast_flows
from skillscan.ecosystems import detect_ecosystems
from skillscan.ml_detector import ml_prompt_injection_findings
from skillscan.models import (
    IOC,
    Capability,
    DependencyFinding,
    Finding,
    Policy,
    ScanMetadata,
    ScanReport,
    Severity,
    TriageMetadata,
    Verdict,
)
from skillscan.analysis_pkg._sections import build_section_map
from skillscan.rules import CompiledRulePack, load_compiled_builtin_rulepack
from skillscan.semantic_local import (
    classify_prompt_injection_raw,
    classify_social_engineering_raw,
    local_prompt_injection_findings,
    local_social_engineering_findings,
)

import re as _re

_NEGATION_WINDOW = 3   # lines to check before and after the match line
_NEGATION_RE = _re.compile(
    r"\b(never|do\s+not|don['']?t|must\s+not|should\s+not|avoid|cannot|can['']?t|"
    r"do\s+NOT|MUST\s+NOT|NEVER|prohibited|forbidden|disallowed|not\s+allowed)\b",
    _re.IGNORECASE,
)
_NEGATION_CONFIDENCE_REDUCTION = 0.35  # subtracted from confidence; may drop below block_min_confidence


def _extract_section_mult(chain_actions: list[str]) -> float:
    """Extract the section score multiplier embedded in chain_actions by the static rule scanner.

    Static rule findings store ``section_mult=X.XX`` as the first element of
    chain_actions.  All other findings (semantic, ML, IOC, dependency) have no
    such tag and default to 1.0× so their scores are unaffected.
    """
    for action in chain_actions:
        if action.startswith("section_mult="):
            try:
                return float(action.split("=", 1)[1])
            except ValueError:
                pass
    return 1.0


def _apply_negation_guard(lines: list[str], line_no: int, confidence: float) -> float:
    """Return a reduced confidence if a negation token appears near *line_no*.

    Checks a window of ±_NEGATION_WINDOW lines around the match.  If a negation
    token is found, subtracts _NEGATION_CONFIDENCE_REDUCTION from confidence
    (floor 0.0).  Returns the original confidence unchanged when no negation is
    found.
    """
    start = max(0, line_no - 1 - _NEGATION_WINDOW)
    end = min(len(lines), line_no + _NEGATION_WINDOW)
    window_text = "\n".join(lines[start:end])
    if _NEGATION_RE.search(window_text):
        return max(0.0, confidence - _NEGATION_CONFIDENCE_REDUCTION)
    return confidence


# ---------------------------------------------------------------------------
# Cross-source finding deduplication
# ---------------------------------------------------------------------------
# When multiple detectors (semantic classifier + ML model) independently flag
# the same underlying threat on the same file, keeping both findings stacks
# their scores additively and inflates the verdict.  For each group below,
# keep only the highest-confidence finding; annotate it with the IDs of the
# suppressed corroborating signals so they remain visible in JSON output.
_DEDUP_GROUPS: list[frozenset[str]] = [
    frozenset({"PINJ-SEM-001", "PINJ-ML-001"}),
]
_DEDUP_ID_TO_GROUP: dict[str, int] = {
    fid: i for i, grp in enumerate(_DEDUP_GROUPS) for fid in grp
}


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse co-firing findings within each dedup group to the highest-confidence one.

    The winning finding receives a ``corroborated_by: <id> (<conf>)`` note in
    ``chain_actions`` so suppressed signals remain visible in JSON output.
    """
    group_buckets: dict[int, list[Finding]] = {}
    ungrouped: list[Finding] = []
    for f in findings:
        gi = _DEDUP_ID_TO_GROUP.get(f.id)
        if gi is not None:
            group_buckets.setdefault(gi, []).append(f)
        else:
            ungrouped.append(f)

    result: list[Finding] = list(ungrouped)
    for group_fs in group_buckets.values():
        if len(group_fs) == 1:
            result.append(group_fs[0])
            continue
        group_fs.sort(key=lambda x: -x.confidence)
        winner = group_fs[0]
        notes = [f"{f.id} ({f.confidence:.2f})" for f in group_fs[1:]]
        result.append(
            winner.model_copy(
                update={"chain_actions": winner.chain_actions + [f"corroborated_by: {', '.join(notes)}"]}
            )
        )
    return result


def scan(
    target: Path | str,
    policy: Policy,
    policy_source: str,
    *,
    url_max_links: int = 25,
    url_timeout_seconds: int = 12,
    url_same_origin_only: bool = True,
    clamav: bool = False,
    clamav_timeout_seconds: int = 30,
    ml_detect: bool = False,
    rulepack_channel: str = "stable",
    graph_scan: bool = False,
    max_file_size_bytes: int = 1_048_576,  # 1 MB default — skip larger files with a warning
    file_timeout_seconds: int = 30,  # per-file rule-matching timeout
) -> ScanReport:
    prepared = prepare_target(
        target,
        policy,
        url_max_links=url_max_links,
        url_timeout_seconds=url_timeout_seconds,
        url_same_origin_only=url_same_origin_only,
    )
    try:
        ruleset: CompiledRulePack = load_compiled_builtin_rulepack(channel=rulepack_channel)
        inventory = iter_text_files(
            prepared.root,
            policy.limits["max_files"],
            policy.limits["max_bytes"],
            policy.limits.get("max_binary_artifacts", 500),
            policy.limits.get("max_binary_bytes", 100_000_000),
        )
        files = inventory.text_files
        findings: list[Finding] = []
        iocs: list[IOC] = []
        capabilities: list[Capability] = []
        dependency_findings: list[DependencyFinding] = []
        # Triage score accumulators — track max across all files
        _triage_sem_inj: float = 0.0
        _triage_se: float = 0.0
        _triage_ml_prob: float | None = None
        vuln_db = _load_builtin_vuln_db()
        ioc_db = _load_builtin_ioc_db()
        ioc_db, vuln_db, intel_sources = _merge_user_intel(ioc_db, vuln_db)
        findings.extend(_binary_artifact_findings(inventory.binary_artifacts))

        if clamav:
            clamav_result = clamav_scan_paths(prepared.root, timeout_seconds=clamav_timeout_seconds)
            if not clamav_result.available:
                findings.append(
                    Finding(
                        id="AV-UNAVAILABLE",
                        category="artifact_malware",
                        severity=Severity.LOW,
                        confidence=1.0,
                        title="ClamAV unavailable",
                        evidence_path=str(prepared.root),
                        snippet=(clamav_result.message or "ClamAV unavailable")[:220],
                        mitigation="Install ClamAV (`clamscan`) or disable --clamav for this run.",
                    )
                )
            else:
                for detection in clamav_result.detections:
                    findings.append(
                        Finding(
                            id="AV-001",
                            category="artifact_malware",
                            severity=Severity.HIGH,
                            confidence=0.9,
                            title="ClamAV malware detection",
                            evidence_path=detection.path,
                            snippet=detection.signature[:220],
                            mitigation=(
                                "Treat detected artifact as malicious and remove/quarantine before execution."
                            ),
                        )
                    )

        # Advisory: if script files are present but ClamAV was not requested,
        # emit a single LOW advisory so the report can recommend a deeper scan.
        if not clamav:
            script_files = [p for p in files if p.suffix.lower() in SCRIPT_SUFFIXES]
            if script_files:
                sample = ", ".join(p.name for p in script_files[:3])
                if len(script_files) > 3:
                    sample += f" (+{len(script_files) - 3} more)"
                findings.append(
                    Finding(
                        id="AV-ADVISORY",
                        category="artifact_malware",
                        severity=Severity.LOW,
                        confidence=1.0,
                        title="Bundled script files detected — ClamAV scan not performed",
                        evidence_path=str(prepared.root),
                        snippet=sample,
                        mitigation=(
                            "This skill bundles executable script files. "
                            "Re-run with --clamav to perform a malware artifact scan on these files. "
                            "Alternatively, manually inspect the scripts before loading this skill."
                        ),
                    )
                )

        def _scan_one_file(
            path: Path,
        ) -> tuple[
            list[Finding],
            list[IOC],
            list[Capability],
            list[DependencyFinding],
            float,  # sem_inj triage score
            float,  # se triage score
            float | None,  # ml prob
        ]:
            """Scan a single file and return all findings/IOCs/capabilities.

            Designed to run inside a ThreadPoolExecutor so the caller can
            enforce a per-file wall-clock timeout via Future.result(timeout=...).
            """
            _f: list[Finding] = []
            _iocs: list[IOC] = []
            _caps: list[Capability] = []
            _deps: list[DependencyFinding] = []
            _sem: float = 0.0
            _se: float = 0.0
            _ml: float | None = None

            # Per-file size guard
            try:
                file_bytes = path.stat().st_size
            except OSError:
                file_bytes = 0
            if file_bytes > max_file_size_bytes:
                _f.append(
                    Finding(
                        id="SCAN-SIZE-SKIP",
                        category="scanner_advisory",
                        severity=Severity.LOW,
                        confidence=1.0,
                        title="File skipped — exceeds max file size",
                        evidence_path=str(path),
                        snippet=(
                            f"{file_bytes // 1024} KB > "
                            f"{max_file_size_bytes // 1024} KB limit. "
                            "Re-run with --max-file-size to raise the limit."
                        ),
                        mitigation="Inspect the file manually or raise --max-file-size.",
                    )
                )
                return _f, _iocs, _caps, _deps, _sem, _se, _ml

            text = _safe_read_text(path)
            if not text:
                return _f, _iocs, _caps, _deps, _sem, _se, _ml
            analysis_text = _prepare_analysis_text(text)

            # Build a section map so static rule findings can be weighted by context.
            section_map = build_section_map(analysis_text)
            lines_cache = analysis_text.splitlines()

            file_ext = path.suffix.lower()
            for rule in ruleset.static_rules:
                if rule.graph_rule:
                    continue
                if rule.language is not None:
                    allowed_exts = _LANG_EXTENSIONS.get(rule.language)
                    if allowed_exts is not None and file_ext not in allowed_exts:
                        continue
                if rule.multiline:
                    # Full-text match for patterns that span multiple lines
                    m = rule.pattern.search(analysis_text)
                    if m:
                        matched_text = m.group(0)
                        line_no = analysis_text[: m.start()].count("\n") + 1
                        section_mult = section_map.multiplier(line_no)
                        confidence = rule.confidence
                        if rule.negation_guard:
                            confidence = _apply_negation_guard(
                                lines_cache, line_no, confidence
                            )
                        _f.append(
                            Finding(
                                id=rule.id,
                                category=rule.category,
                                severity=rule.severity,
                                confidence=confidence,
                                title=rule.title,
                                evidence_path=str(path),
                                line=line_no,
                                snippet=matched_text.replace("\n", " ").strip()[:240],
                                mitigation=rule.mitigation,
                                chain_actions=[f"section_mult={section_mult:.2f}"],
                                section_context=section_map.section_name(line_no),
                            )
                        )
                else:
                    for line_no, line in enumerate(lines_cache, 1):
                        if rule.pattern.search(line):
                            section_mult = section_map.multiplier(line_no)
                            confidence = rule.confidence
                            if rule.negation_guard:
                                confidence = _apply_negation_guard(
                                    lines_cache, line_no, confidence
                                )
                            _f.append(
                                Finding(
                                    id=rule.id,
                                    category=rule.category,
                                    severity=rule.severity,
                                    confidence=confidence,
                                    title=rule.title,
                                    evidence_path=str(path),
                                    line=line_no,
                                    snippet=line.strip()[:240],
                                    mitigation=rule.mitigation,
                                    chain_actions=[f"section_mult={section_mult:.2f}"],
                                    section_context=section_map.section_name(line_no),
                                )
                            )
                            break

            _f.extend(local_prompt_injection_findings(path, analysis_text))
            _f.extend(local_social_engineering_findings(path, analysis_text))
            _sem = classify_prompt_injection_raw(analysis_text)
            _se = classify_social_engineering_raw(analysis_text)

            if ml_detect:
                ml_findings = ml_prompt_injection_findings(path, analysis_text)
                _f.extend(ml_findings)
                for mf in ml_findings:
                    if mf.id.startswith("ML-"):
                        _ml = max(_ml or 0.0, mf.confidence)

            for capability_name, pattern in ruleset.capability_patterns:
                if pattern.search(analysis_text):
                    _caps.append(
                        Capability(name=capability_name, evidence_path=str(path), detail="Pattern match")
                    )

            if file_ext == ".py":
                for ast_finding in detect_python_ast_flows(analysis_text):
                    _f.append(
                        Finding(
                            id=ast_finding.id,
                            category=ast_finding.category,
                            severity=ast_finding.severity,
                            confidence=ast_finding.confidence,
                            title=ast_finding.title,
                            evidence_path=str(path),
                            line=ast_finding.line,
                            snippet=ast_finding.snippet,
                            mitigation=ast_finding.mitigation,
                        )
                    )

            _iocs.extend(_extract_iocs(path, analysis_text))

            # Chain rules with windowed proximity constraint
            _window_cache: dict[int, list[set[str]]] = {}

            def _get_windows(wl: int) -> list[set[str]]:
                if wl not in _window_cache:
                    _window_cache[wl] = _extract_actions_windowed(
                        analysis_text, ruleset.action_patterns, window_lines=wl
                    )
                return _window_cache[wl]

            fired_chain_ids: set[str] = set()
            for chain_rule in ruleset.chain_rules:
                if chain_rule.id in fired_chain_ids:
                    continue
                effective_window = (
                    chain_rule.window_lines if chain_rule.window_lines is not None else _CHAIN_WINDOW_LINES
                )
                for window_actions in _get_windows(effective_window):
                    if chain_rule.all_of.issubset(window_actions):
                        fired_chain_ids.add(chain_rule.id)
                        _f.append(
                            Finding(
                                id=chain_rule.id,
                                category=chain_rule.category,
                                severity=chain_rule.severity,
                                confidence=chain_rule.confidence,
                                title=chain_rule.title,
                                evidence_path=str(path),
                                snippet=chain_rule.snippet or " + ".join(sorted(chain_rule.all_of)),
                                mitigation=chain_rule.mitigation,
                                chain_actions=sorted(chain_rule.all_of),
                            )
                        )
                        break

            lower = path.name.lower()
            if lower == "requirements.txt":
                for name, version in _parse_requirements(text):
                    if name in vuln_db.get("python", {}) and version in vuln_db["python"][name]:
                        entry = vuln_db["python"][name][version]
                        _deps.append(
                            DependencyFinding(
                                ecosystem="python",
                                name=name,
                                version=version,
                                vulnerability_id=entry["id"],
                                severity=Severity(entry["severity"]),
                                fixed_version=entry.get("fixed"),
                            )
                        )
                for name, spec in _find_unpinned_requirements(text):
                    _f.append(
                        Finding(
                            id="DEP-UNPIN",
                            category="dependency_vulnerability",
                            severity=Severity.MEDIUM,
                            confidence=0.8,
                            title=f"Unpinned python dependency: {name}",
                            evidence_path=str(path),
                            snippet=spec,
                            mitigation=(
                                "Pin exact dependency versions to improve reproducibility "
                                "and reduce supply-chain risk."
                            ),
                        )
                    )
            if lower == "package.json":
                for name, version in _parse_package_json(text):
                    version_norm = version.lstrip("^~>=< ")
                    if name in vuln_db.get("npm", {}) and version_norm in vuln_db["npm"][name]:
                        entry = vuln_db["npm"][name][version_norm]
                        _deps.append(
                            DependencyFinding(
                                ecosystem="npm",
                                name=name,
                                version=version,
                                vulnerability_id=entry["id"],
                                severity=Severity(entry["severity"]),
                                fixed_version=entry.get("fixed"),
                            )
                        )
                    if _is_unpinned_npm(version):
                        _f.append(
                            Finding(
                                id="DEP-UNPIN",
                                category="dependency_vulnerability",
                                severity=Severity.MEDIUM,
                                confidence=0.75,
                                title=f"Unpinned npm dependency: {name}",
                                evidence_path=str(path),
                                snippet=f"{name}: {version}",
                                mitigation=(
                                    "Pin exact dependency versions to improve reproducibility "
                                    "and reduce supply-chain risk."
                                ),
                            )
                        )
                scripts = _parse_package_scripts(text)
                lifecycle_hooks = ("preinstall", "install", "postinstall", "prepare")
                for hook in lifecycle_hooks:
                    cmd = scripts.get(hook)
                    if not cmd:
                        continue
                    if RISKY_NPM_SCRIPT_RE.search(cmd):
                        _f.append(
                            Finding(
                                id="SUP-001",
                                category="malware_pattern",
                                severity=Severity.HIGH,
                                confidence=0.88,
                                title=f"Risky npm lifecycle script: {hook}",
                                evidence_path=str(path),
                                snippet=f"{hook}: {cmd[:220]}",
                                mitigation=(
                                    "Remove network/bootstrap execution from lifecycle hooks. "
                                    "Use explicit reviewed setup commands instead."
                                ),
                            )
                        )

            return _f, _iocs, _caps, _deps, _sem, _se, _ml

        # Dispatch per-file scan with individual timeout using a thread pool.
        # Each file gets file_timeout_seconds; if it exceeds the limit a
        # SCAN-TIMEOUT-SKIP advisory finding is emitted and the file is skipped.
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as _executor:
            _futures = {_executor.submit(_scan_one_file, p): p for p in files}
            for _fut, _path in _futures.items():
                try:
                    _ff, _fi, _fc, _fd, _sem, _se, _ml = _fut.result(timeout=file_timeout_seconds)
                    findings.extend(_ff)
                    iocs.extend(_fi)
                    capabilities.extend(_fc)
                    dependency_findings.extend(_fd)
                    _triage_sem_inj = max(_triage_sem_inj, _sem)
                    _triage_se = max(_triage_se, _se)
                    if _ml is not None:
                        _triage_ml_prob = max(_triage_ml_prob or 0.0, _ml)
                except concurrent.futures.TimeoutError:
                    findings.append(
                        Finding(
                            id="SCAN-TIMEOUT-SKIP",
                            category="scanner_advisory",
                            severity=Severity.LOW,
                            confidence=1.0,
                            title="File skipped — per-file scan timeout exceeded",
                            evidence_path=str(_path),
                            snippet=(
                                f"Scan exceeded {file_timeout_seconds}s limit. "
                                "Re-run with --timeout to raise the limit."
                            ),
                            mitigation="Inspect the file manually or raise --timeout.",
                        )
                    )

        dedup_iocs: dict[tuple[str, str, str], IOC] = {}
        allow_domains = {d.lower() for d in policy.allow_domains}
        for ioc in iocs:
            key = (ioc.kind, ioc.value.lower(), ioc.source_path)
            listed = False
            if ioc.kind == "domain" and ioc.value.lower() in ioc_db.get("domains", []):
                listed = True
            if ioc.kind == "ip" and ioc.value in ioc_db.get("ips", []):
                listed = True
            if ioc.kind == "ip" and _ip_in_cidrs(ioc.value, ioc_db.get("cidrs", [])):
                listed = True
            if ioc.kind == "url" and ioc.value.lower() in ioc_db.get("urls", []):
                listed = True
            if ioc.kind == "domain" and ioc.value.lower() in allow_domains:
                listed = False
            ioc.listed = listed
            dedup_iocs[key] = ioc
        iocs = list(dedup_iocs.values())

        block_domains = {d.lower() for d in policy.block_domains}
        for ioc in iocs:
            if ioc.kind == "domain" and ioc.value.lower() in block_domains:
                findings.append(
                    Finding(
                        id="POL-IOC-BLOCK",
                        category="threat_intel",
                        severity=Severity.HIGH,
                        confidence=1.0,
                        title="Domain blocked by local policy",
                        evidence_path=ioc.source_path,
                        snippet=ioc.value,
                        mitigation=(
                            "Replace blocked destination with an approved domain "
                            "or remove network dependency."
                        ),
                    )
                )

        for ioc in iocs:
            if ioc.listed:
                findings.append(
                    Finding(
                        id="IOC-001",
                        category="threat_intel",
                        severity=Severity.HIGH,
                        confidence=0.95,
                        title="IOC matched local blocklist",
                        evidence_path=ioc.source_path,
                        snippet=ioc.value,
                        mitigation=(
                            "Block install/use and investigate indicator reputation. "
                            "Remove all references to this IOC."
                        ),
                    )
                )

        for dep in dependency_findings:
            findings.append(
                Finding(
                    id="DEP-001",
                    category="dependency_vulnerability",
                    severity=dep.severity,
                    confidence=0.9,
                    title=f"Vulnerable dependency: {dep.name}@{dep.version}",
                    evidence_path=dep.name,
                    snippet=dep.vulnerability_id,
                    mitigation="Upgrade to a non-vulnerable dependency version and refresh lockfiles.",
                )
            )

        if prepared.read_warnings:
            findings.append(
                Finding(
                    id="SRC-READ-ERR",
                    category="source_access",
                    severity=Severity.LOW,
                    confidence=1.0,
                    title="Some linked sources could not be fetched",
                    evidence_path=str(target),
                    snippet=f"unreadable_links={len(prepared.read_warnings)}",
                    mitigation=(
                        "Verify linked source URLs are reachable and public. "
                        "Unreachable links are not treated as malicious by default."
                    ),
                )
            )

        if prepared.policy_warnings:
            for warning in prepared.policy_warnings:
                if warning.startswith("BIN-OPAQUE-002:"):
                    archive_name = warning.split(":", 2)[1]
                    findings.append(
                        Finding(
                            id="BIN-OPAQUE-002",
                            category="binary_artifact",
                            severity=Severity.MEDIUM,
                            confidence=0.9,
                            title="Password-protected archive — contents unverified",
                            evidence_path=str(target),
                            snippet=archive_name,
                            mitigation=(
                                "The archive is password-protected and could not be extracted for scanning. "
                                "Manually inspect the contents before loading this skill."
                            ),
                        )
                    )
                elif warning.startswith("BIN-OPAQUE-001:"):
                    parts = warning.split(":", 3)
                    archive_name = parts[1] if len(parts) > 1 else str(target)
                    reason = parts[2] if len(parts) > 2 else "unsupported format"
                    findings.append(
                        Finding(
                            id="BIN-OPAQUE-001",
                            category="binary_artifact",
                            severity=Severity.MEDIUM,
                            confidence=0.8,
                            title="Archive format not extractable — contents unverified",
                            evidence_path=str(target),
                            snippet=f"{archive_name}: {reason}",
                            mitigation=(
                                "Install skillscan[archives] for expanded archive support, "
                                "or manually inspect the archive contents before loading this skill."
                            ),
                        )
                    )
                else:
                    # URL skip policy warning (legacy path)
                    findings.append(
                        Finding(
                            id="URL-SKIP-POLICY",
                            category="source_access",
                            severity=Severity.LOW,
                            confidence=1.0,
                            title="Some linked sources were skipped by URL safety policy",
                            evidence_path=str(target),
                            snippet=f"skipped_links={len(prepared.policy_warnings)}",
                            mitigation=(
                                "Links skipped due to same-origin policy. "
                                "Use --url-same-origin-only false to include cross-origin links when needed."
                            ),
                        )
                    )
                    break  # one finding per batch of URL warnings

        if graph_scan:
            from skillscan.detectors.skill_graph import skill_graph_findings

            findings.extend(skill_graph_findings(prepared.root))

        findings = _deduplicate_findings(findings)

        score = 0
        block_score = 0
        for finding in findings:
            weight = policy.weights.get(finding.category, 1)
            base_contribution = SEVERITY_SCORE[finding.severity] * weight
            # Apply section multiplier when present (set by static rule matching).
            # Semantic and ML findings have no section_mult tag and score at 1.0×.
            # Floor of 1 ensures no finding is completely zeroed out by context
            # multipliers (e.g. negation guard + documentation section stacking).
            section_mult = _extract_section_mult(finding.chain_actions)
            contribution = max(1, int(base_contribution * section_mult))
            score += contribution
            if finding.confidence >= policy.block_min_confidence:
                block_score += contribution

        if any(
            f.id in policy.hard_block_rules and f.confidence >= policy.block_min_confidence for f in findings
        ):
            verdict = Verdict.BLOCK
        elif block_score >= policy.thresholds["block"]:
            verdict = Verdict.BLOCK
        elif score >= policy.thresholds["warn"]:
            verdict = Verdict.WARN
        else:
            verdict = Verdict.ALLOW

        metadata = ScanMetadata(
            scanner_version=__version__,
            target=str(target),
            target_type=prepared.target_type,
            ecosystem_hints=detect_ecosystems(prepared.root),
            rulepack_version=ruleset.version,
            policy_profile=policy.name,
            policy_source=policy_source,
            intel_sources=intel_sources,
        )

        # Build triage metadata — compute has_sub_threshold_signal
        _has_sub = (
            (_triage_sem_inj > 0.25)
            or (_triage_se > 0.25)
            or (_triage_ml_prob is not None and _triage_ml_prob > 0.30)
        )
        triage_metadata = TriageMetadata(
            semantic_injection_score=round(_triage_sem_inj, 4),
            social_engineering_score=round(_triage_se, 4),
            ml_injection_probability=(round(_triage_ml_prob, 4) if _triage_ml_prob is not None else None),
            has_sub_threshold_signal=_has_sub,
        )

        return ScanReport(
            metadata=metadata,
            verdict=verdict,
            score=score,
            findings=findings,
            iocs=iocs,
            dependency_findings=dependency_findings,
            capabilities=capabilities,
            triage_metadata=triage_metadata,
        )
    finally:
        if prepared.cleanup_dir is not None:
            prepared.cleanup_dir.cleanup()
        os.environ.pop("PYTHONINSPECT", None)
