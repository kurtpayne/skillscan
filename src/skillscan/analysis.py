from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import os
import re
import tarfile
import tempfile
import unicodedata
import zipfile
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import cast

from skillscan import __version__
from skillscan.ecosystems import detect_ecosystems
from skillscan.intel import load_store
from skillscan.models import (
    IOC,
    Capability,
    DependencyFinding,
    Finding,
    Policy,
    ScanMetadata,
    ScanReport,
    Severity,
    Verdict,
    is_archive,
)

PATTERNS: list[tuple[str, str, Severity, str, re.Pattern[str]]] = [
    (
        "MAL-001",
        "malware_pattern",
        Severity.CRITICAL,
        "Download-and-execute chain",
        re.compile(r"(curl|wget).*(bash|sh)", re.IGNORECASE),
    ),
    (
        "MAL-002",
        "malware_pattern",
        Severity.HIGH,
        "Base64 decode + execution",
        re.compile(r"base64\s+-d.*(bash|sh|python)", re.IGNORECASE),
    ),
    (
        "ABU-001",
        "instruction_abuse",
        Severity.HIGH,
        "Coercive prerequisite wording",
        re.compile(r"must run.*sudo|disable.*security|turn off.*defender", re.IGNORECASE),
    ),
    (
        "EXF-001",
        "exfiltration",
        Severity.HIGH,
        "Sensitive credential file access",
        re.compile(r"(\.env|id_rsa|aws_access_key_id|browser.*cookies)", re.IGNORECASE),
    ),
]

CAPABILITY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "shell_execution",
        re.compile(r"\b(subprocess|os\.system|bash|powershell)\b", re.IGNORECASE),
    ),
    ("network_access", re.compile(r"\b(requests\.|fetch\(|axios|http[s]?://|socket)\b", re.IGNORECASE)),
    ("filesystem_write", re.compile(r"\b(open\(.*[wa]|write_text\(|append)\b", re.IGNORECASE)),
]

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u2060\ufeff]")
B64_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
KNOWN_TLDS = {
    "ai",
    "app",
    "biz",
    "co",
    "com",
    "dev",
    "edu",
    "fr",
    "gov",
    "info",
    "io",
    "jp",
    "net",
    "org",
    "ru",
    "uk",
    "us",
    "xyz",
}

SEVERITY_SCORE = {
    Severity.LOW: 5,
    Severity.MEDIUM: 15,
    Severity.HIGH: 35,
    Severity.CRITICAL: 60,
}

IOCDB = dict[str, list[str]]
VulnRecord = dict[str, str]
VulnVersionMap = dict[str, VulnRecord]
VulnPackageMap = dict[str, VulnVersionMap]
VulnDB = dict[str, VulnPackageMap]

MITIGATIONS = {
    "MAL-001": "Remove download-and-execute chains. Pin and verify artifacts before execution.",
    "MAL-002": "Avoid decode-and-exec flows. Store reviewed scripts in-repo and execute only trusted files.",
    "ABU-001": "Remove coercive setup steps. Do not ask users to disable security controls.",
    "EXF-001": "Do not read secret files unless strictly required; use scoped secret providers instead.",
    "IOC-001": "Block install/use and investigate indicator reputation. Remove all references to this IOC.",
    "POL-IOC-BLOCK": "Replace blocked destination with an approved domain or remove network dependency.",
    "DEP-001": "Upgrade to a non-vulnerable dependency version and refresh lockfiles.",
    "DEP-UNPIN": "Pin exact dependency versions to improve reproducibility and reduce supply-chain risk.",
    "CHN-001": "Break download-and-execute behavior. Require reviewed local artifacts before execution.",
    "CHN-002": "Remove secret-to-network data flow. Secrets must not be sent to outbound endpoints.",
    "ABU-002": "Remove elevated-security-bypass sequences. Do not require sudo plus security disablement.",
}

ACTION_PATTERNS: dict[str, re.Pattern[str]] = {
    "download": re.compile(r"\b(curl|wget|invoke-webrequest|iwr|download)\b|https?://", re.IGNORECASE),
    "execute": re.compile(
        r"\b(bash|sh|powershell|cmd\.exe|os\.system|subprocess|python\s+-c)\b", re.IGNORECASE
    ),
    "secret_access": re.compile(r"(\.env|id_rsa|aws_access_key_id|ssh key|credentials?)", re.IGNORECASE),
    "network": re.compile(r"https?://|webhook|post\b|upload|socket|requests\.", re.IGNORECASE),
    "privilege": re.compile(r"\bsudo\b|run as administrator|elevat", re.IGNORECASE),
    "security_disable": re.compile(
        r"disable (security|defender|av|antivirus)|turn off (security|defender|av|antivirus)",
        re.IGNORECASE,
    ),
}


@dataclass
class PreparedTarget:
    root: Path
    target_type: str
    cleanup_dir: tempfile.TemporaryDirectory[str] | None


class ScanError(Exception):
    pass


def _safe_extract_zip(src: Path, dst: Path, max_files: int, max_bytes: int) -> None:
    total = 0
    with zipfile.ZipFile(src) as zf:
        infos = zf.infolist()
        if len(infos) > max_files:
            raise ScanError(f"Archive has too many files: {len(infos)}")
        for info in infos:
            name = info.filename
            if name.startswith("/") or ".." in Path(name).parts:
                raise ScanError(f"Unsafe archive path: {name}")
            total += info.file_size
            if total > max_bytes:
                raise ScanError("Archive exceeds max bytes limit")
            zf.extract(info, dst)


def _safe_extract_tar(src: Path, dst: Path, max_files: int, max_bytes: int) -> None:
    total = 0
    with tarfile.open(src) as tf:
        members = tf.getmembers()
        if len(members) > max_files:
            raise ScanError(f"Archive has too many files: {len(members)}")
        for member in members:
            p = Path(member.name)
            if p.is_absolute() or ".." in p.parts:
                raise ScanError(f"Unsafe archive path: {member.name}")
            if member.issym() or member.islnk():
                raise ScanError(f"Symlink/hardlink not allowed in archive: {member.name}")
            total += member.size
            if total > max_bytes:
                raise ScanError("Archive exceeds max bytes limit")
        tf.extractall(dst, filter="data")


def prepare_target(target: Path, policy: Policy) -> PreparedTarget:
    if not target.exists():
        raise ScanError(f"Target does not exist: {target}")
    if target.is_dir():
        return PreparedTarget(root=target, target_type="directory", cleanup_dir=None)
    if target.is_file() and not is_archive(target):
        tmp = tempfile.TemporaryDirectory(prefix="skillscan-")
        dst = Path(tmp.name)
        (dst / target.name).write_bytes(target.read_bytes())
        return PreparedTarget(root=dst, target_type="file", cleanup_dir=tmp)
    if target.is_file() and is_archive(target):
        tmp = tempfile.TemporaryDirectory(prefix="skillscan-")
        dst = Path(tmp.name)
        if target.suffix.lower() == ".zip":
            _safe_extract_zip(target, dst, policy.limits["max_files"], policy.limits["max_bytes"])
        else:
            _safe_extract_tar(target, dst, policy.limits["max_files"], policy.limits["max_bytes"])
        return PreparedTarget(root=dst, target_type="archive", cleanup_dir=tmp)
    raise ScanError("Unsupported target type")


def iter_text_files(root: Path, max_files: int, max_bytes: int) -> list[Path]:
    files: list[Path] = []
    total_bytes = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if "__pycache__" in path.parts:
            continue
        if path.suffix.lower() in {".pyc", ".so", ".dll", ".dylib", ".exe", ".bin"}:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        total_bytes += size
        if total_bytes > max_bytes:
            raise ScanError("Scan size exceeded max_bytes policy limit")
        files.append(path)
        if len(files) > max_files:
            raise ScanError("Scan file count exceeded max_files policy limit")
    return files


def _safe_read_text(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except OSError:
        return ""
    if b"\x00" in raw:
        return ""
    return raw.decode("utf-8", errors="ignore")


def _normalize_text(text: str) -> str:
    norm = unicodedata.normalize("NFKC", text)
    return ZERO_WIDTH_RE.sub("", norm)


def _decode_base64_fragments(text: str, max_decodes: int = 6) -> list[str]:
    decoded: list[str] = []
    seen: set[str] = set()
    for token in B64_TOKEN_RE.findall(text):
        if token in seen:
            continue
        seen.add(token)
        if len(decoded) >= max_decodes:
            break
        if len(token) % 4 != 0:
            continue
        try:
            blob = base64.b64decode(token, validate=True)
        except (binascii.Error, ValueError):
            continue
        if not blob:
            continue
        candidate = blob.decode("utf-8", errors="ignore").strip()
        if not candidate:
            continue
        # Keep only mostly-printable decoded strings to avoid binary noise.
        printable_ratio = sum(ch.isprintable() for ch in candidate) / max(len(candidate), 1)
        if printable_ratio >= 0.9:
            decoded.append(candidate)
    return decoded


def _prepare_analysis_text(text: str) -> str:
    norm = _normalize_text(text)
    decoded = _decode_base64_fragments(norm)
    if not decoded:
        return norm
    return f"{norm}\n\n# decoded_fragments\n" + "\n".join(decoded)


def _extract_actions(text: str) -> set[str]:
    actions: set[str] = set()
    for action, pattern in ACTION_PATTERNS.items():
        if pattern.search(text):
            actions.add(action)
    return actions


def _normalize_domain(value: str) -> str:
    return value.lower().strip().strip(".,;)")


def _parse_requirements(text: str) -> list[tuple[str, str]]:
    deps: list[tuple[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" in line:
            name, version = line.split("==", 1)
            deps.append((name.strip().lower(), version.strip()))
    return deps


def _find_unpinned_requirements(text: str) -> list[tuple[str, str]]:
    unpinned: list[tuple[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" in line:
            continue
        if any(op in line for op in (">=", "<=", "~=", ">", "<")):
            unpinned.append((line.split()[0], line))
    return unpinned


def _parse_package_json(text: str) -> list[tuple[str, str]]:
    deps: list[tuple[str, str]] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return deps
    for section in ("dependencies", "devDependencies"):
        values = data.get(section, {})
        if isinstance(values, dict):
            for name, version in values.items():
                deps.append((name.lower(), str(version)))
    return deps


def _is_unpinned_npm(version: str) -> bool:
    v = version.strip().lower()
    if not v or v == "latest":
        return True
    return v.startswith("^") or v.startswith("~") or "*" in v or "x" in v


def _extract_iocs(path: Path, text: str) -> list[IOC]:
    iocs: list[IOC] = []
    seen: set[tuple[str, str]] = set()
    for url in URL_RE.findall(text):
        key = ("url", url)
        if key not in seen:
            seen.add(key)
            iocs.append(IOC(value=url, kind="url", source_path=str(path)))
    for token in IP_RE.findall(text):
        try:
            ipaddress.ip_address(token)
        except ValueError:
            continue
        key = ("ip", token)
        if key not in seen:
            seen.add(key)
            iocs.append(IOC(value=token, kind="ip", source_path=str(path)))
    for domain in DOMAIN_RE.findall(text):
        norm = _normalize_domain(domain)
        if norm.startswith("http"):
            continue
        tld = norm.rsplit(".", 1)[-1]
        if tld not in KNOWN_TLDS:
            continue
        key = ("domain", norm)
        if key not in seen:
            seen.add(key)
            iocs.append(IOC(value=norm, kind="domain", source_path=str(path)))
    return iocs


def _load_builtin_vuln_db() -> VulnDB:
    raw = resources.files("skillscan.data.intel").joinpath("vuln_db.json").read_text(encoding="utf-8")
    return cast(VulnDB, json.loads(raw))


def _load_builtin_ioc_db() -> IOCDB:
    raw = resources.files("skillscan.data.intel").joinpath("ioc_db.json").read_text(encoding="utf-8")
    return cast(IOCDB, json.loads(raw))


def _merge_user_intel(ioc_db: IOCDB, vuln_db: VulnDB) -> tuple[IOCDB, VulnDB, list[str]]:
    store = load_store()
    sources = ["builtin:ioc_db", "builtin:vuln_db"]
    for source in store.sources:
        if not source.enabled:
            continue
        path = Path(source.path)
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if source.kind == "ioc" and isinstance(payload, dict):
            for key in ("domains", "ips", "urls", "cidrs"):
                values = payload.get(key, [])
                if isinstance(values, list):
                    ioc_db.setdefault(key, []).extend([str(v).lower() for v in values])
        if source.kind == "vuln" and isinstance(payload, dict):
            for ecosystem, values in payload.items():
                eco = vuln_db.setdefault(ecosystem, {})
                if isinstance(values, dict):
                    eco.update(values)
        sources.append(f"user:{source.name}")
    for key in ("domains", "ips", "urls", "cidrs"):
        deduped = sorted(set(ioc_db.get(key, [])))
        ioc_db[key] = deduped
    return ioc_db, vuln_db, sources


def _ip_in_cidrs(ip_value: str, cidrs: list[str]) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_value)
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            if ip_obj in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def scan(target: Path, policy: Policy, policy_source: str) -> ScanReport:
    prepared = prepare_target(target, policy)
    try:
        files = iter_text_files(prepared.root, policy.limits["max_files"], policy.limits["max_bytes"])
        findings: list[Finding] = []
        iocs: list[IOC] = []
        capabilities: list[Capability] = []
        dependency_findings: list[DependencyFinding] = []

        vuln_db = _load_builtin_vuln_db()
        ioc_db = _load_builtin_ioc_db()
        ioc_db, vuln_db, intel_sources = _merge_user_intel(ioc_db, vuln_db)

        for path in files:
            text = _safe_read_text(path)
            if not text:
                continue
            analysis_text = _prepare_analysis_text(text)

            for rule_id, category, severity, title, pattern in PATTERNS:
                for line_no, line in enumerate(analysis_text.splitlines(), 1):
                    if pattern.search(line):
                        findings.append(
                            Finding(
                                id=rule_id,
                                category=category,
                                severity=severity,
                                confidence=0.9 if severity in {Severity.HIGH, Severity.CRITICAL} else 0.7,
                                title=title,
                                evidence_path=str(path),
                                line=line_no,
                                snippet=line.strip()[:240],
                                mitigation=MITIGATIONS.get(rule_id),
                            )
                        )
                        break

            for capability_name, pattern in CAPABILITY_PATTERNS:
                if pattern.search(analysis_text):
                    capabilities.append(
                        Capability(name=capability_name, evidence_path=str(path), detail="Pattern match")
                    )

            iocs.extend(_extract_iocs(path, analysis_text))

            actions = _extract_actions(analysis_text)
            if {"download", "execute"}.issubset(actions):
                findings.append(
                    Finding(
                        id="CHN-001",
                        category="malware_pattern",
                        severity=Severity.CRITICAL,
                        confidence=0.95,
                        title="Dangerous action chain: download plus execute",
                        evidence_path=str(path),
                        snippet="download + execute actions detected",
                        mitigation=MITIGATIONS.get("CHN-001"),
                    )
                )
            if {"secret_access", "network"}.issubset(actions):
                findings.append(
                    Finding(
                        id="CHN-002",
                        category="exfiltration",
                        severity=Severity.CRITICAL,
                        confidence=0.92,
                        title="Potential secret exfiltration chain",
                        evidence_path=str(path),
                        snippet="secret access + outbound network actions detected",
                        mitigation=MITIGATIONS.get("CHN-002"),
                    )
                )
            if {"privilege", "security_disable"}.issubset(actions):
                findings.append(
                    Finding(
                        id="ABU-002",
                        category="instruction_abuse",
                        severity=Severity.HIGH,
                        confidence=0.9,
                        title="Elevated setup with security bypass",
                        evidence_path=str(path),
                        snippet="privilege escalation + security disable sequence detected",
                        mitigation=MITIGATIONS.get("ABU-002"),
                    )
                )

            lower = path.name.lower()
            if lower == "requirements.txt":
                for name, version in _parse_requirements(text):
                    if name in vuln_db.get("python", {}) and version in vuln_db["python"][name]:
                        entry = vuln_db["python"][name][version]
                        dependency_findings.append(
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
                    findings.append(
                        Finding(
                            id="DEP-UNPIN",
                            category="dependency_vulnerability",
                            severity=Severity.MEDIUM,
                            confidence=0.8,
                            title=f"Unpinned python dependency: {name}",
                            evidence_path=str(path),
                            snippet=spec,
                            mitigation=MITIGATIONS.get("DEP-UNPIN"),
                        )
                    )
            if lower == "package.json":
                for name, version in _parse_package_json(text):
                    version_norm = version.lstrip("^~>=< ")
                    if name in vuln_db.get("npm", {}) and version_norm in vuln_db["npm"][name]:
                        entry = vuln_db["npm"][name][version_norm]
                        dependency_findings.append(
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
                        findings.append(
                            Finding(
                                id="DEP-UNPIN",
                                category="dependency_vulnerability",
                                severity=Severity.MEDIUM,
                                confidence=0.75,
                                title=f"Unpinned npm dependency: {name}",
                                evidence_path=str(path),
                                snippet=f"{name}: {version}",
                                mitigation=MITIGATIONS.get("DEP-UNPIN"),
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
                        mitigation=MITIGATIONS.get("POL-IOC-BLOCK"),
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
                        mitigation=MITIGATIONS.get("IOC-001"),
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
                    mitigation=MITIGATIONS.get("DEP-001"),
                )
            )

        score = 0
        for finding in findings:
            weight = policy.weights.get(finding.category, 1)
            score += SEVERITY_SCORE[finding.severity] * weight

        if any(f.id in policy.hard_block_rules for f in findings):
            verdict = Verdict.BLOCK
        elif score >= policy.thresholds["block"]:
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
            policy_profile=policy.name,
            policy_source=policy_source,
            intel_sources=intel_sources,
        )

        return ScanReport(
            metadata=metadata,
            verdict=verdict,
            score=score,
            findings=findings,
            iocs=iocs,
            dependency_findings=dependency_findings,
            capabilities=capabilities,
        )
    finally:
        if prepared.cleanup_dir is not None:
            prepared.cleanup_dir.cleanup()
        os.environ.pop("PYTHONINSPECT", None)
