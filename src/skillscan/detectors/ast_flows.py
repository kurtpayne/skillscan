from __future__ import annotations

import ast
from dataclasses import dataclass

from skillscan.models import Severity


@dataclass
class AstFlowFinding:
    id: str
    category: str
    severity: Severity
    confidence: float
    title: str
    line: int
    snippet: str
    mitigation: str


SECRET_NAMES = {".env", "id_rsa", "aws_access_key_id", "credentials", "secret", "token", "apikey"}
SECRET_SOURCE_CALLS = {
    "os.getenv",
    "dotenv_values",
    "load_dotenv",
}
EXEC_SINK_CALLS = {
    "eval",
    "exec",
    "os.system",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
}
NETWORK_SINK_CALLS = {
    "requests.post",
    "requests.put",
    "requests.get",
    "requests.request",
    "urllib.request.urlopen",
    "socket.send",
    "socket.sendall",
    "smtplib.SMTP.sendmail",
}
DECODE_CALLS = {
    "base64.b64decode",
    "bytes.fromhex",
    "zlib.decompress",
    "marshal.loads",
}
EXEC_SINK_SUFFIXES = {".system", ".run", ".Popen", ".call"}
NETWORK_SINK_SUFFIXES = {".send", ".sendall", ".post", ".put", ".get", ".request", ".urlopen", ".sendmail"}


class AstFlowDetector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.tags: dict[str, set[str]] = {}
        self.findings: list[AstFlowFinding] = []

    def _name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            root = self._name(node.value)
            return f"{root}.{node.attr}" if root else node.attr
        if isinstance(node, ast.Call):
            return self._name(node.func)
        return ""

    def _string_literals(self, node: ast.AST) -> list[str]:
        out: list[str] = []
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            out.append(node.value)
        for child in ast.iter_child_nodes(node):
            out.extend(self._string_literals(child))
        return out

    def _expr_tags(self, node: ast.AST) -> set[str]:
        tags: set[str] = set()
        if isinstance(node, ast.Name):
            tags |= self.tags.get(node.id, set())
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            low = node.value.lower()
            if any(k in low for k in SECRET_NAMES):
                tags.add("secret")
        if isinstance(node, ast.Call):
            fname = self._name(node.func)
            if fname in SECRET_SOURCE_CALLS:
                tags.add("secret")
            if fname in DECODE_CALLS:
                tags.add("constructed")
            if fname in NETWORK_SINK_CALLS:
                tags.add("network")
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            tags |= self._expr_tags(node.left)
            tags |= self._expr_tags(node.right)
            tags.add("constructed")
        if isinstance(node, ast.JoinedStr):
            tags.add("constructed")
            for v in node.values:
                tags |= self._expr_tags(v)
        for child in ast.iter_child_nodes(node):
            tags |= self._expr_tags(child)
        return tags

    def _args_tags(self, call: ast.Call) -> set[str]:
        tags: set[str] = set()
        for arg in call.args:
            tags |= self._expr_tags(arg)
        for kw in call.keywords:
            if kw.value is not None:
                tags |= self._expr_tags(kw.value)
        return tags

    def _is_exec_sink(self, fname: str) -> bool:
        return fname in EXEC_SINK_CALLS or any(fname.endswith(suffix) for suffix in EXEC_SINK_SUFFIXES)

    def _is_network_sink(self, fname: str) -> bool:
        return fname in NETWORK_SINK_CALLS or any(
            fname.endswith(suffix) for suffix in NETWORK_SINK_SUFFIXES
        )

    def visit_Assign(self, node: ast.Assign) -> None:
        value_tags = self._expr_tags(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.tags[target.id] = set(value_tags)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        fname = self._name(node.func)
        arg_tags = self._args_tags(node)
        text_blob = " ".join(self._string_literals(node)).lower()

        if self._is_exec_sink(fname) and ("constructed" in arg_tags or "secret" in arg_tags):
            self.findings.append(
                AstFlowFinding(
                    id="AST-001",
                    category="malware_pattern",
                    severity=Severity.CRITICAL,
                    confidence=0.92,
                    title="Constructed input reaches execution sink",
                    line=getattr(node, "lineno", 1),
                    snippet=fname,
                    mitigation="Remove dynamic code execution paths and avoid eval/exec/system sinks.",
                )
            )

        if self._is_network_sink(fname) and (
            "secret" in arg_tags or any(k in text_blob for k in SECRET_NAMES)
        ):
            self.findings.append(
                AstFlowFinding(
                    id="AST-002",
                    category="exfiltration",
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    title="Potential secret data sent to network sink",
                    line=getattr(node, "lineno", 1),
                    snippet=fname,
                    mitigation="Do not transmit credentials/secrets over network sinks.",
                )
            )

        self.generic_visit(node)


def detect_python_ast_flows(text: str) -> list[AstFlowFinding]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    detector = AstFlowDetector()
    detector.visit(tree)
    return detector.findings
