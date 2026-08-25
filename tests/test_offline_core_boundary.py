import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OFFLINE_CORE = [
    ROOT / "cisco_assistant" / "models.py",
    ROOT / "cisco_assistant" / "ipam.py",
]
FORBIDDEN_IMPORT_ROOTS = {
    "paramiko",
    "socket",
    "subprocess",
    "requests",
    "httpx",
    "telnetlib",
    "asyncssh",
    "netmiko",
    "scrapli",
}


def imported_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".", 1)[0])
    return roots


def test_normalized_models_and_ipam_are_offline_only():
    violations = {}
    for path in OFFLINE_CORE:
        bad = imported_roots(path) & FORBIDDEN_IMPORT_ROOTS
        if bad:
            violations[str(path.relative_to(ROOT))] = sorted(bad)
    assert not violations, f"Offline core imported device/network execution libraries: {violations}"


def test_offline_core_has_no_raw_cli_execution_api_names():
    forbidden_function_names = {
        "execute_command",
        "execute_cli",
        "send_command",
        "send_config_set",
        "invoke_shell",
        "connect_switch",
    }
    violations = {}
    for path in OFFLINE_CORE:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        names = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        bad = names & forbidden_function_names
        if bad:
            violations[str(path.relative_to(ROOT))] = sorted(bad)
    assert not violations, f"Offline core exposed CLI/device execution APIs: {violations}"
