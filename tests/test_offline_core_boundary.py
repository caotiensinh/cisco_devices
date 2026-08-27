import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OFFLINE_CORE = [
    ROOT / "cisco_assistant" / "models.py",
    ROOT / "cisco_assistant" / "ipam.py",
    ROOT / "cisco_assistant" / "validation.py",
    ROOT / "cisco_assistant" / "profiles.py",
    ROOT / "cisco_assistant" / "profile_registry.py",
    ROOT / "cisco_assistant" / "exact_device_workflow.py",
    ROOT / "cisco_assistant" / "r0_evidence.py",
    ROOT / "cisco_assistant" / "r0_validation_promotion.py",
    ROOT / "cisco_assistant" / "targeted_help_evidence.py",
    ROOT / "cisco_assistant" / "targeted_help_diagnostic.py",
    ROOT / "cisco_assistant" / "documented_output_parsers.py",
    ROOT / "cisco_assistant" / "templates.py",
    ROOT / "cisco_assistant" / "template_migrations.py",
    ROOT / "cisco_assistant" / "preview.py",
    ROOT / "cisco_assistant" / "workflow.py",
    ROOT / "cisco_assistant" / "security_profiles.py",
    ROOT / "cisco_assistant" / "current_state.py",
    ROOT / "cisco_assistant" / "state_view.py",
    ROOT / "cisco_assistant" / "planner.py",
    ROOT / "cisco_assistant" / "plan_analysis.py",
    ROOT / "cisco_assistant" / "dry_run.py",
    ROOT / "cisco_assistant" / "export_bundle.py",
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
DANGEROUS_CLI_PREFIXES = (
    "configure terminal",
    "copy running-config startup-config",
    "write memory",
    "reload",
    "clear logging",
    "delete flash:",
)


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


def dangerous_cli_lines(text: str) -> set[str]:
    """Return string-literal lines that look like executable write CLI.

    Matching is line/prefix based instead of raw substring based so safety metadata such
    as ``reboot_or_reload_performed`` cannot be mistaken for the standalone ``reload``
    command. Multiline command bundles are still detected one line at a time.
    """
    found: set[str] = set()
    for raw_line in text.splitlines() or [text]:
        line = " ".join(raw_line.strip().lower().split())
        if not line:
            continue
        for prefix in DANGEROUS_CLI_PREFIXES:
            if line == prefix or line.startswith(prefix + " ") or (
                prefix.endswith(":") and line.startswith(prefix)
            ):
                found.add(prefix)
    return found


def embedded_dangerous_cli_literals(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            found.update(dangerous_cli_lines(node.value))
    return found


def test_normalized_offline_core_has_no_device_execution_imports():
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


def test_cli_literal_scanner_ignores_metadata_but_detects_real_command_lines():
    assert dangerous_cli_lines("reboot_or_reload_performed") == set()
    assert dangerous_cli_lines("no reboot/reload was performed") == set()
    assert dangerous_cli_lines("reload") == {"reload"}
    assert dangerous_cli_lines("  configure   terminal  ") == {"configure terminal"}
    assert dangerous_cli_lines("safe note\ndelete flash:config.txt") == {"delete flash:"}


def test_offline_design_policy_planner_analysis_dry_run_and_export_do_not_embed_cisco_write_cli():
    violations = {}
    for relative in (
        "cisco_assistant/profile_registry.py",
        "cisco_assistant/exact_device_workflow.py",
        "cisco_assistant/r0_evidence.py",
        "cisco_assistant/r0_validation_promotion.py",
        "cisco_assistant/targeted_help_evidence.py",
        "cisco_assistant/targeted_help_diagnostic.py",
        "cisco_assistant/documented_output_parsers.py",
        "cisco_assistant/templates.py",
        "cisco_assistant/template_migrations.py",
        "cisco_assistant/preview.py",
        "cisco_assistant/workflow.py",
        "cisco_assistant/security_profiles.py",
        "cisco_assistant/current_state.py",
        "cisco_assistant/state_view.py",
        "cisco_assistant/planner.py",
        "cisco_assistant/plan_analysis.py",
        "cisco_assistant/dry_run.py",
        "cisco_assistant/export_bundle.py",
    ):
        found = sorted(embedded_dangerous_cli_literals(ROOT / relative))
        if found:
            violations[relative] = found
    assert not violations, f"Offline design/policy/planner/analysis/dry-run/export layer embedded device write CLI: {violations}"
