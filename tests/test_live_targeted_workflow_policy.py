from pathlib import Path


WORKFLOW_PATH = Path('.github/workflows/cbs250-targeted-l3-live.yml')


def _workflow_text() -> str:
    return WORKFLOW_PATH.read_text(encoding='utf-8')


def test_live_targeted_workflow_is_manual_only() -> None:
    text = _workflow_text()
    assert '\n  workflow_dispatch:' in text
    assert '\n  push:' not in text
    assert '\n  pull_request:' not in text
    assert '\n  schedule:' not in text


def test_live_targeted_workflow_is_owner_and_self_hosted_only() -> None:
    text = _workflow_text()
    assert "if: github.actor == 'caotiensinh'" in text
    assert 'runs-on: [self-hosted, Windows, X64]' in text
    assert 'permissions:\n  contents: read' in text
    assert 'persist-credentials: false' in text


def test_live_targeted_workflow_uses_secrets_not_dispatch_password_input() -> None:
    text = _workflow_text()
    assert '${{ secrets.CBS250_HOST }}' in text
    assert '${{ secrets.CBS250_USERNAME }}' in text
    assert '${{ secrets.CBS250_PASSWORD }}' in text
    assert 'CBS_PASSWORD: ${{ secrets.CBS250_PASSWORD }}' in text
    assert 'inputs:' not in text


def test_live_targeted_workflow_runs_policy_checks_before_live_probe() -> None:
    text = _workflow_text()
    discovery_check = text.index('cbs250_cli_discovery_v311.py --policy-check')
    targeted_check = text.index('cbs250_targeted_help_probe.py --policy-check')
    authority_check = text.index("global_device_write_authority")
    live_probe = text.index('cbs250_targeted_help_probe.py --host')
    assert discovery_check < live_probe
    assert targeted_check < live_probe
    assert authority_check < live_probe


def test_live_targeted_workflow_uploads_only_sanitized_evidence() -> None:
    text = _workflow_text()
    assert 'cbs250_targeted_help_evidence_ingest.py' in text
    assert 'name: cbs250-targeted-l3-sanitized' in text
    assert 'cbs250-targeted-l3-sanitized.json' in text
    assert 'targeted_l3_help_transcript.txt' not in text
    assert 'retention-days: 7' in text
    assert 'Remove raw local evidence' in text
    assert 'if: always()' in text


def test_live_targeted_workflow_contains_no_mutation_cli() -> None:
    text = _workflow_text().lower()
    forbidden_cli = (
        'configure terminal',
        'write memory',
        'copy running-config startup-config',
        'copy running-config',
        'reload',
        'reboot',
        'clear logging',
        'delete ',
        'boot system',
        'shutdown',
        'no shutdown',
    )
    for phrase in forbidden_cli:
        assert phrase not in text, phrase
