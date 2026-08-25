#!/usr/bin/env python3
"""CBS250 CLI discovery v3.1.1 coverage-status correction wrapper.

This wrapper preserves the v3.1.0 transport/query safety implementation but corrects
coverage reporting: a run that reaches max_nodes or records discovery errors is never
reported as COMPLETE. Use this entry point for new runs until the legacy v3.1.0 module
is refactored.
"""
from __future__ import annotations

import cbs250_cli_discovery as legacy

TOOL_VERSION = "3.1.1"


def classify_coverage_status(*, nodes: int, max_nodes: int, error_count: int) -> str:
    """Return a truthful run/coverage status without granting any execution authority."""
    if nodes >= max_nodes:
        return "TRUNCATED_MAX_NODES"
    if error_count:
        return "INCOMPLETE_WITH_ERRORS"
    return "COMPLETE_WITHIN_DECLARED_SCOPE"


def _run_with_truthful_coverage(self):
    for command in sorted(legacy.READ_ONLY_EXEC_ALLOWLIST):
        try:
            self.inventory[command] = self.execute_read_only(command)
        except Exception as exc:
            self.errors.append({
                "mode": "inventory",
                "context_prefix": command,
                "shard": "",
                "query": command,
                "error_type": type(exc).__name__,
                "error": str(exc),
            })

    self.mode_trees["privileged_exec"] = self.crawl_mode("privileged_exec")
    if self.a.include_config_help:
        self.mode_trees["global_config"] = self.crawl_mode("global_config")

    max_nodes_reached = self.nodes >= self.a.max_nodes
    status = classify_coverage_status(
        nodes=self.nodes,
        max_nodes=self.a.max_nodes,
        error_count=len(self.errors),
    )
    document = self.build_document(status=status)
    document["tool_version"] = TOOL_VERSION
    document["scope"]["max_nodes_reached"] = max_nodes_reached
    document["scope"]["coverage_complete"] = status == "COMPLETE_WITHIN_DECLARED_SCOPE"
    document["scope"]["coverage_note"] = (
        "COMPLETE_WITHIN_DECLARED_SCOPE means the run finished without reaching max_nodes "
        "and without crawler errors. Finite max_depth, non-instantiated placeholders, and "
        "forbidden configuration submodes remain explicit discovery boundaries."
    )
    return document


legacy.VERSION = TOOL_VERSION
legacy.CBS250ReadOnlyCrawler.run = _run_with_truthful_coverage


if __name__ == "__main__":
    raise SystemExit(legacy.main())
