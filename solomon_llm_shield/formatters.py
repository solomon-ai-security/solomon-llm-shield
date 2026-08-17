from __future__ import annotations
from typing import *
import re, json, logging, ast, math, hmac, hashlib, sqlite3, time, uuid, asyncio, io
from datetime import datetime, timezone
from html import escape as html_escape
from xml.etree import ElementTree as ET
from enum import Enum
from dataclasses import dataclass, field, asdict


#  FORMATTERS 
# ===========================================================================

def _format_text(issues, metrics, skipped, verbose=False):
    bits = [f"Run started:{datetime.now(timezone.utc)}", "\nTest results:"]
    if not issues:
        bits.append("\tNo issues identified.")
    else:
        for issue in issues:
            bits.append(f">> Issue: [{issue.test_id}:{issue.test}] {issue.text}")
            bits.append(f"   Severity: {issue.severity.capitalize()}   Confidence: {issue.confidence.capitalize()}")
            bits.append(f"   CWE: {str(issue.cwe)}")
            bits.append(f"   Location: {issue.fname}:{issue.lineno}")
            bits.append("-" * 50)
    bits.append("\nCode scanned:")
    bits.append(f"\tTotal lines of code: {metrics.data['_totals']['loc']}")
    bits.append(f"\tTotal lines skipped (#nosec): {metrics.data['_totals']['nosec']}")
    bits.append(f"\tTotal potential issues skipped: {metrics.data['_totals']['skipped_tests']}")
    if skipped:
        bits.append(f"Files skipped ({len(skipped)}):")
        for fname, reason in skipped:
            bits.append(f"\t{fname} ({reason})")
    return "\n".join(bits) + "\n"

def _format_json(issues, metrics, skipped):
    out = {"results": [], "errors": []}
    for fname, reason in skipped:
        out["errors"].append({"filename": fname, "reason": reason})
    for issue in issues:
        out["results"].append(issue.as_dict(with_code=False))
    out["metrics"] = metrics.data
    out["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return json.dumps(out, sort_keys=True, indent=2, separators=(",", ": "))

def _format_csv(issues, metrics, skipped):
    import csv as _csv
    output = io.StringIO()
    fieldnames = ["filename", "test_name", "test_id", "issue_severity", "issue_confidence", "issue_cwe", "issue_text", "line_number", "line_range"]
    writer = _csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for issue in issues:
        r = issue.as_dict(with_code=False)
        r["issue_cwe"] = issue.cwe.link()
        writer.writerow(r)
    return output.getvalue()

def _format_html(issues, metrics, skipped):
    results_str = ""
    for i, issue in enumerate(issues):
        results_str += f'\n<div id="issue-{i}">\n<div class="issue-block issue-sev-{issue.severity.lower()}">\n    <b>{issue.test}: </b> {html_escape(issue.text)}<br>\n    <b>Test ID:</b> {issue.test_id}<br>\n    <b>Severity: </b>{issue.severity}<br>\n    <b>Confidence: </b>{issue.confidence}<br>\n    <b>CWE: </b><a href="{issue.cwe.link()}" target="_blank">CWE-{issue.cwe.id}</a><br>\n    <b>File: </b>{html_escape(issue.fname)}<br>\n    <b>Line number: </b>{issue.lineno}<br>\n</div>\n</div>'
    return f'<!DOCTYPE html>\n<html><head><meta charset="UTF-8"><title>LLM Output Guard Report</title>\n<style>\n.issue-block {{ border: 1px solid LightGray; padding: .5em; margin-bottom: .5em; }}\n.issue-sev-high {{ background-color: Pink; }}\n.issue-sev-medium {{ background-color: NavajoWhite; }}\n.issue-sev-low {{ background-color: LightCyan; }}\n</style></head><body>\n<div id="metrics"><b>Metrics:</b><br>\nTotal lines of code: {metrics.data["_totals"]["loc"]}<br>\nTotal lines skipped (#nosec): {metrics.data["_totals"]["nosec"]}<br>\n</div>\n<br><div id="results">{results_str}</div>\n</body></html>'

def _format_xml(issues, metrics, skipped):
    root = ET.Element("testsuite", name="llm_output_guard", tests=str(len(issues)))
    for issue in issues:
        testcase = ET.SubElement(root, "testcase", classname=issue.fname, name=issue.test)
        text = f"Test ID: {issue.test_id} Severity: {issue.severity} Confidence: {issue.confidence}\n{issue.text}\nLocation {issue.fname}:{issue.lineno}"
        ET.SubElement(testcase, "error", type=issue.severity, message=issue.text).text = text
    return ET.tostring(root, encoding="unicode")

def _format_sarif(issues, metrics, skipped):
    results = []
    rules = {}
    rule_indices = {}
    for issue in issues:
        rule_id = issue.test_id
        if rule_id not in rules:
            rules[rule_id] = {"id": rule_id, "name": issue.test, "properties": {"tags": ["security", f"external/cwe/cwe-{issue.cwe.id}"]}}
            rule_indices[rule_id] = len(rules) - 1
        results.append({"ruleId": rule_id, "ruleIndex": rule_indices[rule_id], "message": {"text": issue.text}, "level": "error" if issue.severity == "HIGH" else ("warning" if issue.severity == "MEDIUM" else "note"), "locations": [{"physicalLocation": {"artifactLocation": {"uri": issue.fname}, "region": {"startLine": issue.lineno or 0}}}], "properties": {"issue_confidence": issue.confidence, "issue_severity": issue.severity}})
    log = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "LLMOutputGuard", "version": "2.0.0", "rules": list(rules.values())}}, "results": results}]}
    return json.dumps(log, indent=2)

_FORMATTERS = {"text": _format_text, "txt": _format_text, "json": _format_json, "csv": _format_csv, "html": _format_html, "xml": _format_xml, "sarif": _format_sarif}



