#!/usr/bin/env python3
"""terraform-policy-gate: judge a Terraform plan with the OPA rules and write evidence.

What it does, in order:
  1. Reads the plan (plan.json, made with `terraform show -json tfplan`).
  2. For each of the 12 rules, asks OPA two questions: which resources did the rule judge
     (`scope`) and which of them broke it (`deny`).
  3. Writes one evidence record per judged resource (PASS or FAIL), plus NOT_APPLICABLE records
     for resources of the right type that the rule deliberately skipped.
  4. Optionally asks Checkov for a second opinion and notes where the two engines disagree.
  5. Writes report.md, report.html and summary.json, and exits 1 if anything failed.

Only the standard library is used, so there is nothing to install besides OPA (and Checkov, if wanted).
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
DEFAULT_RULES = HERE / "rules.json"
DEFAULT_POLICIES = HERE.parent / "policies"

# Every deny message starts like "S3-07: aws_s3_bucket.demo needs ...".
DENY_PATTERN = re.compile(r"^(?P<rule>[A-Z0-9]+-\d+): (?P<address>\S+) (?P<text>.*)$")

PASS, FAIL, ERROR, NOT_APPLICABLE = "PASS", "FAIL", "ERROR", "NOT_APPLICABLE"


# ---------------------------------------------------------------- reading the plan


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))  # utf-8-sig also accepts a BOM


def plan_resources(plan: dict[str, Any]) -> dict[str, str]:
    """Address -> type for every resource the plan creates or changes (deletions are ignored)."""
    found: dict[str, str] = {}
    for item in plan.get("resource_changes", []):
        if item.get("change", {}).get("actions") == ["delete"]:
            continue
        found[item["address"]] = item["type"]
    return found


def plan_region(plan: dict[str, Any]) -> str | None:
    """The AWS region written in the provider block, if it is a plain value."""
    try:
        region = plan["configuration"]["provider_config"]["aws"]["expressions"]["region"]
        return region.get("constant_value")
    except (KeyError, TypeError):
        return None


# ---------------------------------------------------------------- asking OPA


def run_opa(opa: str, policies: Path, plan_path: Path, package: str) -> dict[str, list[str]]:
    """Return {"deny": [...messages], "scope": [...addresses]} for one rule package."""
    command = [
        opa, "eval", "--format", "json",
        "--data", str(policies), "--input", str(plan_path), f"data.{package}",
    ]  # fmt: skip
    done = subprocess.run(command, capture_output=True, text=True, check=False)
    if done.returncode != 0:
        raise RuntimeError(done.stderr.strip() or done.stdout.strip() or "opa failed")
    output = json.loads(done.stdout)
    results = output.get("result")
    if not results:  # the package produced nothing at all
        return {"deny": [], "scope": []}
    value = results[0]["expressions"][0]["value"]
    return {"deny": sorted(value.get("deny", [])), "scope": sorted(value.get("scope", []))}


def parse_deny(message: str) -> tuple[str, str]:
    """Split a deny message into (address, text). Unknown formats keep the whole text."""
    match = DENY_PATTERN.match(message)
    if match:
        return match.group("address"), match.group("text")
    return "(unknown resource)", message


# ---------------------------------------------------------------- Checkov second opinion


def parse_checkov(output: Any) -> dict[tuple[str, str], str]:
    """Turn Checkov's JSON into {(check_id, resource_address): "PASSED" or "FAILED"}."""
    blocks = output if isinstance(output, list) else [output]
    found: dict[tuple[str, str], str] = {}
    for block in blocks:
        results = block.get("results", {}) if isinstance(block, dict) else {}
        for key, label in (("passed_checks", "PASSED"), ("failed_checks", "FAILED")):
            for item in results.get(key, []):
                found[(item["check_id"], item["resource"])] = label
    return found


def checkov_command(name: str) -> list[str]:
    """How to start Checkov. shutil.which honours Windows PATHEXT (checkov.cmd); otherwise ask Python to run it."""
    found = shutil.which(name)
    if found:
        return [found]
    if name == "checkov":
        return [sys.executable, "-m", "checkov.main"]
    return [name]


def run_checkov(checkov: str, target: Path, check_ids: list[str]) -> dict[tuple[str, str], str]:
    """Run Checkov on a plan file (default) or on a folder of .tf files, for the given checks only."""
    if target.is_dir():
        scan = ["-d", str(target), "--framework", "terraform"]
    else:
        scan = ["-f", str(target), "--framework", "terraform_plan"]
    options = ["--check", ",".join(check_ids), "--output", "json", "--soft-fail", "--skip-download"]
    command = [*checkov_command(checkov), *scan, *options]
    done = subprocess.run(command, capture_output=True, text=True, check=False)
    try:
        return parse_checkov(json.loads(done.stdout))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Checkov gave no JSON: {done.stderr.strip()[:300]}") from exc


# ---------------------------------------------------------------- building records


def make_record(
    rule: dict[str, Any],
    status: str,
    resource: str,
    resource_type: str | None,
    evidence: dict[str, Any],
    source: dict[str, Any],
    timestamp: str,
) -> dict[str, Any]:
    return {
        "check_id": rule["id"],
        "title": rule["title"],
        "status": status,
        "resource": resource,
        "resource_type": resource_type,
        "timestamp": timestamp,
        "controls": {
            "cis": rule["cis"],
            "nist_800_53_r5": rule["nist"],
            "iso_27001_2022": rule["iso"],
            "soc2": rule["soc2"],
        },
        "evidence": evidence,
        "remediation": rule["remediation"],
        "source": source,
    }


def records_for_rule(
    rule: dict[str, Any],
    opa_result: dict[str, list[str]],
    resources: dict[str, str],
    source: dict[str, Any],
    timestamp: str,
) -> list[dict[str, Any]]:
    """One record per judged resource, plus a NOT_APPLICABLE record for each skipped one."""
    failures: dict[str, list[str]] = {}
    for message in opa_result["deny"]:
        address, text = parse_deny(message)
        failures.setdefault(address, []).append(text)

    scope = set(opa_result["scope"])
    judged = sorted(scope | set(failures))  # a failure is never dropped, even if it is outside scope
    policy = {"engine": "opa", "policy": f"policies/{rule['package']}.rego"}
    records = []
    for address in judged:
        rtype = resources.get(address)
        if address in failures:
            evidence = {**policy, "problems": failures[address]}
            records.append(make_record(rule, FAIL, address, rtype, evidence, source, timestamp))
        else:
            records.append(make_record(rule, PASS, address, rtype, dict(policy), source, timestamp))

    for address, rtype in sorted(resources.items()):
        if rtype in rule["types"] and address not in judged:
            evidence = {**policy, "reason": rule.get("not_applicable_reason", "Not judged by this rule.")}
            records.append(make_record(rule, NOT_APPLICABLE, address, rtype, evidence, source, timestamp))

    if not records:  # the plan has nothing this rule looks at; say so, so the rule still shows up
        evidence = {**policy, "reason": "The plan declares no resources of the kinds this rule judges."}
        records.append(make_record(rule, NOT_APPLICABLE, "(whole plan)", None, evidence, source, timestamp))
    return records


def error_record(rule: dict[str, Any], message: str, source: dict[str, Any], timestamp: str) -> dict[str, Any]:
    """A rule that could not run is an ERROR, never a PASS."""
    return make_record(rule, ERROR, "(rule could not run)", None, {"error": message[:500]}, source, timestamp)


def add_cross_check(
    rule: dict[str, Any], records: list[dict[str, Any]], checkov: dict[tuple[str, str], str]
) -> list[dict[str, Any]]:
    """Attach Checkov's verdict to each record, and return the disagreements."""
    disagreements = []
    for record in records:
        if record["status"] not in (PASS, FAIL):
            continue
        for check_id in rule["checkov"]:
            verdict = checkov.get((check_id, record["resource"]))
            if verdict is None:
                continue
            record["evidence"]["checkov"] = {
                "check_id": check_id,
                "result": verdict,
                "relation": rule["checkov_relation"],
            }
            agree = (record["status"] == PASS) == (verdict == "PASSED")
            if not agree:
                disagreements.append(
                    {
                        "check_id": rule["id"],
                        "resource": record["resource"],
                        "opa": record["status"],
                        "checkov": f"{check_id} {verdict}",
                        "note": rule["checkov_note"],
                    }
                )
    return disagreements


# ---------------------------------------------------------------- summary and reports


def summarize(records: list[dict[str, Any]], rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for rule in rules:
        mine = [r for r in records if r["check_id"] == rule["id"]]
        counts = Counter(r["status"] for r in mine)
        if counts[ERROR]:
            verdict = ERROR
        elif counts[FAIL]:
            verdict = FAIL
        elif counts[PASS]:
            verdict = PASS
        else:
            verdict = NOT_APPLICABLE
        rows.append(
            {
                "check_id": rule["id"],
                "title": rule["title"],
                "verdict": verdict,
                "pass": counts[PASS],
                "fail": counts[FAIL],
                "error": counts[ERROR],
                "not_applicable": counts[NOT_APPLICABLE],
            }
        )
    return rows


def markdown_report(
    meta: dict[str, Any], rows: list[dict[str, Any]], records: list[dict[str, Any]], disagreements: list[dict[str, Any]]
) -> str:
    lines = [
        "# Terraform policy gate report",
        "",
        f"- Plan: `{meta['plan_file']}` (sha256 `{meta['plan_sha256'][:12]}`)",
        f"- Terraform version in the plan: {meta['terraform_version'] or 'unknown'}",
        f"- Run at: {meta['timestamp']}",
        f"- Result: **{meta['result']}** ({meta['failed']} failing resources)",
        "",
        "| Rule | Verdict | Pass | Fail | Not applicable | Title |",
        "|------|---------|------|------|----------------|-------|",
    ]
    for row in rows:
        lines.append(
            f"| {row['check_id']} | {row['verdict']} | {row['pass']} | {row['fail']} | "
            f"{row['not_applicable']} | {row['title']} |"
        )
    failing = [r for r in records if r["status"] in (FAIL, ERROR)]
    if failing:
        lines += ["", "## Findings", ""]
        for r in failing:
            problem = "; ".join(r["evidence"].get("problems", [r["evidence"].get("error", "")]))
            lines.append(f"- **{r['check_id']}** `{r['resource']}`: {problem}. Fix: {r['remediation']}")
    if disagreements:
        lines += ["", "## Where Checkov and the OPA rules disagree", ""]
        for d in disagreements:
            lines.append(
                f"- **{d['check_id']}** `{d['resource']}`: OPA says {d['opa']}, "
                f"Checkov says {d['checkov']}. {d['note']}"
            )
    lines.append("")
    return "\n".join(lines)


def html_report(
    meta: dict[str, Any], rows: list[dict[str, Any]], records: list[dict[str, Any]], disagreements: list[dict[str, Any]]
) -> str:
    e = html.escape
    colors = {PASS: "#1a7f37", FAIL: "#cf222e", ERROR: "#9a6700", NOT_APPLICABLE: "#6e7781"}

    def badge(status: str) -> str:
        return f'<span class="b" style="background:{colors[status]}">{e(status)}</span>'

    table = "".join(
        f"<tr><td>{e(r['check_id'])}</td><td>{badge(r['verdict'])}</td><td>{r['pass']}</td>"
        f"<td>{r['fail']}</td><td>{r['not_applicable']}</td><td>{e(r['title'])}</td></tr>"
        for r in rows
    )
    findings = "".join(
        f"<li><b>{e(r['check_id'])}</b> <code>{e(r['resource'])}</code>: "
        f"{e('; '.join(r['evidence'].get('problems', [r['evidence'].get('error', '')])))}. "
        f"<i>Fix: {e(r['remediation'])}</i></li>"
        for r in records
        if r["status"] in (FAIL, ERROR)
    )
    diffs = "".join(
        f"<li><b>{e(d['check_id'])}</b> <code>{e(d['resource'])}</code>: OPA says {e(d['opa'])}, "
        f"Checkov says {e(d['checkov'])}. {e(d['note'])}</li>"
        for d in disagreements
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Terraform policy gate report</title>
<style>
body{{font:15px/1.5 system-ui,sans-serif;max-width:980px;margin:2rem auto;padding:0 1rem;color:#1f2328}}
table{{border-collapse:collapse;width:100%}}
th,td{{border-bottom:1px solid #d0d7de;padding:.45rem .6rem;text-align:left}}
th{{background:#f6f8fa}} .b{{color:#fff;border-radius:4px;padding:.1rem .5rem;font-size:.8rem}}
code{{background:#f6f8fa;padding:.1rem .3rem;border-radius:4px}} .meta{{color:#57606a}}
</style></head><body>
<h1>Terraform policy gate report</h1>
<p class="meta">Plan <code>{e(meta["plan_file"])}</code> (sha256 {e(meta["plan_sha256"][:12])}) &middot;
Terraform {e(str(meta["terraform_version"] or "unknown"))} &middot; {e(meta["timestamp"])}</p>
<h2>Result: {badge(meta["result"])} &nbsp;{meta["failed"]} failing resources</h2>
<table><tr><th>Rule</th><th>Verdict</th><th>Pass</th><th>Fail</th><th>N/A</th><th>Title</th></tr>{table}</table>
{"<h2>Findings</h2><ul>" + findings + "</ul>" if findings else ""}
{"<h2>Where Checkov and the OPA rules disagree</h2><ul>" + diffs + "</ul>" if diffs else ""}
</body></html>
"""


# ---------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Judge a Terraform plan with the OPA policy gate.")
    parser.add_argument("--plan", required=True, type=Path, help="plan.json from `terraform show -json`")
    parser.add_argument("--policies", type=Path, default=DEFAULT_POLICIES, help="folder with the .rego files")
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="rules.json (titles and mappings)")
    parser.add_argument("--output", type=Path, default=Path("evidence"), help="folder for evidence runs")
    parser.add_argument("--opa", default="opa", help="path to the opa program")
    parser.add_argument(
        "--checkov",
        nargs="?",
        const="checkov",
        default=None,
        help="also ask Checkov for a second opinion (optionally give its path)",
    )
    parser.add_argument(
        "--checkov-target",
        type=Path,
        default=None,
        help="give Checkov this plan file or folder of .tf files (default: the plan)",
    )
    parser.add_argument("--only", action="append", help="run only this rule id (can repeat)")
    args = parser.parse_args(argv)

    plan = load_json(args.plan)
    rules = load_json(args.rules)["rules"]
    if args.only:
        rules = [r for r in rules if r["id"] in set(args.only)]

    now = datetime.now(UTC)
    timestamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    source = {
        "type": "terraform_plan",
        "plan_file": args.plan.name,
        "plan_sha256": hashlib.sha256(args.plan.read_bytes()).hexdigest(),
        "terraform_version": plan.get("terraform_version"),
        "region": plan_region(plan),
    }
    resources = plan_resources(plan)

    checkov: dict[tuple[str, str], str] = {}
    if args.checkov:
        ids = sorted({cid for r in rules for cid in r["checkov"]})
        try:
            checkov = run_checkov(args.checkov, args.checkov_target or args.plan, ids)
        except (OSError, RuntimeError) as exc:
            print(f"warning: Checkov second opinion skipped ({exc})", file=sys.stderr)

    all_records: list[dict[str, Any]] = []
    disagreements: list[dict[str, Any]] = []
    for rule in rules:
        try:
            result = run_opa(args.opa, args.policies, args.plan, rule["package"])
            records = records_for_rule(rule, result, resources, source, timestamp)
        except (OSError, RuntimeError, json.JSONDecodeError) as exc:
            records = [error_record(rule, str(exc), source, timestamp)]
        if checkov:
            disagreements += add_cross_check(rule, records, checkov)
        all_records += records

    rows = summarize(all_records, rules)
    failed = sum(1 for r in all_records if r["status"] in (FAIL, ERROR))
    meta = {
        "plan_file": args.plan.name,
        "plan_sha256": source["plan_sha256"],
        "terraform_version": source["terraform_version"],
        "timestamp": timestamp,
        "failed": failed,
        "result": "FAIL" if failed else "PASS",
    }

    run_dir = args.output / now.strftime("%Y-%m-%dT%H-%M-%SZ")
    run_dir.mkdir(parents=True, exist_ok=False)
    for rule in rules:
        mine = [r for r in all_records if r["check_id"] == rule["id"]]
        (run_dir / f"{rule['id']}.json").write_text(json.dumps(mine, indent=2) + "\n", encoding="utf-8")
    (run_dir / "summary.json").write_text(
        json.dumps({**meta, "rules": rows, "disagreements": disagreements}, indent=2) + "\n", encoding="utf-8"
    )
    (run_dir / "report.md").write_text(markdown_report(meta, rows, all_records, disagreements), encoding="utf-8")
    (run_dir / "report.html").write_text(html_report(meta, rows, all_records, disagreements), encoding="utf-8")

    for row in rows:
        print(
            f"{row['check_id']:7} {row['verdict']:15} pass={row['pass']} fail={row['fail']} n/a={row['not_applicable']}"
        )
    print(f"\nResult: {meta['result']} ({failed} failing resources). Evidence written to {run_dir}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
