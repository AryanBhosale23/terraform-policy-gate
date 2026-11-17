"""Tests for scripts/policy_gate.py. The end-to-end tests need the `opa` program and skip without it."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import plan_fixtures as fx  # noqa: E402
import policy_gate as gate  # noqa: E402

RULES = json.loads((ROOT / "scripts" / "rules.json").read_text(encoding="utf-8"))["rules"]
RULE = next(r for r in RULES if r["id"] == "S3-10")
SOURCE = {"type": "terraform_plan"}
NOW = "2026-01-01T00:00:00Z"


def test_rules_file_has_the_twelve_rules_with_every_mapping():
    ids = [r["id"] for r in RULES]
    assert ids == ["S3-07", "S3-08", "S3-09", "S3-10", "VPC-15", "VPC-17", "VPC-18",
                   "CT-11", "CT-12", "CT-13", "KMS-19", "IAM-06"]  # fmt: skip
    for rule in RULES:
        for key in ("title", "package", "types", "cis", "nist", "iso", "soc2", "remediation", "checkov"):
            assert rule[key], f"{rule['id']} is missing {key}"


def test_every_rule_has_a_rego_file_and_a_test_file():
    for rule in RULES:
        assert (ROOT / "policies" / f"{rule['package']}.rego").exists()
        assert (ROOT / "policies" / f"{rule['package']}_test.rego").exists()


def test_parse_deny_splits_address_and_text():
    address, text = gate.parse_deny("S3-07: aws_s3_bucket.demo needs a public access block")
    assert address == "aws_s3_bucket.demo"
    assert text == "needs a public access block"


def test_parse_deny_keeps_unknown_formats():
    address, text = gate.parse_deny("something unexpected")
    assert address == "(unknown resource)"
    assert text == "something unexpected"


def test_records_pass_fail_and_not_applicable():
    resources = {
        "aws_s3_bucket.a": "aws_s3_bucket",
        "aws_s3_bucket.b": "aws_s3_bucket",
        "aws_s3_bucket.logs": "aws_s3_bucket",
    }
    result = {"deny": ["S3-10: aws_s3_bucket.b needs access logging"], "scope": ["aws_s3_bucket.a", "aws_s3_bucket.b"]}
    records = gate.records_for_rule(RULE, result, resources, SOURCE, NOW)
    status = {r["resource"]: r["status"] for r in records}
    assert status == {
        "aws_s3_bucket.a": "PASS",
        "aws_s3_bucket.b": "FAIL",
        "aws_s3_bucket.logs": "NOT_APPLICABLE",
    }
    failing = next(r for r in records if r["status"] == "FAIL")
    assert failing["evidence"]["problems"] == ["needs access logging"]
    assert failing["controls"]["nist_800_53_r5"] == "AU-12"


def test_a_failure_outside_scope_is_never_dropped():
    result = {"deny": ["S3-10: aws_s3_bucket.x needs access logging"], "scope": []}
    records = gate.records_for_rule(RULE, result, {}, SOURCE, NOW)
    assert [(r["resource"], r["status"]) for r in records] == [("aws_s3_bucket.x", "FAIL")]


def test_a_rule_with_nothing_to_judge_still_appears():
    records = gate.records_for_rule(RULE, {"deny": [], "scope": []}, {}, SOURCE, NOW)
    assert [(r["resource"], r["status"]) for r in records] == [("(whole plan)", "NOT_APPLICABLE")]


def test_a_rule_that_cannot_run_is_an_error_never_a_pass():
    record = gate.error_record(RULE, "opa exploded", SOURCE, NOW)
    assert record["status"] == "ERROR"
    rows = gate.summarize([record], [RULE])
    assert rows[0]["verdict"] == "ERROR"


def test_summary_verdict_order_is_error_then_fail_then_pass():
    def rec(status: str) -> dict:
        return {"check_id": "S3-10", "status": status}

    assert gate.summarize([rec("PASS"), rec("FAIL")], [RULE])[0]["verdict"] == "FAIL"
    assert gate.summarize([rec("PASS")], [RULE])[0]["verdict"] == "PASS"
    assert gate.summarize([rec("NOT_APPLICABLE")], [RULE])[0]["verdict"] == "NOT_APPLICABLE"


def test_parse_checkov_reads_both_result_lists_and_both_shapes():
    one = {"results": {"passed_checks": [{"check_id": "CKV_AWS_21", "resource": "aws_s3_bucket.a"}],
                       "failed_checks": [{"check_id": "CKV_AWS_21", "resource": "aws_s3_bucket.b"}]}}  # fmt: skip
    expected = {("CKV_AWS_21", "aws_s3_bucket.a"): "PASSED", ("CKV_AWS_21", "aws_s3_bucket.b"): "FAILED"}
    assert gate.parse_checkov(one) == expected
    assert gate.parse_checkov([one]) == expected


def test_cross_check_reports_disagreement_and_agreement():
    rule = next(r for r in RULES if r["id"] == "S3-08")
    records = [
        {"status": "PASS", "resource": "aws_s3_bucket.a", "evidence": {}},
        {"status": "PASS", "resource": "aws_s3_bucket.b", "evidence": {}},
    ]
    checkov = {("CKV_AWS_145", "aws_s3_bucket.a"): "FAILED", ("CKV_AWS_145", "aws_s3_bucket.b"): "PASSED"}
    disagreements = gate.add_cross_check(rule, records, checkov)
    assert [d["resource"] for d in disagreements] == ["aws_s3_bucket.a"]
    assert records[0]["evidence"]["checkov"]["result"] == "FAILED"
    assert records[1]["evidence"]["checkov"]["result"] == "PASSED"


# ---------------------------------------------------------------- end to end (needs opa)

needs_opa = pytest.mark.skipif(shutil.which("opa") is None, reason="opa is not installed")


def run_gate(tmp_path: Path, plan: dict, name: str) -> tuple[int, Path]:
    plan_path = tmp_path / f"{name}.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    out = tmp_path / f"evidence-{name}"
    code = gate.main(["--plan", str(plan_path), "--policies", str(ROOT / "policies"), "--output", str(out)])
    run_dir = next(out.iterdir())
    return code, run_dir


@needs_opa
def test_secure_plan_passes_every_rule(tmp_path):
    code, run_dir = run_gate(tmp_path, fx.secure_plan(), "secure")
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert code == 0
    assert summary["result"] == "PASS"
    assert [r["verdict"] for r in summary["rules"]] == ["PASS"] * 12
    # the log bucket is exempt from S3-10, and the evidence says so
    s3_10 = json.loads((run_dir / "S3-10.json").read_text(encoding="utf-8"))
    assert {r["resource"]: r["status"] for r in s3_10} == {
        "aws_s3_bucket.demo": "PASS",
        "aws_s3_bucket.logs": "NOT_APPLICABLE",
    }


@needs_opa
def test_insecure_plan_fails_every_rule(tmp_path):
    code, run_dir = run_gate(tmp_path, fx.insecure_plan(), "insecure")
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert code == 1
    assert [r["verdict"] for r in summary["rules"]] == ["FAIL"] * 12
    fails = {r["check_id"]: r["fail"] for r in summary["rules"]}
    assert fails["VPC-17"] == 3  # inline, modern and old rule forms
    assert summary["failed"] == 14
    assert (run_dir / "report.html").read_text(encoding="utf-8").startswith("<!doctype html>")


@needs_opa
def test_a_broken_policy_folder_gives_errors_not_passes(tmp_path):
    empty = tmp_path / "no_policies"
    empty.mkdir()
    (empty / "bad.rego").write_text("package bad\nthis is not rego", encoding="utf-8")
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(fx.secure_plan()), encoding="utf-8")
    code = gate.main(["--plan", str(plan_path), "--policies", str(empty), "--output", str(tmp_path / "out")])
    assert code == 1
    run_dir = next((tmp_path / "out").iterdir())
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert {r["verdict"] for r in summary["rules"]} == {"ERROR"}


def test_checkov_command_uses_the_path_lookup(monkeypatch):
    # shutil.which finds checkov.cmd on Windows, where a bare "checkov" would not start.
    monkeypatch.setattr(gate.shutil, "which", lambda name: r"C:\venv\Scripts\checkov.CMD")
    assert gate.checkov_command("checkov") == [r"C:\venv\Scripts\checkov.CMD"]


def test_checkov_command_falls_back_to_python_module(monkeypatch):
    monkeypatch.setattr(gate.shutil, "which", lambda name: None)
    assert gate.checkov_command("checkov") == [sys.executable, "-m", "checkov.main"]
    assert gate.checkov_command("my-checkov") == ["my-checkov"]
