"""Hand-built plans for the tests.

IMPORTANT: these are NOT real `terraform show -json` output. They copy the shape that Terraform
produces for the example folders, so the script can be tested without Terraform or an AWS account.
Real plans are checked separately, by running the gate on terraform/insecure and terraform/secure.
"""

from __future__ import annotations

from typing import Any


def rc(address: str, rtype: str, after: dict[str, Any], unknown: dict[str, Any] | None = None) -> dict[str, Any]:
    """One entry of resource_changes."""
    return {
        "address": address,
        "type": rtype,
        "change": {"actions": ["create"], "after": after, "after_unknown": unknown or {}},
    }


def cfg(address: str, rtype: str, expressions: dict[str, Any]) -> dict[str, Any]:
    """One entry of configuration.root_module.resources."""
    return {"address": address, "type": rtype, "expressions": expressions}


def refs(*names: str) -> dict[str, Any]:
    """The 'references' form Terraform uses when a value points at another resource."""
    out = []
    for name in names:
        out += [f"{name}.id", name]
    return {"references": out}


def plan(changes: list[dict[str, Any]], config: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "format_version": "1.2",
        "terraform_version": "1.17.1",
        "resource_changes": changes,
        "configuration": {
            "provider_config": {"aws": {"expressions": {"region": {"constant_value": "us-east-1"}}}},
            "root_module": {"resources": config},
        },
    }


ALL_FOUR = {
    "block_public_acls": True,
    "block_public_policy": True,
    "ignore_public_acls": True,
    "restrict_public_buckets": True,
}


def admin_policy_text() -> str:
    return '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'


def narrow_policy_text() -> str:
    return (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],'
        '"Resource":["arn:aws:s3:::lg/*"]}]}'
    )


def secure_plan() -> dict[str, Any]:
    changes: list[dict[str, Any]] = []
    config: list[dict[str, Any]] = []
    for name in ("demo", "logs"):
        bucket = f"aws_s3_bucket.{name}"
        changes += [
            rc(bucket, "aws_s3_bucket", {"bucket": f"b-{name}"}),
            rc(f"aws_s3_bucket_public_access_block.{name}", "aws_s3_bucket_public_access_block", ALL_FOUR),
            rc(
                f"aws_s3_bucket_versioning.{name}",
                "aws_s3_bucket_versioning",
                {"versioning_configuration": [{"status": "Enabled"}]},
            ),
            rc(
                f"aws_s3_bucket_server_side_encryption_configuration.{name}",
                "aws_s3_bucket_server_side_encryption_configuration",
                {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]},
            ),
        ]
        for rtype in (
            "aws_s3_bucket_public_access_block",
            "aws_s3_bucket_versioning",
            "aws_s3_bucket_server_side_encryption_configuration",
        ):
            config.append(cfg(f"{rtype}.{name}", rtype, {"bucket": refs(bucket)}))
    changes.append(rc("aws_s3_bucket_logging.demo", "aws_s3_bucket_logging", {"target_prefix": "x/"}))
    config.append(
        cfg(
            "aws_s3_bucket_logging.demo",
            "aws_s3_bucket_logging",
            {"bucket": refs("aws_s3_bucket.demo"), "target_bucket": refs("aws_s3_bucket.logs")},
        )
    )
    changes += [
        rc("aws_vpc.main", "aws_vpc", {"cidr_block": "10.0.0.0/16"}),
        rc("aws_flow_log.main", "aws_flow_log", {"traffic_type": "ALL"}),
        rc(
            "aws_kms_key.trail",
            "aws_kms_key",
            {"enable_key_rotation": True, "customer_master_key_spec": "SYMMETRIC_DEFAULT", "is_enabled": True},
        ),
        rc(
            "aws_cloudtrail.main",
            "aws_cloudtrail",
            {"is_multi_region_trail": True, "enable_logging": True, "enable_log_file_validation": True},
            {"kms_key_id": True},
        ),
        rc("aws_iam_policy.read_logs", "aws_iam_policy", {"policy": narrow_policy_text()}),
        rc(
            "aws_security_group.web",
            "aws_security_group",
            {
                "ingress": [
                    {
                        "from_port": 443,
                        "to_port": 443,
                        "protocol": "tcp",
                        "cidr_blocks": ["0.0.0.0/0"],
                        "ipv6_cidr_blocks": [],
                    },
                    {
                        "from_port": 22,
                        "to_port": 22,
                        "protocol": "tcp",
                        "cidr_blocks": ["10.0.0.0/8"],
                        "ipv6_cidr_blocks": [],
                    },
                ]
            },
        ),
    ]
    config += [
        cfg("aws_flow_log.main", "aws_flow_log", {"vpc_id": refs("aws_vpc.main")}),
        cfg(
            "aws_cloudtrail.main",
            "aws_cloudtrail",
            {"kms_key_id": {"references": ["aws_kms_key.trail.arn", "aws_kms_key.trail"]}},
        ),
    ]
    return plan(changes, config)


def insecure_plan() -> dict[str, Any]:
    open_world = {
        "from_port": 22,
        "to_port": 22,
        "protocol": "tcp",
        "cidr_blocks": ["0.0.0.0/0"],
        "ipv6_cidr_blocks": [],
    }
    rdp_world = {**open_world, "from_port": 3389, "to_port": 3389}
    changes = [
        rc("aws_s3_bucket.demo", "aws_s3_bucket", {"bucket": "b-demo"}),
        rc("aws_security_group.ssh_inline", "aws_security_group", {"ingress": [open_world]}),
        rc("aws_security_group.ssh_modern", "aws_security_group", {"ingress": []}),
        rc(
            "aws_vpc_security_group_ingress_rule.ssh_modern",
            "aws_vpc_security_group_ingress_rule",
            {"from_port": 22, "to_port": 22, "ip_protocol": "tcp", "cidr_ipv4": "0.0.0.0/0", "cidr_ipv6": None},
        ),
        rc("aws_security_group.ssh_old", "aws_security_group", {"ingress": []}),
        rc(
            "aws_security_group_rule.ssh_old",
            "aws_security_group_rule",
            {
                "type": "ingress",
                "from_port": 22,
                "to_port": 22,
                "protocol": "tcp",
                "cidr_blocks": ["0.0.0.0/0"],
                "ipv6_cidr_blocks": None,
            },
        ),
        rc("aws_security_group.rdp_inline", "aws_security_group", {"ingress": [rdp_world]}),
        rc("aws_vpc.main", "aws_vpc", {"cidr_block": "10.0.0.0/16"}),
        rc(
            "aws_kms_key.no_rotation",
            "aws_kms_key",
            {"enable_key_rotation": False, "customer_master_key_spec": "SYMMETRIC_DEFAULT", "is_enabled": True},
        ),
        rc(
            "aws_cloudtrail.weak",
            "aws_cloudtrail",
            {
                "is_multi_region_trail": False,
                "enable_logging": True,
                "enable_log_file_validation": False,
                "kms_key_id": None,
            },
        ),
        rc("aws_iam_policy.admin", "aws_iam_policy", {"policy": admin_policy_text()}),
    ]
    return plan(changes, [])
