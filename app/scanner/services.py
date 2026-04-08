from __future__ import annotations

import json
import logging

from botocore.exceptions import BotoCoreError, ClientError

from app.scanner.aws_client import build_client
from app.services.scoring import cvss_like_score, score_to_severity
from app.services.schemas import FindingCreate

logger = logging.getLogger(__name__)


def scan_s3_public_access() -> list[FindingCreate]:
    client = build_client("s3")
    findings: list[FindingCreate] = []

    try:
        buckets = client.list_buckets().get("Buckets", [])
    except (ClientError, BotoCoreError) as exc:
        logger.error("Unable to list S3 buckets: %s", exc)
        return findings

    for bucket in buckets:
        bucket_name = bucket["Name"]
        try:
            acl = client.get_bucket_acl(Bucket=bucket_name)
            grants = acl.get("Grants", [])
            public_grant = any(
                g.get("Grantee", {}).get("URI", "").endswith("AllUsers")
                for g in grants
            )
            if public_grant:
                score = cvss_like_score(exploitability=8.8, impact=7.5)
                findings.append(
                    FindingCreate(
                        resource_type="S3",
                        resource_id=bucket_name,
                        issue="Bucket ACL allows public access",
                        severity=score_to_severity(score),
                        score=score,
                        details=json.dumps({"grants": grants}, default=str),
                    )
                )
        except (ClientError, BotoCoreError) as exc:
            logger.warning("Unable to inspect ACL for bucket %s: %s", bucket_name, exc)

    return findings


def scan_iam_policies() -> list[FindingCreate]:
    client = build_client("iam")
    findings: list[FindingCreate] = []

    try:
        roles = client.list_roles().get("Roles", [])
    except (ClientError, BotoCoreError) as exc:
        logger.error("Unable to list IAM roles: %s", exc)
        return findings

    for role in roles:
        role_name = role["RoleName"]
        for policy in role.get("AssumeRolePolicyDocument", {}).get("Statement", []):
            principal = policy.get("Principal", "")
            if principal == "*" or principal == {"AWS": "*"}:
                score = cvss_like_score(exploitability=8.0, impact=8.0)
                findings.append(
                    FindingCreate(
                        resource_type="IAM",
                        resource_id=role_name,
                        issue="Role trust policy allows wildcard principal",
                        severity=score_to_severity(score),
                        score=score,
                        details=json.dumps(policy, default=str),
                    )
                )

        attached = client.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
        for ap in attached:
            if "AdministratorAccess" in ap.get("PolicyName", ""):
                score = cvss_like_score(exploitability=7.8, impact=9.8)
                findings.append(
                    FindingCreate(
                        resource_type="IAM",
                        resource_id=role_name,
                        issue="Role has AdministratorAccess policy",
                        severity=score_to_severity(score),
                        score=score,
                        details=json.dumps(ap, default=str),
                    )
                )

    return findings


def scan_ec2_security_groups() -> list[FindingCreate]:
    client = build_client("ec2")
    findings: list[FindingCreate] = []

    try:
        groups = client.describe_security_groups().get("SecurityGroups", [])
    except (ClientError, BotoCoreError) as exc:
        logger.error("Unable to list security groups: %s", exc)
        return findings

    risky_ports = {22, 3389, 3306, 5432}
    for sg in groups:
        sg_id = sg.get("GroupId", "unknown")
        for perm in sg.get("IpPermissions", []):
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")
            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0" and (
                    from_port is None or to_port is None or any(p in risky_ports for p in range(from_port, to_port + 1))
                ):
                    score = cvss_like_score(exploitability=9.0, impact=8.6)
                    findings.append(
                        FindingCreate(
                            resource_type="EC2",
                            resource_id=sg_id,
                            issue="Security group exposes risky port(s) to the internet",
                            severity=score_to_severity(score),
                            score=score,
                            details=json.dumps(perm, default=str),
                        )
                    )

    return findings
