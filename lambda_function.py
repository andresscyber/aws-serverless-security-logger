# file: lambda_function.py
"""
AWS Serverless Security Logger (refined)

- Structured logging (JSON) with eventID for easy correlation in CloudTrail
- Defensive .get() usage with sensible defaults (e.g., "unknown")
- Resilient SNS publishing with error handling
- Clear constants and helper functions
"""

import json
import logging
import os
from typing import Dict, Tuple

import boto3

# --- Logging setup -----------------------------------------------------------
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# --- Configuration -----------------------------------------------------------
# SNS topic to publish alerts to. Set in Lambda console (Configuration > Environment variables).
SNS_ARN = os.environ.get("ALERT_SNS_ARN", "").strip()
sns = boto3.client("sns")

# Monitored AWS services (via CloudTrail -> EventBridge)
INTERESTING_EVENT_SOURCES = {
    "signin.amazonaws.com",
    "iam.amazonaws.com",
    "ec2.amazonaws.com",
    "s3.amazonaws.com",
    "cloudtrail.amazonaws.com",
    "kms.amazonaws.com",
}

# High-value IAM changes that should alert
IAM_CHANGE_EVENTS = {
    "CreateUser",
    "DeleteUser",
    "CreateAccessKey",
    "DeleteAccessKey",
    "AttachUserPolicy",
    "DetachUserPolicy",
    "PutUserPolicy",
    "DeleteUserPolicy",
    "CreateRole",
    "DeleteRole",
    "AttachRolePolicy",
    "DetachRolePolicy",
    "UpdateAssumeRolePolicy",
}

# CloudTrail tampering indicators
CLOUDTRAIL_CHANGE_EVENTS = {
    "StopLogging",
    "DeleteTrail",
    "UpdateTrail",
    "PutEventSelectors",
}


# --- Helper logic ------------------------------------------------------------
def _is_world_open_sg_change(detail: Dict) -> bool:
    """Return True if a Security Group ingress change opens to the world (0.0.0.0/0)."""
    if detail.get("eventSource") != "ec2.amazonaws.com":
        return False
    if detail.get("eventName") not in ("AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress"):
        return False

    params = detail.get("requestParameters") or {}
    ip_permissions = params.get("ipPermissions") or []
    if isinstance(ip_permissions, dict):
        ip_permissions = [ip_permissions]

    # Newer API shape
    for p in ip_permissions:
        for r in (p.get("ipRanges") or []):
            if (r.get("cidrIp") or r.get("cidrIpv4")) == "0.0.0.0/0":
                return True

    # Older/simple shape
    if params.get("cidrIp") == "0.0.0.0/0":
        return True

    return False


def _is_interesting(detail: Dict) -> Tuple[bool, str]:
    """Return (is_interesting, reason) for the given CloudTrail detail."""
    es = (detail.get("eventSource") or "").strip()
    en = (detail.get("eventName") or "").strip()
    err = (detail.get("errorCode") or "").strip()

    if es not in INTERESTING_EVENT_SOURCES:
        return False, ""

    # Console logins
    if es == "signin.amazonaws.com" and en == "ConsoleLogin":
        status = (detail.get("responseElements") or {}).get("ConsoleLogin")
        mfa = (detail.get("additionalEventData") or {}).get("MFAUsed")
        if status != "Success" or str(mfa).lower() in {"no", "false", "none", ""}:
            return True, f"ConsoleLogin status={status}, MFAUsed={mfa}"

    # IAM changes
    if es == "iam.amazonaws.com" and en in IAM_CHANGE_EVENTS:
        return True, "IAM change"

    # CloudTrail tampering
    if es == "cloudtrail.amazonaws.com" and en in CLOUDTRAIL_CHANGE_EVENTS:
        return True, "CloudTrail change"

    # Security Group opened to world
    if _is_world_open_sg_change(detail):
        return True, "SecurityGroup world-open change"

    # Unauthorized / AccessDenied
    if err and ("Unauthorized" in err or "AccessDenied" in err):
        return True, f"API error {err}"

    return False, ""


def _fmt(detail: Dict, reason: str) -> str:
    """Human-friendly message body for SNS/email."""
    user = detail.get("userIdentity") or {}
    user_arn = user.get("arn") or user.get("principalId") or "unknown"
    request_snippet = json.dumps(detail.get("requestParameters") or {}, default=str)[:900]

    return (
        f"[{reason}] {detail.get('eventName')} @ {detail.get('eventSource')}\n"
        f"EventID: {detail.get('eventID')}\n"
        f"Account: {detail.get('recipientAccountId')}  Region: {detail.get('awsRegion')}\n"
        f"User: {user_arn}\n"
        f"Source IP: {detail.get('sourceIPAddress')}  UserAgent: {detail.get('userAgent')}\n"
        f"Time: {detail.get('eventTime')}\n"
        f"Request: {request_snippet}"
    )


# --- Lambda handler ----------------------------------------------------------
def lambda_handler(event, context):
    detail = (event or {}).get("detail") or {}

    interesting, reason = _is_interesting(detail)

    # Structured log for CloudWatch (easy to query with Logs Insights)
    log_line = {
        "eventID": detail.get("eventID"),
        "interesting": interesting,
        "reason": reason,
        "eventName": detail.get("eventName"),
        "eventSource": detail.get("eventSource"),
        "user": (detail.get("userIdentity") or {}).get("arn") or (detail.get("userIdentity") or {}).get("principalId"),
        "sourceIP": detail.get("sourceIPAddress"),
        "region": detail.get("awsRegion"),
        "time": detail.get("eventTime"),
        "errorCode": detail.get("errorCode"),
    }
    logger.info(json.dumps(log_line))

    # Publish interesting events to SNS
    if interesting and SNS_ARN:
        try:
            sns.publish(
                TopicArn=SNS_ARN,
                Subject=f"Security Alert: {detail.get('eventName') or 'Event'}",
                Message=_fmt(detail, reason),
            )
        except Exception as e:
            # Keep running, but surface the failure in logs for triage
            logger.error(f"SNS publish failed: {e}", exc_info=True)

    return {"ok": True, "interesting": interesting, "reason": reason}
