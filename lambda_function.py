# file: lambda_function.py
import os, json, boto3

SNS_ARN = os.environ.get("ALERT_SNS_ARN", "")
sns = boto3.client("sns")

INTERESTING_EVENT_SOURCES = {
    "signin.amazonaws.com",
    "iam.amazonaws.com",
    "ec2.amazonaws.com",
    "s3.amazonaws.com",
    "cloudtrail.amazonaws.com",
    "kms.amazonaws.com",
}

IAM_CHANGE_EVENTS = {
    "CreateUser","DeleteUser","CreateAccessKey","DeleteAccessKey",
    "AttachUserPolicy","DetachUserPolicy","PutUserPolicy","DeleteUserPolicy",
    "CreateRole","DeleteRole","AttachRolePolicy","DetachRolePolicy",
    "UpdateAssumeRolePolicy"
}

CLOUDTRAIL_CHANGE_EVENTS = {
    "StopLogging","DeleteTrail","UpdateTrail","PutEventSelectors"
}

def _is_world_open_sg_change(detail):
    if detail.get("eventSource") != "ec2.amazonaws.com":
        return False
    if detail.get("eventName") not in ("AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress"):
        return False
    params = detail.get("requestParameters") or {}
    ip_permissions = params.get("ipPermissions") or []
    if isinstance(ip_permissions, dict):
        ip_permissions = [ip_permissions]
    # check any cidrIpv4/cidrIp = 0.0.0.0/0
    for p in ip_permissions:
        for r in (p.get("ipRanges") or []):
            if (r.get("cidrIp") or r.get("cidrIpv4")) == "0.0.0.0/0":
                return True
    # older form
    if params.get("cidrIp") == "0.0.0.0/0":
        return True
    return False

def _is_interesting(detail):
    es = detail.get("eventSource","")
    en = detail.get("eventName","")
    err = detail.get("errorCode") or ""
    if es not in INTERESTING_EVENT_SOURCES:
        return False, ""

    # Console login failures or no MFA
    if es == "signin.amazonaws.com" and en == "ConsoleLogin":
        status = (detail.get("responseElements") or {}).get("ConsoleLogin")
        mfa = (detail.get("additionalEventData") or {}).get("MFAUsed")
        if status != "Success" or str(mfa).lower() in ("no","false","none",""):
            return True, f"ConsoleLogin status={status}, MFAUsed={mfa}"

    # IAM changes
    if es == "iam.amazonaws.com" and en in IAM_CHANGE_EVENTS:
        return True, "IAM change"

    # CloudTrail tampering
    if es == "cloudtrail.amazonaws.com" and en in CLOUDTRAIL_CHANGE_EVENTS:
        return True, "CloudTrail change"

    # Security Group world-open
    if _is_world_open_sg_change(detail):
        return True, "SecurityGroup world-open change"

    # Unauthorized / AccessDenied
    if err and ("Unauthorized" in err or "AccessDenied" in err):
        return True, f"API error {err}"

    return False, ""

def _fmt(detail, reason):
    user = detail.get("userIdentity") or {}
    return (
        f"[{reason}] {detail.get('eventName')} @ {detail.get('eventSource')}\n"
        f"Account: {detail.get('recipientAccountId')}  Region: {detail.get('awsRegion')}\n"
        f"User: {user.get('arn') or user.get('principalId')}\n"
        f"Source IP: {detail.get('sourceIPAddress')}  UserAgent: {detail.get('userAgent')}\n"
        f"Time: {detail.get('eventTime')}\n"
        f"Request: {json.dumps(detail.get('requestParameters') or {}, default=str)[:900]}"
    )

def lambda_handler(event, context):
    detail = event.get("detail") or {}
    interesting, reason = _is_interesting(detail)

    # Always log structured line to CloudWatch
    print(json.dumps({
        "interesting": interesting,
        "reason": reason,
        "eventName": detail.get("eventName"),
        "eventSource": detail.get("eventSource"),
        "user": (detail.get("userIdentity") or {}).get("arn"),
        "sourceIP": detail.get("sourceIPAddress"),
        "region": detail.get("awsRegion"),
        "time": detail.get("eventTime"),
        "errorCode": detail.get("errorCode")
    }))

    # Send alert to SNS for interesting events
    if interesting and SNS_ARN:
        sns.publish(
            TopicArn=SNS_ARN,
            Subject=f"Security Alert: {detail.get('eventName')}",
            Message=_fmt(detail, reason),
        )

    return {"ok": True, "interesting": interesting, "reason": reason}
