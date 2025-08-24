
import json
import os
import boto3
from datetime import datetime

sns = boto3.client('sns')
TOPIC_ARN = os.environ.get('TOPIC_ARN')

def lambda_handler(event, context):
    # EventBridge event with CloudTrail detail
    detail = event.get('detail', {})
    event_name = detail.get('eventName', 'UnknownEvent')
    event_source = detail.get('eventSource', 'unknown.amazonaws.com')
    account = event.get('account', 'unknown')
    region = event.get('region', 'unknown')
    user_identity = detail.get('userIdentity', {})
    src_ip = detail.get('sourceIPAddress', 'unknown')

    alert = {
        "severity": "high" if event_name in ["CreateUser", "AttachUserPolicy", "AuthorizeSecurityGroupIngress"] else "medium",
        "eventTime": detail.get('eventTime', datetime.utcnow().isoformat() + "Z"),
        "account": account,
        "region": region,
        "eventSource": event_source,
        "eventName": event_name,
        "sourceIPAddress": src_ip,
        "userIdentity": {
            "type": user_identity.get("type"),
            "arn": user_identity.get("arn"),
            "userName": user_identity.get("userName"),
            "principalId": user_identity.get("principalId"),
        },
        "requestParameters": detail.get("requestParameters", {}),
        "ruleHint": _rule_hint(detail)
    }

    subject = f"AWS Security Alert: {event_name}"
    message = json.dumps(alert, default=str, ensure_ascii=False)

    sns.publish(
        TopicArn=TOPIC_ARN,
        Subject=subject[:100],
        Message=message
    )
    return {"published": True, "subject": subject, "alert": alert}

def _rule_hint(detail):
    src = detail.get("eventSource")
    name = detail.get("eventName")
    if src == "ec2.amazonaws.com" and name == "AuthorizeSecurityGroupIngress":
        return "EC2 SG modified to allow 0.0.0.0/0"
    if src == "signin.amazonaws.com" and name == "ConsoleLogin":
        if detail.get("errorMessage") == "Failed authentication":
            return "Console login failure"
    if src == "iam.amazonaws.com" and name in {"CreateUser","PutUserPolicy","AttachUserPolicy","CreateAccessKey","UpdateAssumeRolePolicy"}:
        return "Sensitive IAM change"
    return "General security event"
