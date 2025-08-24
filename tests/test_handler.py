
from unittest.mock import patch, MagicMock
import src.handler as h

def _publish_mock():
    m = MagicMock()
    m.publish.return_value = {"MessageId": "123"}
    return m

def test_iam_create_user_publishes_alert():
    event = {
        "account": "111122223333",
        "region": "us-east-1",
        "detail": {
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateUser",
            "sourceIPAddress": "1.2.3.4",
            "userIdentity": {"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/Admin","userName":"Admin"}
        }
    }
    with patch("src.handler.sns", _publish_mock()):
        resp = h.lambda_handler(event, None)
        assert resp["published"] is True
        assert "CreateUser" in resp["subject"]
        assert resp["alert"]["severity"] == "high"

def test_console_login_failure():
    event = {
        "account": "111122223333",
        "region": "us-east-1",
        "detail": {
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "errorMessage": "Failed authentication",
            "sourceIPAddress": "5.6.7.8",
            "userIdentity": {"type":"Root","arn":"arn:aws:iam::111122223333:root"}
        }
    }
    with patch("src.handler.sns", _publish_mock()):
        resp = h.lambda_handler(event, None)
        assert "ConsoleLogin" in resp["subject"]
        assert resp["alert"]["ruleHint"] == "Console login failure"

def test_ec2_open_sg():
    event = {
        "account": "111122223333",
        "region": "us-east-1",
        "detail": {
            "eventSource": "ec2.amazonaws.com",
            "eventName": "AuthorizeSecurityGroupIngress",
            "requestParameters": {
                "ipPermissions": [
                    {"ipRanges": [{"cidrIp":"0.0.0.0/0"}]}
                ]
            },
            "sourceIPAddress": "10.0.0.10",
            "userIdentity": {"type":"AssumedRole","arn":"arn:aws:sts::111122223333:assumed-role/Admin/cli"}
        }
    }
    with patch("src.handler.sns", _publish_mock()):
        resp = h.lambda_handler(event, None)
        assert resp["alert"]["ruleHint"] == "EC2 SG modified to allow 0.0.0.0/0"
