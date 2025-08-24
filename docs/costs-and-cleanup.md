
# Costs & Cleanup

## Approximate Costs (light usage)
- **CloudTrail (management events)**: one copy of management events is generally included at no additional cost. Data events incur charges if enabled.
- **Amazon EventBridge**: very low cost per matched event; for small labs, typically pennies per month.
- **AWS Lambda**: free tier includes 1M requests/month; beyond that, very low per-request + duration cost.
- **Amazon SNS**: free tier includes 1M publishes/month; email delivery is free.

> Always check the current pricing pages before production use.

## Cleanup
If deployed with this SAM template and a stack name like `serverless-security-logger`:

### Using AWS Console
1. Go to **CloudFormation**.
2. Select your stack (e.g., `serverless-security-logger`) and choose **Delete**.
3. Confirm. CloudFormation will remove the Lambda, EventBridge rules, and SNS topic/subscription.

### Using SAM CLI
```bash
sam delete --stack-name serverless-security-logger
```

### Manual Pieces (if you created resources by hand)
- Delete the **EventBridge Rules** that target the Lambda.
- Delete the **SNS Topic** and **email subscription**.
- Delete the **Lambda function**.
- Optionally remove related **CloudWatch Log Groups** for the Lambda.
