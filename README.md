# S3Streamer Project Source

## CloudFormation Deployment Steps

1. You will require an AWS account.
2. Put **cloudformation/s3streamer.zip** in a source S3 bucket (not your uoload destination bucket, that will be created automatically by CloudFormation).
2. Deploy **cloudformation/s3streamer.yaml**.
3. Create Access Key ID and Secret Access Key for the corresponding IAM user.
4. Create a change set for the CloudFormation stack to update those credentials.
5. Obtain API endpoint URL and key from the stack's Lambda function console.
