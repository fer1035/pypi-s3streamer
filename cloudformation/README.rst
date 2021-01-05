==============
**S3Streamer**
==============

**AWS API Deployments**

Overview
--------

These are the CloudFormation templates and Lambda functions to deploy the API that the Python module connects to. 

Steps
-----

**CDN**

We use CloudFlare as the CDN for our upload repository, so that's what this very concise guide pertains to. Other CDNs may employ different steps to purge cache programmatically.

1. Create an account in the CDN.
2. Configure it to cache the contents of your upload repository.
3. Obtain the necessary tokens and URL to perform programmatical purges of your cache.
4. Use the endpoint URL in the cache purge API.

**S3 Bucket**

1. Create an S3 bucket to host uploaded files.
2. Create an IAM user with arite access to the bucket. Note the user's programmatic credentials.
3. Create another S3 bucket to host the API source materials.

**Auth API**

1. Rename *authenticator.py* to *lambda_function.py*.
2. ZIP the file.
3. Rename *authorizer.py* to *lambda_function.py*..
4. ZIP the file.
5. Upload both ZIP files along with *jose.zip* to the API source bucket.
6. Deploy *cognito.yaml*, then *main.yaml* in CloudFormation, specifying the correct parameters and noting the outputs of both deployments.
7. You may also need to create a basic HTML page to receive the output of the Auth API.

**Cache Purge API**

1. Rename *cdnpurge.py* to *lambda_function.py*.
2. ZIP the file along with *mklog.py*.
3. Rename *dbrefresh.py* to *lambda_function.py*.
4. ZIP the file.
5. Rename *mediator.py* to *lambda_function.py*.
6. ZIP the file.
7. Upload all ZIP files along with *requests.zip* - available in *common_files* - to the API source bucket.
8. Deploy *main.yaml*, then *mediator.yaml* in CloudFormation, specifying the correct parameters and noting the outputs.
9. You will need to configure a Git account to host the CSV files which will control access to upload and cache-purging paths, as well as cache-purge method switches (if applicable).
10. There is also an Azure DevOps pipeline YAML included if you're using that to host the CSV files.

**Upload API**

1. Rename *main.py* to *lambda_function.py*.
2. ZIP the file along with *mklog.py*.
3. Rename *mediator.py* to *lambda_function.py*.
4. ZIP the file.
5. Upload both ZIP files along with *requests.zip* - available in *common_files* - to the API source bucket.
6. Deploy *main.yaml*, then *mediator.yaml* in CloudFormation, specifying the correct parameters and noting the outputs.
7. The final output from *mediator.yaml* will be the endpoint URL of the API to use in the Python module.
