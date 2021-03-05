==============
**S3Streamer**
==============

Overview
--------

A frontend module to upload files to AWS S3 storage. The module supports large files as it chunks them into smaller sizes and recombines them into the original file in the specified S3 bucket. It employs multiprocessing, and there is the option of specifying the size of each chunk as well as how many chunks to send in a single run. The defaults are listed in **Optional Arguments** below.

Prerequisites
-------------

- An AWS S3 bucket to receive uploads.
- An AWS Lambda function to perform backend tasks.
- The AWS CloudFormation template to create these resources are available in the project's GitHub repository.

Required (Positional) Arguments
-------------------------------

- Position 1: Filename (local full / relative path to the file)

Optional (Keyword) Arguments
----------------------------

- path: Destination path in the S3 bucket (default: /)
- parts: Number of multiprocessing parts to send simultaneously (default: 5)
- partsize: Size of each part in MB (default: 100)
- tmp: Location of local temporary directory to store temporary files created by the module (default: '/tmp')
- purge: Whether to purge the specified file instead of uploading it (default: False)
- requrl: The endpoint URL for backend Lambda function (default: 'https://<api_endpoint_url>')
- reqapikey: The API key for backend Lambda function (default: '<api_key>')

Usage
-----

Installation:

.. code-block:: BASH

   pip3 install s3streamer
   # or
   python3 -m pip install s3streamer

In Python3:

.. code-block:: BASH

   # To upload a new file.
   from s3streamer.s3streamer import multipart
   response = multipart(
       'myfile.iso', 
       'installer/images'
   )

   # To remove a file from S3.
   from s3streamer.s3streamer import multipart
   response = multipart(
       'myfile.iso', 
       'installer/images', 
       purge = True
   )

In BASH:

.. code-block:: BASH

   # To upload a new file.
   python3 -c \
   "from s3streamer.s3streamer import multipart; \
   response = multipart(\
   'myfile.iso', \
   'installer/images')"

   # To remove a file from S3.
   python3 -c \
   "from s3streamer.s3streamer import multipart; \
   response = multipart(\
   'myfile.iso', \
   'installer/images', \
   purge = True)"

If the upload is successful, the file will be available at **installer/images/myfile.iso**.

Changelog
---------

2021.2.4.2

- Moved build and publish process to GitHub Actions.

2021.2.4.1

- Updated README.

2021.2.4.0

- Simplified the module and backend to use as few assumptions as possible.
- Removed authentication and authorization layer.
- Removed CloudFront.
- Removed S3 path verification; default is now the root path.
- Removed overwrite flag; overwrites existing objects by default if already exists.
- One-step backend deployment (plus credentials creation and stack update).
- Cleaned-up module to replace most printouts with returns.

2021.2.3.2

- Removed CDN cache purge request from the module. That requet can be made separately based on use-cases.

2021.2.3.1

- Updated README to account for recent changes.

2021.2.3.0

- Streamlined all backend HTTP calls to use *requests* instead of *urllib*.
- Updated backend to use API key and Bearer token for authentication and authorization.
- Updated frontend to follow suit.

2020.2.2.3

- Added link to project repository.

2020.2.2.2

- Updated HTTP method for geturl action.

2020.2.2.1

- Removed tqdm as dependency. The module works more silently now.

2020.2.2.0

- Streamlined HTTP response throughout all layers of the streaming process. The frontend now echoes the status from the backend instead of producing its own, where possible.
- Code cleanup.

2020.2.1.7

- Initial release of the finalized working module.

*Current version: 2021.2.4.2*
