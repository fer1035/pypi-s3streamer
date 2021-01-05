import os
import ast
import json
import datetime
import boto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError

# Import internal modules.
import mklog

# Resource details.
KMSID = os.environ['KMSID']
REGION = os.environ['REGION']
BUCKET = os.environ['BUCKET']
IDSECRET = os.environ['IDSECRET']
SECSECRET = os.environ['SECSECRET']
MAPTABLE = os.environ['MAPTABLE']
DOMAIN = os.environ['DOMAIN']
URLEXPIRY = int(os.environ['URLEXPIRY'])

# Get secret values from Secrets Manager.
def getsec(secid):
    clientsecrets = boto3.client('secretsmanager')
    secdict = clientsecrets.get_secret_value(SecretId = secid)
    sec = secdict['SecretString']
    return sec
ACCESSKEY = getsec(IDSECRET)
ACCESSSEC = getsec(SECSECRET)

# Validation: Check if file exists.
def get_filesize(client, bucket, file):
    response = client.list_objects_v2(
        Bucket = bucket,
        Prefix = file,
    )
    for obj in response.get('Contents', []):
        if obj['Key'] == file:
            return obj['Size']

# Validation: Check if user has permission for the specified path.
def checkpattern(checkgroup):
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(os.environ['MAPTABLE'])
    fe = Key('group').eq(checkgroup)
    pe = "pattern, hostname"
    response = table.scan(
        FilterExpression=fe,
        ProjectionExpression=pe
    )
    patternlist = [i['pattern'] for i in response['Items'] if i['hostname'] == DOMAIN]
    return patternlist

def lambda_handler(event, context):

    # Initialize logger
    lslog = []

    # Initialize.
    try:

        # Send session data to the logs.
        uploadts = f'{datetime.datetime.now():%Y-%m-%d %H:%M:%S} GMT'
        mklog.mklog(lslog,'starttime', uploadts)
        mklog.mklog(lslog,'request_id', context.aws_request_id)

        payload = json.loads(event['body'])
        USERNAME = payload['username']
        GROUP = payload['group']
        ACTION = payload['action']
        FILENAME = payload['filename']
        UPLOADID = payload['uploadid']
        PARTNAME = payload['partname']
        PARTNUMBER = payload['partnumber']
        OBJECTS = ast.literal_eval(payload['objects'])
        PARTS = ast.literal_eval(payload['parts'])
        FILESIZE = payload['filesize']
        OVERWRITE = payload['overwrite']

        restaction = ['create']
        noneaction = ['purge']
        urlaction = ['geturl']

        mklog.mklog(lslog, 'user', USERNAME)
        mklog.mklog(lslog, 'group', GROUP)
        mklog.mklog(lslog, 'file', FILENAME)
        mklog.mklog(lslog, 'size', FILESIZE)
        mklog.mklog(lslog, 'action', ACTION)
        mklog.mklog(lslog, 'overwrite', OVERWRITE)

        # Initialize S3 client.
        client = boto3.client('s3', aws_access_key_id = ACCESSKEY, aws_secret_access_key = ACCESSSEC, region_name = REGION)

        # Ensure that the user has access to the specified path.
        checklist = checkpattern(GROUP)
        matchlist = [i for i in checklist if FILENAME.startswith(i.strip('/'))]
        if matchlist == [] and ACTION not in urlaction:
            STATUSCODE = 403
            STATUSTXT = 'No access to the specified path.'
            mklog.mklog(lslog, 'status', STATUSCODE)
            mklog.mklog(lslog, 'description', STATUSTXT)
            print('{'+','.join(lslog)+'}')
            return {
                'statusCode': STATUSCODE,
                'headers': {
                    'Content-Type': 'text/plain',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': STATUSTXT
            }

        # Ensure the file doesn't already exist, or if the --overwrite flag is set.
        if OVERWRITE != 'YES' and ACTION in restaction and get_filesize(client, BUCKET, FILENAME) != None:
            STATUSCODE = 401
            STATUSTXT = 'Document already exists and overwrite is not set.'
            mklog.mklog(lslog, 'status', STATUSCODE)
            mklog.mklog(lslog, 'description', STATUSTXT)
            print('{'+','.join(lslog)+'}')
            return {
                'statusCode': STATUSCODE,
                'headers': {
                    'Content-Type': 'text/plain',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': STATUSTXT
            }
        
        # If purging, ensure that the file actually exists.
        if ACTION in noneaction and get_filesize(client, BUCKET, FILENAME) == None:
            STATUSCODE = 404
            STATUSTXT = 'Document does not exist and therefore cannot be purged.'
            mklog.mklog(lslog, 'status', STATUSCODE)
            mklog.mklog(lslog, 'description', STATUSTXT)
            print('{'+','.join(lslog)+'}')
            return {
                'statusCode': STATUSCODE,
                'headers': {
                    'Content-Type': 'text/plain',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': STATUSTXT
            }

        # Get pre-signed URL.
        if ACTION == 'geturl':
            try:
                response = client.generate_presigned_post(BUCKET, 'tmp/{}'.format(FILENAME), Fields = None, Conditions = None, ExpiresIn = URLEXPIRY)
                STATUSCODE = 200
                STATUSTXT = str(response)
                mklog.mklog(lslog, 'status', STATUSCODE)
                mklog.mklog(lslog, 'description', 'Pre-signed URL returned to client.')
                print('{'+','.join(lslog)+'}')
                return {
                    'statusCode': STATUSCODE,
                    'headers': {
                        'Content-Type': 'text/plain',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': STATUSTXT
                }
            except Exception as e:
                STATUSCODE = 403
                STATUSTXT = str(e)
                mklog.mklog(lslog, 'status', STATUSCODE)
                mklog.mklog(lslog, 'description', STATUSTXT)
                print('{'+','.join(lslog)+'}')
                return {
                    'statusCode': STATUSCODE,
                    'headers': {
                        'Content-Type': 'text/plain',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': STATUSTXT
                }

        # Get pre-signed URL for non-multipart uploads.
        if ACTION == 'geturls':
            try:
                response = client.generate_presigned_post(BUCKET, FILENAME, Fields = None, Conditions = None, ExpiresIn = URLEXPIRY)
                STATUSCODE = 200
                STATUSTXT = str(response)
                mklog.mklog(lslog, 'status', STATUSCODE)
                mklog.mklog(lslog, 'description', 'Pre-signed URL returned to client.')
                print('{'+','.join(lslog)+'}')
                return {
                    'statusCode': STATUSCODE,
                    'headers': {
                        'Content-Type': 'text/plain',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': STATUSTXT
                }
            except Exception as e:
                STATUSCODE = 403
                STATUSTXT = str(e)
                mklog.mklog(lslog, 'status', STATUSCODE)
                mklog.mklog(lslog, 'description', STATUSTXT)
                print('{'+','.join(lslog)+'}')
                return {
                    'statusCode': STATUSCODE,
                    'headers': {
                        'Content-Type': 'text/plain',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': STATUSTXT
                }
        
        # Get Upload ID.
        if ACTION == 'create':
            try:
                response = client.create_multipart_upload(ACL = 'private', Bucket = BUCKET, Key = FILENAME)
                assert response
                STATUSCODE = 200
                STATUSTXT = response['UploadId']
                mklog.mklog(lslog, 'status', STATUSCODE)
                mklog.mklog(lslog, 'description', 'Upload ID returned to client.')
                print('{'+','.join(lslog)+'}')
                return {
                    'statusCode': STATUSCODE,
                    'headers': {
                        'Content-Type': 'text/plain',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': STATUSTXT
                }
            except Exception as e:
                STATUSCODE = 403
                STATUSTXT = str(e)
                mklog.mklog(lslog, 'status', STATUSCODE)
                mklog.mklog(lslog, 'description', STATUSTXT)
                print('{'+','.join(lslog)+'}')
                return {
                    'statusCode': STATUSCODE,
                    'headers': {
                        'Content-Type': 'text/plain',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': STATUSTXT
                }

        # Add each part to the main document.
        if ACTION == 'add':
            try:
                response = client.upload_part_copy(
                    Bucket = BUCKET,
                    CopySource = {
                        'Bucket': BUCKET,
                        'Key': 'tmp/{}'.format(PARTNAME)
                    },
                    Key = FILENAME,
                    PartNumber = int(PARTNUMBER),
                    UploadId = UPLOADID
                )
                assert response
                STATUSCODE = 200
                STATUSTXT = 'Part added to the main document.'
                mklog.mklog(lslog, 'status', STATUSCODE)
                mklog.mklog(lslog, 'description', STATUSTXT)
                print('{'+','.join(lslog)+'}')
                return {
                    'statusCode': STATUSCODE,
                    'headers': {
                        'Content-Type': 'text/plain',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': STATUSTXT
                }
            except Exception as e:
                STATUSCODE = 403
                STATUSTXT = str(e)
                mklog.mklog(lslog, 'status', STATUSCODE)
                mklog.mklog(lslog, 'description', STATUSTXT)
                print('{'+','.join(lslog)+'}')
                return {
                    'statusCode': STATUSCODE,
                    'headers': {
                        'Content-Type': 'text/plain',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': STATUSTXT
                }
        
        # Complete multipart recombination.
        if ACTION == 'complete':
            try:
                response = client.complete_multipart_upload(
                    Bucket = BUCKET,
                    Key = FILENAME,
                    UploadId = UPLOADID,
                    MultipartUpload={
                        'Parts': PARTS
                    }
                )
                assert response
                STATUSCODE = 200
                STATUSTXT = 'Document recombined.'
                mklog.mklog(lslog, 'status', STATUSCODE)
                mklog.mklog(lslog, 'description', STATUSTXT)
                print('{'+','.join(lslog)+'}')
                return {
                    'statusCode': STATUSCODE,
                    'headers': {
                        'Content-Type': 'text/plain',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': STATUSTXT
                }
            except Exception as e:
                STATUSCODE = 403
                STATUSTXT = str(e)
                mklog.mklog(lslog, 'status', STATUSCODE)
                mklog.mklog(lslog, 'description', STATUSTXT)
                print('{'+','.join(lslog)+'}')
                return {
                    'statusCode': STATUSCODE,
                    'headers': {
                        'Content-Type': 'text/plain',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': STATUSTXT
                }

        # Delete parts if multipart upload completes or aborts.
        if ACTION == 'delete':
            try:
                response = client.delete_objects(
                    Bucket = BUCKET,
                    Delete={
                        'Objects': OBJECTS,
                        'Quiet': True
                    }
                )
                assert response
                STATUSCODE = 200
                STATUSTXT = 'Temporary file(s) deleted.'
                mklog.mklog(lslog, 'status', STATUSCODE)
                mklog.mklog(lslog, 'description', STATUSTXT)
                print('{'+','.join(lslog)+'}')
                return {
                    'statusCode': STATUSCODE,
                    'headers': {
                        'Content-Type': 'text/plain',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': STATUSTXT
                }
            except Exception as e:
                STATUSCODE = 403
                STATUSTXT = str(e)
                mklog.mklog(lslog, 'status', STATUSCODE)
                mklog.mklog(lslog, 'description', STATUSTXT)
                print('{'+','.join(lslog)+'}')
                return {
                    'statusCode': STATUSCODE,
                    'headers': {
                        'Content-Type': 'text/plain',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': STATUSTXT
                }

        # Purge documents from main storage.
        if ACTION == 'purge':
            try:
                response = client.delete_objects(
                    Bucket = BUCKET,
                    Delete={
                        'Objects': OBJECTS,
                        'Quiet': True
                    }
                )
                assert response
                STATUSCODE = 200
                STATUSTXT = 'Document purged.'
                mklog.mklog(lslog, 'status', STATUSCODE)
                mklog.mklog(lslog, 'description', STATUSTXT)
                print('{'+','.join(lslog)+'}')
                return {
                    'statusCode': STATUSCODE,
                    'headers': {
                        'Content-Type': 'text/plain',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': STATUSTXT
                }
            except Exception as e:
                STATUSCODE = 403
                STATUSTXT = str(e)
                mklog.mklog(lslog, 'status', STATUSCODE)
                mklog.mklog(lslog, 'description', STATUSTXT)
                print('{'+','.join(lslog)+'}')
                return {
                    'statusCode': STATUSCODE,
                    'headers': {
                        'Content-Type': 'text/plain',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': STATUSTXT
                }

        # Abort multipart upload if any part fails.
        if ACTION == 'abort':
            try:
                response = client.abort_multipart_upload(
                    Bucket = BUCKET,
                    Key = FILENAME,
                    UploadId = UPLOADID
                )
                assert response
                STATUSCODE = 200
                STATUSTXT = 'Multipart upload aborted.'
                mklog.mklog(lslog, 'status', STATUSCODE)
                mklog.mklog(lslog, 'description', STATUSTXT)
                print('{'+','.join(lslog)+'}')
                return {
                    'statusCode': STATUSCODE,
                    'headers': {
                        'Content-Type': 'text/plain',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': STATUSTXT
                }
            except Exception as e:
                STATUSCODE = 403
                STATUSTXT = str(e)
                mklog.mklog(lslog, 'status', STATUSCODE)
                mklog.mklog(lslog, 'description', STATUSTXT)
                print('{'+','.join(lslog)+'}')
                return {
                    'statusCode': STATUSCODE,
                    'headers': {
                        'Content-Type': 'text/plain',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': STATUSTXT
                }

    except Exception as e:
        STATUSCODE = 500
        STATUSTXT = str(e)
        mklog.mklog(lslog, 'status', STATUSCODE)
        mklog.mklog(lslog, 'description', STATUSTXT)
        print('{'+','.join(lslog)+'}')
        return {
            'statusCode': STATUSCODE,
            'headers': {
                'Content-Type': 'text/plain',
                'Access-Control-Allow-Origin': '*'
            },
            'body': STATUSTXT
        }
