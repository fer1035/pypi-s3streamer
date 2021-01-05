import os
import json
import requests
import ast
import hashlib
import boto3

# Resource details.
KMSID = os.environ['KMSID']
AUTHAPISECRET = os.environ['AUTHAPISECRET']
MAINAPISECRET = os.environ['MAINAPISECRET']
SALTSECRET = os.environ['SALTSECRET']
AUTHURL = os.environ['AUTHURL']
MAINURL = os.environ['MAINURL']
ENCODING = os.environ['ENCODING']

# Convert sensitive information to the selected hash: SHA3_512.
def mkhash(clrtxt):
    clrslt = clrtxt+CONDIMENTS
    clrbyte = clrslt.encode(ENCODING)
    hashbyte = hashlib.sha3_512(clrbyte)
    hashstr = hashbyte.hexdigest()
    return hashstr

# Get secret values from Secrets Manager.
def getsec(secid):
    clientsecrets = boto3.client('secretsmanager')
    secdict = clientsecrets.get_secret_value(SecretId = secid)
    sec = secdict['SecretString']
    return sec
CONDIMENTS = getsec(SALTSECRET)
APIKEYACCESS = getsec(AUTHAPISECRET)
APIKEY = getsec(MAINAPISECRET)

def lambda_handler(event, context):

    # Print to log.
    def prlog(logtxt):
        print(context.aws_request_id+': '+logtxt)
    
    # Initiate calls.
    try:

        # Mandatory objects.        
        payload = json.loads(event['body'])
        # try:
        #     AUTHCODE = payload['code']
        #     GROUP = mkhash(AUTHCODE)
        # except:
        #     AUTHCODE = None
        #     GROUP = None
        # try:
        #     FILENAME = payload['filename']
        # except:
        #     FILENAME = None
        try:
            ACTION = payload['action']
        except:
            ACTION = None
        try:
            UPLOADID = payload['uploadid']
        except:
            UPLOADID = None
        try:
            PARTNAME = payload['partname']
        except:
            PARTNAME = None
        try:
            PARTNUMBER = payload['partnumber']
        except:
            PARTNUMBER = None
        try:
            OBJECTS = payload['objects']
        except:
            OBJECTS = None
        try:
            PARTS = payload['parts']
        except:
            PARTS = None
        try:
            FILESIZE = payload['filesize']
        except:
            FILESIZE = None
        try:
            OVERWRITE = payload['overwrite']
        except:
            OVERWRITE = 'NO'

        # Get access token and identity for the suthorization code.
        AUTHCODE = event['queryStringParameters']['code']
        FILENAME = event['queryStringParameters']['filename']
        GROUP = mkhash(AUTHCODE)
        authresponse = requests.get('{}?code={}'.format(AUTHURL, AUTHCODE), headers={"x-api-key": APIKEYACCESS})
        authdict = ast.literal_eval(authresponse.text)
        ACCTOKEN = authdict['acctoken']
        EMAIL = authdict['email']

        HEADERS = {
            "x-api-key": APIKEY, 
            "Authorization": ACCTOKEN
        }

        DATA = '{{"username": "{}", "group": "{}", "action": "{}", "filename": "{}", "uploadid": "{}", "partname": "{}", "partnumber": "{}", "objects": "{}", "parts": "{}", "filesize": "{}", "overwrite": "{}"}}'.format(EMAIL, GROUP, ACTION, FILENAME, UPLOADID, PARTNAME, PARTNUMBER, OBJECTS, PARTS, FILESIZE, OVERWRITE)
    
    except Exception as e:

        STATUSCODE = 500
        STATUSTXT = 'Failed to obtain authorization code from frontend.'
        prlog(STATUSTXT)
        return {
            'statusCode': STATUSCODE,
            'headers': {
                'Content-Type': 'text/plain',
                'Access-Control-Allow-Origin': '*'
            },
            'body': {"status": STATUSCODE, "description": STATUSTXT}
        }

    # Execute frontend calls and return backend response.
    response = requests.post(MAINURL, headers = HEADERS, data = DATA)
    STATUSCODE = response.status_code
    STATUSTXT = response.text
    # prlog(STATUSTXT)
    return {
        'statusCode': STATUSCODE,
        'headers': {
            'Content-Type': 'text/plain',
            'Access-Control-Allow-Origin': '*'
        },
        'body': STATUSTXT
    }
