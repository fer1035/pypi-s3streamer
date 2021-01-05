import os
import json
import urllib3
import hashlib
import boto3
from boto3.dynamodb.conditions import Key, Attr
import time
import urllib.request
from jose import jwk, jwt
from jose.utils import base64url_decode

# Environment variables.
ENCODING = os.environ['ENCODING']
POOLID = os.environ['POOLID']
CLIENTID = os.environ['CLIENTID']
CALLBACK = os.environ['CALLBACK']
AUTHSECRET = os.environ['AUTHSECRET']
KEYURL = os.environ['KEYURL']
TOKENURL = os.environ['TOKENURL']
SALTSECRET = os.environ['SALTSECRET']
DBTABLE = os.environ['DBTABLE']
KMSID = os.environ['KMSID']

# Execution timestamp.
TIMESTAMP = time.strftime('%Y-%m-%d:%H-%M-%S')

# Get secret values from Secrets Manager.
def getsec(secid):
    clientsecrets = boto3.client('secretsmanager')
    secdict = clientsecrets.get_secret_value(SecretId = secid)
    sec = secdict['SecretString']
    return sec
SECRET = 'Basic '+getsec(AUTHSECRET)
CONDIMENTS = getsec(SALTSECRET)

# Print to log.
def prlog(requestid, logtxt):
    print(requestid+': '+logtxt)

# Convert sensitive information to the selected hash: SHA3_512.
def mkhash(clrtxt):
    clrslt = clrtxt+CONDIMENTS
    clrbyte = clrslt.encode(ENCODING)
    hashbyte = hashlib.sha3_512(clrbyte)
    hashstr = hashbyte.hexdigest()
    return hashstr

# Encrypt refresh token.
def mkenc(mybt):
    clientkmsenc = boto3.client('kms')
    response = clientkmsenc.encrypt(
        KeyId = KMSID,
        Plaintext = mybt
    )
    return response['CiphertextBlob']

# Decrypt Refresh Token.
def mkdec(mybt):
    clientkmsdec = boto3.client('kms')
    response = clientkmsdec.decrypt(
        KeyId = KMSID,
        CiphertextBlob = mybt
    )
    return response['Plaintext']

def lambda_handler(event, context):

    try:

        # User code from query string if available or use form data.
        try:
            AUTHCODE = event['queryStringParameters']['code']
        except:
            payload = json.loads(event['body'])
            AUTHCODE = payload['code']

        # Call the Cognito token endpoint to get tokens.
        http = urllib3.PoolManager()
        request = http.request('POST', TOKENURL+'?grant_type=authorization_code&code='+AUTHCODE+'&client_id='+CLIENTID+'&redirect_uri='+CALLBACK, headers={'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': SECRET})

        # Convert byte response data to dict.
        DATA = json.loads(request.data.decode(ENCODING))

        ############################## START TOKEN VERIFICATION ##############################

        # Get keys.
        with urllib.request.urlopen(KEYURL) as f:
            response = f.read()
        KEYS = json.loads(response.decode(ENCODING))['keys']

        # Get headers.
        HEADERS = jwt.get_unverified_headers(DATA['id_token'])
        KID = HEADERS['kid']

        # Search for the Key ID in the downloaded public keys.

        key_index = -1

        for i in range(len(KEYS)):
            if KID == KEYS[i]['kid']:
                key_index = i
                break

        if key_index == -1:
            prlog(context.aws_request_id, 'Public key not found in jwks.json.')
            return {
                'statusCode': 404,
                'isBase64Encoded': False,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': '{"status": "Public key not found in jwks.json.", "request_id": "'+context.aws_request_id+'"}'
            }

        # Construct the public key.
        PUBKEY = jwk.construct(KEYS[key_index])

        # Get the last two sections of the token, message and signature (encoded in base64).
        PAYLOAD, ENCSIG = str(DATA['id_token']).rsplit('.', 1)

        # Decode the signature.
        DECSIG = base64url_decode(ENCSIG.encode(ENCODING))

        # Verify the signature.
        if not PUBKEY.verify(PAYLOAD.encode(ENCODING), DECSIG):
            prlog(context.aws_request_id, 'Signature verification failed.')
            return {
                'statusCode': 401,
                'isBase64Encoded': False,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': '{"status": "Signature verification failed.", "request_id": "'+context.aws_request_id+'"}'
            }

        prlog(context.aws_request_id, 'Signature successfully verified.')
        
        # Since we passed the verification, we can now safely use the unverified claims.
        CLAIMS = jwt.get_unverified_claims(DATA['id_token'])
        
        ############################## END TOKEN VERIFICATION ##############################

        # Send entry to log.
        prlog(context.aws_request_id, 'Code creation requested by: '+CLAIMS['email'])

        # Save authorization code and associated refresh token in DynamoDB.
        clientdb = boto3.client('dynamodb')
        response = clientdb.put_item(
            TableName = DBTABLE,
            Item = {
                'code': {
                    'S': mkhash(AUTHCODE)
                },
                'refresh': {
                    'S': mkenc(bytes(DATA['refresh_token'], ENCODING)).hex()
                },
                'created_timestamp': {
                    'S': TIMESTAMP
                },
                'email': {
                    'S': CLAIMS['email']
                },
                'request_id': {
                    'S': context.aws_request_id
                }
            }
        )

        import authbackends

        ############################## START BACKEND CALLS ##############################

        # 1. Send notification for CDNPurge access requests.
        payloadcdn = json.loads(event['body'])
        try:
            NOTES = payloadcdn['notes']
        except:
            NOTES = 'Not applicable.'
        TEAM = payloadcdn['team']
        MANAGER = payloadcdn['manager']
        URLS = payloadcdn['urls']
        SNSTOPIC = os.environ['SNSTOPIC']
        authbackends.cdnnotify(SNSTOPIC, mkhash(AUTHCODE), CLAIMS['email'], TEAM, MANAGER, URLS, NOTES)

        ############################## END BACKEND CALLS ##############################

        prlog(context.aws_request_id, 'Obtained tokens.')

        # Return data if validated.
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            
            # Display authorization code to client.
            'body': '{"status": "succeeded", "code": "'+AUTHCODE+'"}'
        
        }

    except Exception as e:
        
        # Print errors to log and return access denied.
        prlog(context.aws_request_id, str(e))
        return {
            'statusCode': 403,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': '{"status": "failed", "request_id": "'+context.aws_request_id+'"}'
        }
