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

        CODE = mkhash(AUTHCODE)

        # Get refresh token and username from DynamoDB based on authorization code.
        clientdb = boto3.resource('dynamodb')
        table = clientdb.Table(DBTABLE)
        
        response = table.get_item(
            Key={
                'code': CODE
            }
        )
        
        REFTOKEN = mkdec(bytes.fromhex(response['Item']['refresh'])).decode(ENCODING)
        EMAIL = response['Item']['email']
        
        # Get access token using refresh token.
        http = urllib3.PoolManager()
        request = http.request('POST', TOKENURL+'?grant_type=refresh_token&refresh_token='+REFTOKEN+'&client_id='+CLIENTID+'&redirect_uri='+CALLBACK, headers={'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': SECRET})
        DATA = json.loads(request.data.decode(ENCODING))
        IDTOKEN = DATA['id_token']
        ACCTOKEN = DATA['access_token']

        ############################## START TOKEN VERIFICATION ##############################

        # Get keys.
        with urllib.request.urlopen(KEYURL) as f:
            response = f.read()
        KEYS = json.loads(response.decode('utf-8'))['keys']

        # Get headers.
        HEADERS = jwt.get_unverified_headers(IDTOKEN)
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
        PAYLOAD, ENCSIG = str(IDTOKEN).rsplit('.', 1)

        # Decode the signature.
        DECSIG = base64url_decode(ENCSIG.encode('utf-8'))

        # Verify the signature.
        if not PUBKEY.verify(PAYLOAD.encode("utf8"), DECSIG):
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

        prlog(context.aws_request_id, 'Signature successfully verified')
        
        # Since we passed the verification, we can now safely use the unverified claims.
        CLAIMSID = jwt.get_unverified_claims(IDTOKEN)
        CLAIMSACC = jwt.get_unverified_claims(ACCTOKEN)

        # Additionally, we can verify the token expiration.
        if time.time() > CLAIMSID['exp']:
            prlog(context.aws_request_id, 'Token has expired.')
            return {
                'statusCode': 401,
                'isBase64Encoded': False,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': '{"status": "Token has expired.", "request_id": "'+context.aws_request_id+'"}'
            }

        # And the Audience (use claims['client_id'] if verifying an access token).

        if CLAIMSID['aud'] != CLIENTID:
            prlog(context.aws_request_id, 'Token was not issued for this audience.')
            return {
                'statusCode': 401,
                'isBase64Encoded': False,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': '{"status": "Token was not issued for this audience.", "request_id": "'+context.aws_request_id+'"}'
            }

        if CLAIMSACC['client_id'] != CLIENTID:
            prlog(context.aws_request_id, 'Token was not issued for this audience.')
            return {
                'statusCode': 401,
                'isBase64Encoded': False,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': '{"status": "Token was not issued for this audience.", "request_id": "'+context.aws_request_id+'"}'
            }

        # Compare the username inside the token to the one in the original record.

        if CLAIMSID['email'] != EMAIL:
            prlog(context.aws_request_id, 'Token was not issued for this user.')
            return {
                'statusCode': 401,
                'isBase64Encoded': False,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': '{"status": "Token was not issued for this user.", "request_id": "'+context.aws_request_id+'"}'
            }

        ############################## END TOKEN VERIFICATION ##############################
        
        # Return access token.
        return {
            'statusCode': 200,
            'isBase64Encoded': False,
            'headers': {
                'Content-Type': 'text/plain',
                'Access-Control-Allow-Origin': '*'
            },
            'body': '{"acctoken": "'+ACCTOKEN+'", "email": "'+EMAIL+'"}'
        }

    except Exception as e:
        
        # Print errors to log and return access denied.
        prlog(context.aws_request_id, str(e))
        return {
            'statusCode': 403,
            'isBase64Encoded': False,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': '{"status": "failed", "request_id": "'+context.aws_request_id+'"}'
        }
