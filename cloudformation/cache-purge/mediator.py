import os
import json
import requests
import ast
import hashlib
import boto3

# Resource details.
ENCODING = os.environ['ENCODING']
KMSID = os.environ['KMSID']
AUTHAPISECRET = os.environ['AUTHAPISECRET']
MAINAPISECRET = os.environ['MAINAPISECRET']
SALTSECRET = os.environ['SALTSECRET']
AUTHURL = os.environ['AUTHURL']
MAINURL = os.environ['MAINURL']
EMAIL = os.environ['EMAIL']

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
    
    try:

        # Get input from frontend.
        try:
            payload = json.loads(event['body'])
            AUTHCODE = payload['code']
        except:
            AUTHCODE = event['queryStringParameters']['code']
        try:
            payload = json.loads(event['body'])
            URLLS = payload['urls']
        except:
            URLS = event['queryStringParameters']['urls']
            URLLS = URLS.split(',')

        # Get access token and identity for the authorization code.
        authresponse = requests.get(AUTHURL+'?code='+AUTHCODE, headers={"x-api-key": APIKEYACCESS})
        authdict = ast.literal_eval(authresponse.text)
        ACCTOKEN = authdict['acctoken']
        EMAIL = authdict['email']
        
        # The data to be sent.
        DATA = '{ "username": "'+EMAIL+'", "email": "'+EMAIL+'", "group": ["'+mkhash(AUTHCODE)+'"], "url": ["'+'","'.join(URLLS)+'"]}'

        # Backend endpoint call.
        response = requests.post(MAINURL, headers = {"x-api-key": APIKEY, "Authorization": ACCTOKEN}, data = DATA)

        # Return data if validated.
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'text/plain',
                'Access-Control-Allow-Origin': '*'
            },
            'body': response.text
        }

    except Exception as e:

        # Return access denied on errors.
        prlog(str(e))
        return {
            'statusCode': 403,
            'headers': {
                'Content-Type': 'text/plain',
                'Access-Control-Allow-Origin': '*'
            },
            'body': str(e)
        }
