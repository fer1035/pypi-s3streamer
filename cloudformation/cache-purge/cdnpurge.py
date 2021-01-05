import os
import sys
import itertools
import datetime
import random
import string
import json
import requests
import boto3
from boto3.dynamodb.conditions import Key, Attr

# Import internal modules.
import mklog

# Resource details.
KMSID = os.environ['KMSID']
CFTOKENSEC = os.environ['CFTOKENSEC']

# Get secret values from Secrets Manager.
def getsec(secid):
    clientsecrets = boto3.client('secretsmanager')
    secdict = clientsecrets.get_secret_value(SecretId = secid)
    sec = secdict['SecretString']
    return sec
CFTOKEN = getsec(CFTOKENSEC)

# Methods
def cachemethod(methodname,methodlist):
    
    statusls = []

    try:

        
        
        #################################################
        # BEGIN PURGE BACKEND DEFINITIONS #
        #################################################

        # Create purge lists.
        cfdlmethodlist = [url for url in methodlist if url.startswith('download.ni.com')]
        cfnimethodlist = [url for url in methodlist if 'ni.com' in url and not url.startswith('download.ni.com')]
        cfmsmethodlist = [url for url in methodlist if 'multisim.com' in url]
        cfmsmethodlistALL = [url for url in methodlist if methodlist == ['multisim/PURGEALL']]

        # for methoditem in methodlist:
        #     if methoditem.startswith('download.ni.com'):
        #         cfdlmethodlist.append(methoditem)
        #     elif 'multisim.com' in methoditem:
        #         cfmsmethodlist.append(methoditem)
        #     elif methoditem == 'multisim/PURGEALL' and 'multisim.com' not in methoditem:
        #         cfmsmethodlist = ['multisim/PURGEALL']
        #     else:
        #         cfnimethodlist.append(methoditem)
        
        if methodname == 'cfurl':

            # Method: CloudFlare - Purge by URL for download.ni.com.
            if cfdlmethodlist != []:
                urlmethodlist = [ 'https://'+m for m in cfdlmethodlist ]
                urlmethodlist2 = [ 'http://'+m for m in cfdlmethodlist ]
                urlmethodlist.extend(urlmethodlist2)
                DATA = '{"files": ["'+'","'.join(urlmethodlist)+'"]}'
                purgereqcfdlurl = requests.post(os.environ['CFDLENDPOINT'], headers = {"Authorization": "Bearer "+CFTOKEN, "Content-Type": "application/json"}, data = DATA)
                statusls.append(200 if json.loads(purgereqcfdlurl.text)['success'] == True else methodname+' backend: '+str(json.loads(purgereqcfdlurl.text)['errors']))
        
            # Method: CloudFlare - Purge by URL for ni.com.
            if cfnimethodlist != []:
                urlmethodlist = [ 'https://'+m for m in cfnimethodlist ]
                urlmethodlist2 = [ 'http://'+m for m in cfnimethodlist ]
                urlmethodlist.extend(urlmethodlist2)
                DATA = '{"files": ["'+'","'.join(urlmethodlist)+'"]}'
                purgereqcfniurl = requests.post(os.environ['CFNIENDPOINT'], headers = {"Authorization": "Bearer "+CFTOKEN, "Content-Type": "application/json"}, data = DATA)
                statusls.append(200 if json.loads(purgereqcfniurl.text)['success'] == True else methodname+' backend: '+str(json.loads(purgereqcfniurl.text)['errors']))
       
            # Method: CloudFlare - Purge by URL for multisim.com.
            if cfmsmethodlist != []:
                urlmethodlist = [ 'https://'+m for m in cfmsmethodlist ]
                urlmethodlist2 = [ 'http://'+m for m in cfmsmethodlist ]
                urlmethodlist.extend(urlmethodlist2)
                DATA = '{"files": ["'+'","'.join(urlmethodlist)+'"]}'
                purgereqcfmsurl = requests.post(os.environ['CFMSENDPOINT'], headers = {"Authorization": "Bearer "+CFTOKEN, "Content-Type": "application/json"}, data = DATA)
                statusls.append(200 if json.loads(purgereqcfmsurl.text)['success'] == True else methodname+' backend: '+str(json.loads(purgereqcfmsurl.text)['errors']))
        
            # Method: CloudFlare - Purge All by URL for multisim.com.
            if cfmsmethodlistALL == ['multisim/PURGEALL'] and cfmsmethodlist == []:
                DATA = '{"purge_everything": true}'
                purgereqcfmstag = requests.post(os.environ['CFMSENDPOINT'], headers = {"Authorization": "Bearer "+CFTOKEN, "Content-Type": "application/json"}, data = DATA)
                statusls.append(200 if json.loads(purgereqcfmstag.text)['success'] == True else methodname+' backend: '+str(json.loads(purgereqcfmstag.text)['errors']))
        
        if methodname == 'cftag':

            # Method: CloudFlare - Purge by Cache-Tag for download.ni.com.
            if cfdlmethodlist != []:
                DATA = '{"tags": ["'+'","'.join(cfdlmethodlist)+'"]}'
                purgereqcfdltag = requests.post(os.environ['CFDLENDPOINT'], headers = {"Authorization": "Bearer "+CFTOKEN, "Content-Type": "application/json"}, data = DATA)
                statusls.append(200 if json.loads(purgereqcfdltag.text)['success'] == True else methodname+' backend: '+str(json.loads(purgereqcfdltag.text)['errors']))
         
            # Method: CloudFlare - Purge by Cache-Tag for ni.com.
            if cfnimethodlist != []:
                DATA = '{"tags": ["'+'","'.join(cfnimethodlist)+'"]}'
                purgereqcfnitag = requests.post(os.environ['CFNIENDPOINT'], headers = {"Authorization": "Bearer "+CFTOKEN, "Content-Type": "application/json"}, data = DATA)
                statusls.append(200 if json.loads(purgereqcfnitag.text)['success'] == True else methodname+' backend: '+str(json.loads(purgereqcfnitag.text)['errors']))
        
            # Method: CloudFlare - Purge by Cache-Tag for multisim.com.
            if cfmsmethodlist != []:
                DATA = '{"tags": ["'+'","'.join(cfmsmethodlist)+'"]}'
                purgereqcfmstag = requests.post(os.environ['CFMSENDPOINT'], headers = {"Authorization": "Bearer "+CFTOKEN, "Content-Type": "application/json"}, data = DATA)
                statusls.append(200 if json.loads(purgereqcfmstag.text)['success'] == True else methodname+' backend: '+str(json.loads(purgereqcfmstag.text)['errors']))

        #################################################
        # END PURGE BACKEND DEFINITIONS #
        #################################################
            
            
            
        return statusls
        
    except Exception as e:
        logtxt = 'Could not contact backend(s).'
        mklog.mklog(lslog,'status','failed')
        mklog.mklog(lslog,'exception', str(e))
        mklog.mklog(lslog,'error',logtxt)
        print('{'+','.join(lslog)+'}')
        return False
        lslog.clear()
        sys.exit()

# Function: get list of active backends.
def getbe():
    try:
        
        bedb = boto3.resource('dynamodb')
        betable = bedb.Table(os.environ['BETABLE'])
        fe = Key('switch').eq('on')
        pe = "provider"
        beresponse = betable.scan(
            FilterExpression=fe,
            ProjectionExpression=pe
        )
            
        backends = [ i['provider'] for i in beresponse['Items'] ]
        
        return backends
        
    except Exception as e:
        logtxt = 'Could not fetch backend list.'
        mklog.mklog(lslog,'status','failed')
        mklog.mklog(lslog,'exception', str(e))
        mklog.mklog(lslog,'error',logtxt)
        print('{'+','.join(lslog)+'}')
        return False
        lslog.clear()
        sys.exit()

# Function: get list of allowed purge patterns for the specified LDS group.
# def checkpattern(checkgroup,checkproviders):
def checkpattern(checkgroup):
    try:
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(os.environ['MAPTABLE'])

        # Define search key and result format.
        fe = Key('group').eq(checkgroup)
        pe = "hostname, pattern, provider"
        
        # Scan DynamoDB for matching results.
        response = table.scan(
            FilterExpression=fe,
            ProjectionExpression=pe
        )
        
        # Create the list of allowed patterns for the LDS groups.
        # if checkgroup == os.environ['WSLDS']:
        #     patternproviders = [ p for p in checkproviders ]
        #     patterndict = { '|'.join(patternproviders):i['hostname'] for i in response['Items'] }
        # else:
        patterndict = [{ i['provider']:i['hostname']+'/'+i['pattern'] } for i in response['Items']]
        return patterndict
    
    except Exception as e:
        logtxt = 'Could not validate pattern.'
        mklog.mklog(lslog,'status','failed')
        mklog.mklog(lslog,'exception', str(e))
        mklog.mklog(lslog,'error',logtxt)
        print('{'+','.join(lslog)+'}')
        return False
        lslog.clear()
        sys.exit()
    
# Function: break list into chunks of 30.
def chunks(chunklist,chunksize):
    for x in range(0, len(chunklist), chunksize):
        yield chunklist[x:x + chunksize]

# Main Lambda function to execute purge.
def lambda_handler(event, context):

    # Initialize logger
    lslog = []
    
    try:

        # Send session data to the logs.
        purgets = f'{datetime.datetime.now():%Y-%m-%d %H:%M:%S} GMT'
        purgeid = 'NICDNPurge_'+''.join(random.choices(string.ascii_lowercase+string.ascii_uppercase+string.digits, k=20))
        mklog.mklog(lslog,'request_id',context.aws_request_id)
        mklog.mklog(lslog,'exec_timestamp',purgets)
        mklog.mklog(lslog,'exec_id',purgeid)
        
        # Get payload data from frontend.
        payload = json.loads(event['body'])
        purgeuser = payload['username']
        purgemail = payload['email']
        purgegroup = payload['group']
        purgelist = payload['url']
        
        # Send request data to the logs.
        mklog.mklog(lslog,'user',purgeuser)
        mklog.mklog(lslog,'groups',', '.join(purgegroup))
        
        # Get out if list is empty.
        if not purgelist:
            logtxt = 'Empty list.'
            mklog.mklog(lslog,'status','failed')
            mklog.mklog(lslog,'error',logtxt)
            print('{'+','.join(lslog)+'}')
            return {
                'statusCode': 470,
                'isBase64Encoded': False,
                'headers': {
                    'Content-Type': 'text/plain',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': 'ERROR: Empty list, exiting.\n'
            }
            lslog.clear()
            sys.exit()
        
        # Strip protocols if present.
        stripls = []
        for s in purgelist:
            if s.strip().startswith('http://') or s.strip().startswith('https://'):
                stripitem = s.strip().replace('http://','',1).replace('https://','',1).replace(' ','%20')
            else:
                stripitem = s.strip().replace(' ','%20')
            stripls.append(stripitem)
            striplist = list(set(stripls))
        
        # Get lists of patterns and providers.
        
        dictlist = []
        itemlist = []
        authlist = []
        
        try:
            payload['backend']
            
        except:
            providers = getbe()
            for lds in purgegroup:
                if checkpattern(lds) != []:
                    dictlist.extend(checkpattern(lds))
    
            for myitem,mydict in itertools.product(striplist,dictlist):
                for provider,mykey in itertools.product(providers,mydict):
                    if provider in mykey and mydict[mykey] in myitem:
                        itemlist.append({provider:myitem})
                        authlist.append(myitem)
                        
            badlist = [ baditem for baditem in striplist if baditem not in list(set(authlist)) ]
                
        else:
            providers = payload['backend']
            if ','.join(purgegroup) == os.environ['WSLDS']:
                for provider,myitem in itertools.product(providers,striplist):
                    itemlist.append({provider:myitem})
                    badlist = []
            else:
                badlist = [ baditem for baditem in striplist ]
                
        # Check if there's any unauthorized item in the list.
        if badlist != []:
            logtxt = 'Unauthorized purge item(s): '+','.join(badlist)
            mklog.mklog(lslog,'status','failed')
            mklog.mklog(lslog,'error',logtxt)
            print('{'+','.join(lslog)+'}')
            return {
                'statusCode': 471,
                'isBase64Encoded': False,
                'headers': {
                    'Content-Type': 'text/plain',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': 'ERROR: Unauthorized purge item(s): \n'+'\n'.join(badlist)+'\n'
            }
            lslog.clear()
            sys.exit()
            
        # Create lists for each backend and execute.
        statuslist = []
        finalls = []
        finalproviders = []

        for provider in providers:
            execls = []
            for execdict in itemlist:
                if execdict.get(provider):
                    execls.append(execdict.get(provider))
            execbiglist = list(set(execls))
            finalls.extend(execbiglist)
            if execbiglist != []:
                finalproviders.append(provider)
                execbiglist = list(set(execls))
                execchunks = chunks(execbiglist,15)
                for execlist in execchunks:
                    statuslist.extend(cachemethod(provider,execlist))
        
        statusfinal = []
        for execstatus in statuslist:
            if execstatus != 200:
                statusfinal.append(execstatus)
            
        # Send results to client abd logs,
        if statusfinal == []:
            
            # Log purge backend and list.
            mklog.mklog(lslog,'status','succeeded')
            mklog.mklog(lslog,'backends',','.join(finalproviders))
            mklog.mklog(lslog,'purged',','.join(finalls))
            print('{'+','.join(lslog)+'}')
            return {
                'statusCode': 200,
                'isBase64Encoded': False,
                'headers': {
                    'Content-Type': 'text/plain',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': 'Purge request sent: \n'+'\n'.join(striplist)+'\n'
            }
            lslog.clear()
            sys.exit()
            
        else:
            
            logtxt = statusfinal
            mklog.mklog(lslog,'status','failed')
            mklog.mklog(lslog,'error',logtxt)
            print('{'+','.join(lslog)+'}')
            return {
                'statusCode': 472,
                'isBase64Encoded': False,
                'headers': {
                    'Content-Type': 'text/plain',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': 'ERROR: \n'+str(statusfinal)+'\n\nPlease contact Web Systems <web.systems.support@ni.com> with the following details for assistance:\n'+'Timestamp: '+purgets+'\n'+'Session ID: '+purgeid+'\n'
            }
            lslog.clear()
            sys.exit()
    
    except Exception as e:
       
        logtxt = 'Failed to purge.'
        mklog.mklog(lslog,'status','failed')
        mklog.mklog(lslog,'exception',str(e))
        mklog.mklog(lslog,'error',logtxt)
        print('{'+','.join(lslog)+'}')
        return {
            'statusCode': 500,
            'isBase64Encoded': False,
            'headers': {
                'Content-Type': 'text/plain',
                'Access-Control-Allow-Origin': '*'
            },
            'body': 'Failed to purge, please contact Web Systems <web.systems.support@ni.com> with the following details for assistance:\n'+'Timestamp: '+purgets+'\n'+'Session ID: '+purgeid+'\n'
        }
        lslog.clear()
        sys.exit()
