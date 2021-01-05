import os
import sys
import shutil
from git import Repo
import boto3

# Resource details.
KMSID = os.environ['KMSID']
GITPWSEC = os.environ['GITPWSEC']

# Get secret values from Secrets Manager.
def getsec(secid):
    clientsecrets = boto3.client('secretsmanager')
    secdict = clientsecrets.get_secret_value(SecretId = secid)
    sec = secdict['SecretString']
    return sec
GITPW = getsec(GITPWSEC)

def lambda_handler(event,context):
    
    try:
    
        # MAPPING TABLE
        
        mapdb = boto3.resource('dynamodb')
        maptable = mapdb.Table(os.environ['MAPTABLE'])
        
        # Remove tmp destination if it exists.
        if os.path.exists(os.environ['TMPPATH']):
            shutil.rmtree(os.environ['TMPPATH'])

        for filename in os.listdir('/tmp'):
            file_path = os.path.join('/tmp', filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                print(e)
                return {
                    'statusCode': 500,
                    'isBase64Encoded': False,
                    'headers': {
                        'Content-Type': 'text/plain',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': 'Refresh failed.'
                }
        
        # Clone files from Git repo.
        Repo.clone_from('https://ni:'+GITPW+'@'+os.environ['GITREPO'],'/tmp',branch='release')
        
        # Read mappings file.
        with open (os.environ['TMPPATH']+'/'+os.environ['MAPCSV'],'r')as mapcsv:
            mapfile = mapcsv.read()
        
        # Create the big list of all mapping items.
        mapfile1 = mapfile.replace(' ,',',')
        mapfile2 = mapfile1.replace(', ',',')
        mapbigls = mapfile2.splitlines()
        
        # Delete the whole table to refresh content.
        
        mapscan = maptable.scan(
            ProjectionExpression='id'
        )
        
        with maptable.batch_writer() as batch:
            for each in mapscan['Items']:
                batch.delete_item(Key=each)
    
        # Insert latest contents into table.
        mapid = 0
        for i in mapbigls:
            if i.strip() != '' and not i.startswith('#'):
                mapls = i.split(',')
                mapgroup = str(mapls[0]).strip()
                maphostname = str(mapls[1]).strip()
                mappattern = str(mapls[2]).strip()
                mapprovider = str(mapls[3]).replace(' ','')
                
                maptable.put_item(
                   Item={
                        'id': str(mapid),
                        'group': os.environ['WSLDS'],
                        'hostname': maphostname,
                        'pattern': mappattern,
                        'provider': mapprovider
                    }
                )
                mapid += 1
                
                # Insert privilegs for everyone else.
                if mapgroup != os.environ['WSLDS']:
                    maptable.put_item(
                       Item={
                            'id': str(mapid),
                            'group': mapgroup,
                            'hostname': maphostname,
                            'pattern': mappattern,
                            'provider': mapprovider
                        }
                    )
                    mapid += 1
        
        # BACKEND TABLE
        
        bedb = boto3.resource('dynamodb')
        betable = bedb.Table(os.environ['BETABLE'])
        
        # Read backends file.
        with open (os.environ['TMPPATH']+'/'+os.environ['BECSV'],'r')as becsv:
            befile = becsv.read()
        
        # Create the big list of all backend items.
        befile1 = befile.replace(' ,',',')
        befile2 = befile1.replace(', ',',')
        bebigls = befile2.splitlines()
        
        # Delete the whole table to refresh content.
        
        bescan = betable.scan(
            ProjectionExpression='id'
        )
        
        with betable.batch_writer() as batch:
            for each in bescan['Items']:
                batch.delete_item(Key=each)
    
        # Insert latest contents into table.
        beid = 0
        for i in bebigls:
            if i.strip() != '' and not i.startswith('#'):
                bels = i.split(',')
                bebe = str(bels[0]).strip()
                beswitch = str(bels[1]).strip()
                
                if bebe:
                    betable.put_item(
                       Item={
                            'id': str(beid),
                            'provider': bebe,
                            'switch': beswitch
                        }
                    )
                    beid += 1
                
        return {
            'statusCode': 200,
            'isBase64Encoded': False,
            'headers': {
                'Content-Type': 'text/plain',
                'Access-Control-Allow-Origin': '*'
            },
            'body': 'Refresh successful.'
        }
    
    except Exception as e:
        print(e)
        return {
            'statusCode': 400,
            'isBase64Encoded': False,
            'headers': {
                'Content-Type': 'text/plain',
                'Access-Control-Allow-Origin': '*'
            },
            'body': 'Refresh failed.'
        }

    sys.exit()
