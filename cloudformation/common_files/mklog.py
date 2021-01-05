'''
Accumulate log events into a predefined list as key-value pairs which can be printed to CloudWatch as JSON for automatic parsing.

Sample usage:
def lambda_handler(event, context):
    lslog = []
    try:
        logtxt = 'Retrieved user info.'
        mklog.mklog(lslog,'request_id',context.aws_request_id)
        mklog.mklog(lslog,'status','succeeded')
        mklog.mklog(lslog,'message',logtxt)
    except Exception as e:
        mklog.mklog(lslog,'exception', str(e))
    print('{'+','.join(lslog)+'}')
'''
def mklog(logls,logkey,logvalue):
    logls.append('"{}": "{}"'.format(logkey,logvalue))
