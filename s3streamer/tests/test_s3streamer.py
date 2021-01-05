from s3streamer import __version__
from s3streamer.s3streamer import multipart

def test_version():
    assert __version__ == '2020.2.2.2'

def test_upload():
    response = multipart('6cc2a895-3136-487a-80a0-4f39315834b0', 'tests/test.img', 'support2/docs', overwrite = 'YES', domain = 'https://download.ni.com', requrl = 'https://g1gpcdn4hl.execute-api.us-east-1.amazonaws.com/dev/request', cdnurl = 'https://mtpl5fus69.execute-api.us-east-1.amazonaws.com/dev/request')
    assert response['status'] == 200
