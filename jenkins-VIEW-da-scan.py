#!/usr/bin/env python3
import os
import time                                                                     
import hmac                                                                     
import codecs
import json  
import sys                                                              
from hashlib import sha256 
import requests
from requests.adapters import HTTPAdapter                                       
from urllib.parse import urlparse

#Setup variables according to environment

#Jenkins:
#api_id = os.getenv("API_ID")
api_id = '7ba41c040f6c9f8dcacdb4d7a18da383'
#api_secret = os.getenv("API_KEY")
api_secret = 'bc354827aca7743ff31199736b0cf0aed2f6832f4b0758fc8db617a885dceeaf0d8b3897557e2a37213677b515ee497dc38dc689f6329a49e5c0b88e83df0728'
#dynamic_job = os.getenv("JOB_NAME")


def veracode_hmac(host, url, method):
    signing_data = 'id={api_id}&host={host}&url={url}&method={method}'.format(
                    api_id=api_id.lower(),
                    host=host.lower(),
                    url=url, method=method.upper())

    timestamp = int(round(time.time() * 1000))
    nonce = os.urandom(16).hex()

    key_nonce = hmac.new(
        codecs.decode(api_secret, 'hex_codec'),
        codecs.decode(nonce, 'hex_codec'), sha256).digest()

    key_date = hmac.new(key_nonce, str(timestamp).encode(), sha256).digest()
    signature_key = hmac.new(
            key_date, 'vcode_request_version_1'.encode(), sha256).digest()
    signature = hmac.new(
            signature_key, signing_data.encode(), sha256).hexdigest()

    return '{auth} id={id},ts={ts},nonce={nonce},sig={sig}'.format(
            auth='VERACODE-HMAC-SHA-256',
            id=api_id,
            ts=timestamp,
            nonce=nonce,
            sig=signature)

def prepared_request(method, end_point, json=None, query=None, file=None):
    session = requests.Session()
    session.mount(end_point, HTTPAdapter(max_retries=3))
    request = requests.Request(method, end_point, json=json, params=query, files=file)
    prepared_request = request.prepare()
    prepared_request.headers['Authorization'] = veracode_hmac(
        urlparse(end_point).hostname, prepared_request.path_url, method)
    res = session.send(prepared_request)

    return res

# code above this line is reusable for all/most API calls

#Payload for updating schedule of existing DA job to start now
data =   { 
    "schedule": 
        {       
            "now": True,
            "duration": 
                {
                "length": 1,
                "unit": "DAY"
                }
        }
}


print("Looking for Dynamic Analysis Jobs")
#Retrieve DA Job ID by project name
res = prepared_request('GET', 'https://api.veracode.com/was/configservice/v1/analyses')
response = res.json()
try:
    print(response)
except: 
    print("Could not find Dynamic Analysis")
    sys.exit(1)

#Update Schedule of existing DA Job
#try:
#    res = prepared_request('PUT', 'https://api.veracode.com/was/configservice/v1/analyses/' + job_id + '?method=PATCH', json=data)
#    if res.status_code == 204:
#        print("Scan Submitted Successfully: " + str(res.status_code) )
#    else:
#        response = res.json()
#        print("Error encountered: " + response['_embedded']['errors'][0]['detail'])
#except:
#    print("Error executing API Call")
#    sys.exit(1)
