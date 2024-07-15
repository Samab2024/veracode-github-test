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

#CI/CD parameters (below example):
api_id = os.getenv("API_ID")
api_secret = os.getenv("API_KEY")

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
    prepared_request.headers['Authorization'] = veracode_hmac(urlparse(end_point).hostname, prepared_request.path_url, method)
    res = session.send(prepared_request)

    return res

# code above this line is reusable for all/most API calls

print("\nLooking for Applications accessible to the profile\n")
#Retrieve Application_data name
res = prepared_request('GET', 'https://api.veracode.com/appsec/v1/applications')
response = res.json()
#print(response)
records = len(response)
app_id=response['_embedded']['applications'][0]['id']
app_guid=response['_embedded']['applications'][0]['guid']
Policy_Name=response['_embedded']['applications'][0]['profile']['policies'][0]['name']
Policy_Check_Status=response['_embedded']['applications'][0]['profile']['policies'][0]['policy_compliance_status']
Last_Policy_Check_Date=response['_embedded']['applications'][0]['last_policy_compliance_check_date']
try:
    print('APP_ID|APP_GUID|POLICY|STATUS|LAST_POLICY_CHECK_DATE')
    for x in range(0, records - 1):
        app_id=response['_embedded']['applications'][x]['id']
        app_guid=response['_embedded']['applications'][x]['guid']
        Policy_Name=response['_embedded']['applications'][x]['profile']['policies'][0]['name']
        Policy_Check_Status=response['_embedded']['applications'][x]['profile']['policies'][0]['policy_compliance_status']
        Last_Policy_Check_Date=response['_embedded']['applications'][x]['last_policy_compliance_check_date']
        print(app_id + '|' + app_guid + '|' + Policy_Name + '|' + Policy_Check_Status + '|' + Last_Policy_Check_Date)
        x=x+1
except: 
    print("\nError executing API Call")
    sys.exit(1)
