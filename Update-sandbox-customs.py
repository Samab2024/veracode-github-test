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
api_id = os.getenv("API_ID")
api_secret = os.getenv("API_KEY")
app_list = ['KT_TEST_IDE']
sandbox_list = ['XML Report Test')#, 'IDE_SANDBOX']

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

#Payload for updating Custom Fields
data =   {
  "custom_fields": [
    {
      "name": "Custom 3",
      "value": ""
    },
    {
      "name": "Custom 4",
      "value": ""
    },
    {
      "name": "Custom 5",
      "value": ""
    }
  ]
}

for app_name in app_list:
    print("Looking for Application: " + app_name )
    #Retrieve App ID by App name
    res = prepared_request('GET', 'https://api.veracode.com/appsec/v1/applications' + '?name=' + app_name)
    response = res.json()
    #print(res.json())
    try:
        app_guid = response['_embedded']['applications'][0]['guid']
    except: 
        print("Could not find Application")
        sys.exit(1)
        
    for sandbox_name in sandbox_list:
        #Retrieve Sandbox ID by Sandbox name
        res = prepared_request('GET', 'https://api.veracode.com/appsec/v1/applications/' + app_guid + '/sandboxes?name=' + sandbox_name)
        response = res.json()
        print(res.json())
        try:
            sandbox_guid = response['_embedded']['sandboxes'][0]['guid']
        except: 
            print("Could not find Application Details")
            sys.exit(1)

        #Update Schedule of existing DA Job
        try:
            res = prepared_request('PUT', 'https://api.veracode.com/appsec/v1/applications/' + app_guid + '/sandboxes/' + sandbox_guid + '?method=PATCH', json=data)
            print(res.json())
            if res.status_code == 204:
                print("\nScan Submitted Successfully: " + str(res.status_code) )
            else:
                response = res.json()
                print("\nError encountered: " + response['_embedded']['errors'][0]['detail'])
        except:
            print("Error executing API Call")
            sys.exit(1)
