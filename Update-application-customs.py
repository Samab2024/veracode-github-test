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
app_list = ['KT_TEST_IDE','Test Update 15 Nov','test_api_wrapper_new']

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

for app_name in app_list:
    print("Looking for Application: " + app_name )
    #Retrieve App ID by App name
    res = prepared_request('GET', 'https://api.veracode.com/appsec/v1/applications' + '?name=' + app_name)
    response = res.json()
    #print(res.json())
    try:
        app_guid = response['_embedded']['applications'][0]['guid']
        bus_crit = response['_embedded']['applications'][0]['profile']['business_criticality']
    except: 
        print("\nCould not find Application")
        sys.exit(1)

    #Payload for updating Custom Fields
    data =   {
      "profile": {
        "name": app_name,
        'custom_fields': [
            {'name': 'Custom 2', 'value': 'TESTING'}, {'name': 'Custom 3', 'value': 'COMP1: : : '}, {'name': 'Custom 4', 'value': ''}, {'name': 'Custom 5', 'value': 'Test'}
        ],
        "business_criticality": bus_crit
      }
    }

    #Update Schedule of existing DA Job
    res = prepared_request('PUT', 'https://api.veracode.com/appsec/v1/applications/' + app_guid + '?method=PATCH', json=data)
    #print(res.status_code)
    try:
        if res.status_code == 200:
          print("\nApplication Updated Successfully: " + str(res.status_code) )
          res1 = prepared_request('GET', 'https://api.veracode.com/appsec/v1/applications' + '?name=' + app_name)
          response1 = res1.json()
          custom = response1['_embedded']['applications'][0]['profile']['custom_fields']
          print("\nUpdated Custom Data: ")
          print(custom)
        else:
          response = res.json()
          print("\nError encountered: " + response['_embedded']['errors'][0]['detail'])
    except:
        print("\nError executing API Call")
        sys.exit(1)
