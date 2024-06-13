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

#Creds:
api_id = '3a98c572568e2c378102716e933352da'
api_secret = '22be5f66c5daef723bf871498eb5145d2054b89c5ffe8e193e3654c16efa7a3ec5616dad31a6c8be3194774eec617b3619fc16463739fa098b68486af4941d2c'
user_list = ['00749b2c-8654-4147-872f-b5a225af0c7c']
ip_list = ['65.221.0.160', '65.210.204.254', '65.203.150.126', '202.54.83.117', '203.16.165.129']

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
#for new_ip in ip_list:
#new_ip=input("What IP do you want to add? ")
for user_guid in user_list:
    print("Looking for User ID: " + user_guid)
    #Retrieve data for User GUID
    res = prepared_request('GET', 'https://api.veracode.com/api/authn/v2/users/' + user_guid)
    response = res.json()
    #print(res.json())
    try:
        old_ip = response['allowed_ip_addresses']
        print(old_ip)
    except: 
        print("\nCould not find User")
        sys.exit(1)

    #Payload for updating IP
    #new_ip=input("What do you want to pickup? ")
    ip = old_ip + ip_list
    data = {"allowed_ip_addresses": ip}
    print(data)

    #Update existing IP
    res = prepared_request('PUT', 'https://api.veracode.com/api/authn/v2/users/' + user_guid + '?partial=true', json=data)
    print(res.status_code)
    try:
        if res.status_code == 200:
          print("\nUser Updated Successfully: " + str(res.status_code) )
          res1 = prepared_request('GET', 'https://api.veracode.com/api/authn/v2/users/' + user_guid)
          response1 = res1.json()
          ip = response['allowed_ip_addresses']
          print("\nUpdated IP Data: ")
          print(ip)
        else:
          response = res.json()
          print("\nError encountered: " + response['_embedded']['errors'][0]['detail'])
    except:
        print("\nError executing API Call")
        sys.exit(1)
