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
dynamic_job = os.getenv("JOB_NAME")
#dynamic_job = 'Findings DAST'
#app_name = 'Test Update 15 Nov'

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

#print("Looking for Dynamic Analysis Jobs")
#Retrieve all DA Job
#res = prepared_request('GET', 'https://api.veracode.com/was/configservice/v1/analyses')
#response = res.json()
#try:
#    print(response)
#except: 
#    print("Could not find Dynamic Analysis")
#    sys.exit(1)

print("\nLooking for Dynamic Analysis Job: " + dynamic_job )
#Retrieve DA Job ID by project name
res = prepared_request('GET', 'https://api.veracode.com/was/configservice/v1/analyses' + '?name=' + dynamic_job)
#print(res.json())
response = res.json()
try:
    job_id = response['_embedded']['analyses'][0]['analysis_id']
    print('\nJob ID for Dynamic Analysis ' + dynamic_job + ' is ' + job_id + '.')
except: 
    print("\nCould not find Dynamic Analysis")
    sys.exit(1)

#Update Schedule of existing DA Job
try:
    res = prepared_request('PUT', 'https://api.veracode.com/was/configservice/v1/analyses/' + job_id + '?method=PATCH', json=data)
    if res.status_code == 204:
        print("\nScan Submitted Successfully: " + str(res.status_code) )
    else:
        response = res.json()
        print("\nError encountered: " + response['_embedded']['errors'][0]['detail'])
except:
    print("Error executing API Call")
    sys.exit(1)

time.sleep(30)
print('\nWaiting for 30 seconds to update the status.')

cnt = 1
print("\nLooking for Dynamic Analysis Job Status: ")
#Retrieve DA Status by Analysis name
while cnt > 0:
    res = prepared_request('GET', 'https://api.veracode.com/was/configservice/v1/analyses' + '?name=' + dynamic_job)
    #print(res.json())
    response = res.json()
    try:
        status = response['_embedded']['analyses'][0]['latest_occurrence_status']['status_type']
        if status == 'FINISHED_RESULTS_AVAILABLE':
            print('\nStatus for Dynamic Analysis ' + dynamic_job + ' is ' + status + '.')
            exit()
        else:
            print('\nStatus for Dynamic Analysis ' + dynamic_job + ' is ' + status + '.')
            print('\nChecking Status after 30 seconds\n.')
            cnt += 1
    except: 
        print("\nCould not find Dynamic Analysis")
        sys.exit(1)
    time.sleep(30)
    
#print("Looking for Application: " + app_name )
#Retrieve App List by project name
#res = prepared_request('GET', 'https://api.veracode.com/appsec/v1/applications' + '?name=' + app_name)
#response = res.json()
#print(res.json())
#try:
#    app_id = response['_embedded']['applications'][0]['id']
#    app_guid = response['_embedded']['applications'][0]['guid']
#    app_name = response['_embedded']['applications'][0]['profile']['name']
#    print('Application GUID for ' + app_name + ' is ' + app_guid + '.')
#except: 
#    print("Could not find Application")
#    sys.exit(1)

#print("Looking for Dynamic Findings: ")
#Retrieve App List by project name
#res = prepared_request('GET', 'https://api.veracode.com/appsec/v2/applications/' + app_guid + '/findings?scan_type=DYNAMIC&size=10')
#response = res.json()
#print(res.json())
