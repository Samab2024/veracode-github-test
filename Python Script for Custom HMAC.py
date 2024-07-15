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

var template = `
<style type="text/css">
    .tftable {font-size:14px;color:#333333;width:100%;border-width: 1px;border-color: #87ceeb;border-collapse: collapse;}
    .tftable th {font-size:18px;background-color:#87ceeb;border-width: 1px;padding: 8px;border-style: solid;border-color: #87ceeb;text-align:left;}
    .tftable tr {background-color:#ffffff;}
    .tftable td {font-size:14px;border-width: 1px;padding: 8px;border-style: solid;border-color: #87ceeb;}
    .tftable tr:hover {background-color:#e0ffff;}
</style>

<table class="tftable" border="1">
    <tr>
        <th>App ID</th>
        <th>App GUID</th>
        <th>Policy</th>
        <th>Policy Compliance Status</th>
        <th>Last Ploicy Check</th>
    </tr>
    
    {{#each response._embedded.findings}}
        <tr>
            <td>{{id}}</td>
            <td>{{guid}}</td>
            <td>{{policies.name}}</td>
            <td>{{policies.policy_compliance_status}}</td>
            <td>{{last_policy_compliance_check_date}}</td>
        </tr>
    {{/each}}
</table>
`;

function constructVisualizerPayload() {
    return { response: pm.response.json() }
}

print("\nLooking for Applications accessible to the profile\n")
#Retrieve Application_data name
res = prepared_request('GET', 'https://api.veracode.com/appsec/v1/applications')
response = res.json()
try:
    pm.visualizer.set(template, constructVisualizerPayload());
    print(response)
except: 
    print("\nError executing API Call")
    sys.exit(1)
