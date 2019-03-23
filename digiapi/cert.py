from digiapi import conf
from digiapi.conf import confd_cert, rest_status, confd_org, keyd
from pathlib import Path
from configparser import ConfigParser
import re
import json
import requests

# REST resources
url = 'https://www.digicert.com/services/v2/order/certificate'
headers_get = {"X-DC-DEVKEY" : conf.api_key, "Accept" : "application/json"}
headers_post = {"X-DC-DEVKEY" : conf.api_key, "Content-Type" : "application/json"}

def list_cert():
    req = requests.get(url, headers=headers_get)
    rest_status(req)
    list = []
    col = ['Order Num', 'Common Name', 'Status', 'Org id', 'Type', 'Expires']
    list.append(col)
    for order in req.json()['orders']:
        array = []
        array.append(str(order['id']))
        if order['certificate'].get('common_name'):
            array.append(order['certificate']['common_name'])
        else:
            array.append('N/A')
        array.append(order['status'])
        array.append(str(order['organization']['id']))
        array.append(order['product']['name'])
        if order['certificate'].get('valid_till'):
            array.append(order['certificate']['valid_till'])
        else:
            array.append('N/A')
        list.append(array)
    return list

def view_cert(ordernum):
    req_url = url + '/' + ordernum
    req = requests.get(req_url, headers=headers_get)
    rest_status(req)
    return req.json()

def new_cert(payload):
    req_url = url + '/ssl'
    req = requests.post(req_url, headers=headers_post, data=payload)
    rest_status(req)
    return req.json()

def revoke_cert(oid, comment):
    req_url = 'https://www.digicert.com/services/v2/certificate/' + oid + '/revoke'
    payload = json.dumps( { 'comments': comment } )
    req = requests.put(req_url, headers=headers_post, data=payload)
    rest_status(req)
    return req.json()

def download_cert(ordernum):
    req_url = 'https://www.digicert.com/services/v2/certificate/' + ordernum + '/download/platform'
    req = requests.get(req_url, headers=headers_get)
    rest_status(req)
    if zipfile.is_zipfile(io.BytesIO(req.content)):
        return zipfile.ZipFile(io.BytesIO(req.content))
    else:
        return req.content

def download_cert_by_format(cid, format):
    req_url = url + '/' + str(cid) + '/download/format/' + format
    req = requests.get(req_url, headers=headers_get)
    rest_status(req)
    return req.json()
# List duplicate certificates
def list_duplicates(ordernum):
    req_url =  url + '/' + ordernum + '/duplicate'
    req = requests.get(req_url, headers=headers_get)
    rest_status(req)
    return req.json()
# List all pending requests
def list_requests():
    req_url = 'https://www.digicert.com/services/v2/request'
    req = requests.get(req_url, headers=headers_get)
    rest_status(req)
    return req.json()
# View a specific pending request
def view_request(rid):
    req_url = 'https://www.digicert.com/services/v2/request/' + str(rid)
    req = requests.get(req_url, headers=headers_get)
    rest_status(req)
    return req.json()
# Update a pending request
def update_request(rid, status, comment):
    req_url = 'https://www.digicert.com/services/v2/request/' + str(rid) + '/status'
    if status == 'submitted' or 'pending' or 'approved' or 'rejected':
        payload = json.dumps({ 'status': status, 'processor_comment': comment})
        req = requests.put(req_url, headers=headers_post, data=payload)
        rest_status(req)
        return req.json()
    else:
        print('Please enter valid status. [ submitted, pending, approved, rejected ]')
