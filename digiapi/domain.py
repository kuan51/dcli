from digiapi import conf
from digiapi.container import root_container
from digiapi.conf import rest_status
import requests
import json

# Rest resources
url = 'https://www.digicert.com/services/v2/domain'
headers_get = {"X-DC-DEVKEY" : conf.api_key, "Accept" : "application/json"}
headers_post = {"X-DC-DEVKEY" : conf.api_key, "Content-Type" : "application/json"}

def list_domains():
    req_url = url + '?container_id=' + str(root_container()) + '&include_validation=true'
    req = requests.get(req_url, headers=headers_get)
    req.raise_for_status()
    return req.json()

def view_domain(did):
    req_url = url + '/' + did + '?include_dcv=true&include_validation=true'
    req = requests.get(req_url, headers=headers_get)
    req.raise_for_status()
    return req.json()

def activate_domain(did):
    req_url = url + '/' + did + '/activate'
    req = requests.put(req_url, headers=headers_get)
    req.raise_for_status()
    return req

def deactivate_domain(did):
    req_url = url + '/' + did + '/deactivate'
    req = requests.put(req_url, headers=headers_get)
    req.raise_for_status()
    return req

def submit_domain(did):
    choice = input('Submit domain for OV, EV, OV CS, or EV CS? [ov/ev/ovcs/evcs] ')
    type = ''
    while type != 'ov' or 'ev' or 'ovcs' or 'evcs':
        if choice == 'ov':
            type = 'ov'
            break
        elif choice == 'ev':
            type = 'ev'
            break
        elif choice == 'ovcs':
            type = 'cs'
        elif choice == 'evcs':
            type = 'ev_cs'
        else:
            print('Please enter ov, ev, ovcs, or evcs.')
            choice = input('Submit domain for OV, EV, OV CS, or EV CS? [ov/ev/ovcs/evcs] ')
    payload = json.dumps({
      "validations": [
        {
          "type": type,
          "user": {
            "id": did
          }
        }
      ]
    })
    req_url = url + '/' + did + '/validation'
    req = requests.post(req_url, headers=headers_post, data=payload)
    rest_status(req)
    return req

def dcv_methods():
    req_url = url + '/dcv/method'
    req = requests.get(req_url, headers=headers_get)
    req.raise_for_status()
    resp = req.json()
    list = []
    for method in resp['methods']:
        list.append(method['name'])
    text = ', '.join(list)
    return text

def choose_dcv(did, payload):
    req_url = url + '/' + did + '/dcv/method'
    req = requests.put(req_url, headers=headers_post, data=payload)
    if req.status_code == 200:
        return req.json()
    else:
        print(req.json())
        req.raise_for_status()

def dcv_emails(did):
    req_url = url + '/' + did + '/dcv/emails'
    req = requests.get(req_url, headers=headers_get)
    if req.status_code == 200:
        return req.json()
    else:
        print('Error ' + req.status_code + ': ' + req.json())
        req.raise_for_status()

def test_dns(did, method, token):
    req_url = url + '/' + did + '/dcv/cname'
    payload = json.dumps({'dcv_method': method, 'token': token})
    req = requests.put(req_url, headers=headers_post, data=payload)
    if req.status_code == 200:
        return req.json()
    else:
        print('Error ' + str(req.status_code) + ': ' + str(req.json()))
        req.raise_for_status()

def new_domain(name, oid, type):
    payload = json.dumps({
      'name': name,
      'organization': {
        'id': oid
      },
      'validations': [{
          'type': type
        }]
    })
    req = requests.post(url, headers=headers_post, data=payload)
    if req.status_code == 201:
        return req.json()
    else:
        print('Error ' + str(req.status_code) + ': ' + str(req.json()))
        req.raise_for_status()
