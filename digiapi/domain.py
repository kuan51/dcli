from digiapi import conf
from digiapi.container import root_container
from digiapi.conf import rest_status, paginate, regex_test, colorize, colorize_edit
import requests
import json

# Rest resources
url = 'https://www.digicert.com/services/v2/domain'
headers_get = {"X-DC-DEVKEY" : conf.api_key, "Accept" : "application/json"}
headers_post = {"X-DC-DEVKEY" : conf.api_key, "Content-Type" : "application/json"}

def list_domains():
    req_url = url + '?container_id=' + str(root_container()) + '&include_validation=true'
    req = requests.get(req_url, headers=headers_get)
    rest_status(req)
    return req.json()

def view_domain(did,type):
    if type == 'json':
        req_url = url + '/' + did + '?include_dcv=true&include_validation=true'
        req = requests.get(req_url, headers=headers_get)
        rest_status(req)
        return req.json()
    else:
        req_url = url + '/' + did + '?include_dcv=true&include_validation=true'
        req = requests.get(req_url, headers=headers_get)
        rest_status(req)
        resp = req.json()
        list = []
        col = ['ID', 'Name', 'Status', 'DCV Method', 'Org ID']
        list.append(col)
        array = []
        array.append(str(resp['id']))
        array.append(resp['name'])
        array.append(resp['status'])
        if resp['dcv_method'] == 'email':
            array.append('email')
        elif resp['dcv_method'] == 'dns-txt-token':
            array.append('txt')
        elif resp['dcv_method'] == 'dns-cname-token':
            array.append('cname')
        elif resp['dcv_method'] == 'http-token':
            array.append('http')
        array.append(str(resp['organization']['id']))
        list.append(array)
        return list

def activate_domain(did):
    req_url = url + '/' + did + '/activate'
    req = requests.put(req_url, headers=headers_get)
    rest_status(req)
    return req

def deactivate_domain(did):
    req_url = url + '/' + did + '/deactivate'
    req = requests.put(req_url, headers=headers_get)
    rest_status(req)
    return req

def submit_domain(did):
    choices = ['ov','ev','ovcs','evcs']
    type = input('Validate for [ov, ev, ovcs, evcs]? ')
    while type not in choices:
        colorize('red')
        choices = input('Please choose one of the following validation types: [ov, ev, ovcs, evcs] ')
        colorize_edit('reset')
        type = choices
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
    if req.status_code == 204:
        colorize('green')
        print('Domain submitted for ' + type + ' validation.\n')
        colorize_edit('reset')
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
    rest_status(req)
    if req.status_code == 200:
        return req.json()

def dcv_emails(did):
    req_url = url + '/' + did + '/dcv/emails'
    req = requests.get(req_url, headers=headers_get)
    rest_status(req)
    if req.status_code == 200:
        return req.json()

def test_dns(did, method, token):
    req_url = url + '/' + did + '/dcv/cname'
    payload = json.dumps({'dcv_method': method, 'token': token})
    req = requests.put(req_url, headers=headers_post, data=payload)
    rest_status(req)
    if req.status_code == 200:
        return req.json()

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
    rest_status(req)
    if req.status_code == 201:
        return req.json()

def do_dcv(type):
    # List pending/expired domains
    resp = list_domains()
    list = []
    col = ['Domain ID','Domain Name','Status']
    list.append(col)
    for dom in resp['domains']:
        if dom.get('validations'):
            for val in dom['validations']:
                if val.get('dcv_status'):
                    if val['dcv_status'] == 'expired':
                        array = []
                        array.append(dom['id'])
                        array.append(dom['name'])
                        array.append(val['dcv_status'])
                        list.append(array)
                    elif val['dcv_status'] == 'pending':
                        array = []
                        array.append(dom['id'])
                        array.append(dom['name'])
                        array.append(val['dcv_status'])
                        list.append(array)
    print('Showing Pending/Expired DCV\'s: ')
    paginate(list,10)
    # Prompt user for domain id to submit DCV for
    did = input('\nEnter Domain ID: ')
    # Choose DCV option by switch value
    if type == 'email':
        # Change domain to new DCV
        payload = json.dumps({
            'dcv_method': 'email'
            })
        choose_dcv(did, payload)
        # Get domain control emails
        emails = dcv_emails(did)
        colorize('green')
        print('\nEmails were sent to:\n')
        colorize_edit('reset')
        for email in emails['base_emails']:
            print(' ' + email)
        for email in emails['whois_emails']:
            print(' ' + email)
        print('\n')
    if type == 'txt':
        # Change domain to new DCV
        payload = json.dumps({
            'dcv_method': 'dns-txt-token'
            })
        resp = choose_dcv(did, payload)
        dcv = resp['dcv_token']
        colorize('green')
        print('Create a TXT record in your domains DNS: \n')
        colorize_edit('reset')
        print('Random String: ' + dcv['token'])
        print('Status: ' + dcv['status'])
        print('String Expires On: ' + dcv['expiration_date'])
        print('\n')
    if type == 'cname':
        # Change domain to new DCV
        payload = json.dumps({
            'dcv_method': 'dns-cname-token'
            })
        resp = choose_dcv(did, payload)
        dcv = resp['dcv_token']
        colorize('green')
        print('Create a CNAME record in your DNS: \n')
        colorize_edit('reset')
        print('Random String: ' + dcv['token'])
        print('Target: ' + dcv['verification_value'])
        print('Domain Status: ' + dcv['status'])
        print('Example: ' + dcv['token'] + '.[yourdomain].com -> ' + dcv['verification_value'])
        print('\n')
