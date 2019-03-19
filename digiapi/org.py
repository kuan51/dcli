import requests
import json
from digiapi import conf
from digiapi.container import root_container
from digiapi.conf import rest_status

# REST resources
url = 'https://www.digicert.com/services/v2/organization'
headers_get = {"X-DC-DEVKEY" : conf.api_key, "Accept" : "application/json"}
headers_post = {"X-DC-DEVKEY" : conf.api_key, "Content-Type" : "application/json"}

# Declared Org Functions
def view_org(oid):
    req_url = url + '/' + oid
    req = requests.get(req_url, headers=headers_get)
    if req.status_code is not 200 or 201 or 202:
        print(req.status_code)
        rest_status(req)
    return req.json()

def list_org(val_list):
    if val_list == 'y':
        req_url = url + '?include_validation=true'
    else:
        req_url = url
    req = requests.get(req_url, headers=headers_get)
    if req.status_code is not 200 or 201 or 202:
        print(req.status_code)
        rest_status(req)
    return req.json()

def new_org():
    # Collect org details
    print('Creating new org...')
    name = input('Enter a org name: ')
    street = input('Enter the street address: ')
    city = input('Enter the city: ')
    state = input('Enter the state/province: ')
    country = input('Enter the country: ')
    zip = input('Enter a zip code: ')
    phone = input('Enter a phone for the org: ')
    # Collect org contact details
    print('Adding a Organization contact...')
    c_fname = input('Enter the first name: ')
    c_lname = input('Enter the last name: ')
    c_job = input('Enter the job title: ')
    c_email = input('Enter the email: ')
    c_phone = input('Enter the phone: ')
    # Combine input to JSON payload
    payload = json.dumps({
      'name': name,
      'address': street,
      'zip': zip,
      'city': phone,
      'state': state,
      'country': country,
      'telephone': phone,
      'container': {
        'id': root_container()
      },
      'organization_contact': {
        'first_name': c_fname,
        'last_name': c_lname,
        'email': c_email,
        'telephone': c_phone,
      }
    })
    req = requests.post(url, headers=headers_post, data=payload)
    if req.status_code is not 200 or 201 or 202:
        print(req.status_code)
        rest_status(req)
    print('\nNew org id: ' + str(resp["id"]))
    return resp["id"]

def submit_org(payload, oid):
    req_url = url + '/' + oid + '/validation'
    req = requests.post(req_url, headers=headers_post, data=payload)
    if req.status_code is not 200 or 201 or 202:
        print(req.status_code)
        rest_status(req)
    return req

# See active validations for an org
def active_org_val(oid):
    req_url = url + '/' + str(oid) + '/validation'
    req = requests.get(req_url, headers=headers_post)
    if req.status_code is not 200 or 201 or 202:
        print(req.status_code)
        rest_status(req)
    return req.json()
