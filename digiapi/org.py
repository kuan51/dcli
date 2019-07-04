import requests
import json
from digiapi import conf
from digiapi.container import root_container
from digiapi.conf import rest_status, paginate
from digiapi.usr import list_usr, verified_usr

# REST resources
url = 'https://www.digicert.com/services/v2/organization'
headers_get = {"X-DC-DEVKEY" : conf.api_key, "Accept" : "application/json"}
headers_post = {"X-DC-DEVKEY" : conf.api_key, "Content-Type" : "application/json"}

# Declared Org Functions
def view_org(oid):
    req_url = url + '/' + oid
    req = requests.get(req_url, headers=headers_get)
    rest_status(req)
    return req.json()

def list_org(val,list):
    if val == 'y':
        req_url = url + '?include_validation=true'
    else:
        req_url = url
    req = requests.get(req_url, headers=headers_get)
    rest_status(req)
    if list == 'y':
        list_array = []
        col = ['Org ID', 'Org Name', 'Address', 'Activated', 'Validated For']
        list_array.append(col)
        for org in req.json()['organizations']:
            array = []
            array.append(str(org['id']))
            array.append(org['name'])
            array.append(org['address'])
            array.append(str(org['is_active']))
            vals = []
            if org.get('validations'):
                for val in org['validations']:
                    vals.append(val['type'])
            array.append(', '.join(vals))
            list_array.append(array)
        return list_array
    else:
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
      'city': city,
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
    rest_status(req)
    print('\nNew org id: ' + str(req.json()["id"]))
    return req.json()["id"]

# See active validations for an org
def active_org_val(oid):
    req_url = url + '/' + str(oid) + '/validation'
    req = requests.get(req_url, headers=headers_get)
    rest_status(req)
    return req.json()

# Get Organizations available for new orders
def get_active_org():
    req_url = 'https://www.digicert.com/services/v2/container/' + str(root_container()) + '/order/organization'
    req = requests.get(req_url, headers=headers_get)
    req.raise_for_status()
    return req.json()

# Submit organization id for validation
def submit_org(oid):
    choice = input('Submit org for OV, EV, OV CS, or EV CS? [ov/ev/cs/evcs] ')
    type = ''
    while type != 'ov' or 'ev' or 'ovcs' or 'evcs':
        if choice == 'ov':
            type = 'ov'
            payload = json.dumps({
              "validations": [
                {
                  "type": type
                }
              ]
             })
            break
        elif choice == 'ev':
            type = 'ev'
            verified_usr()
            # Craft payload for REST request
            payload = json.dumps({
              "validations": [
                {
                  "type": type,
                  "verified_users": [
                    {
                      "id": uid
                    }
                  ]
                }
              ]
             })
            break
        elif choice == 'cs':
            type = 'cs'
            verified_usr()
            # Craft payload for REST request
            payload = json.dumps({
              "validations": [
                {
                  "type": type,
                  "verified_users": [
                    {
                      "id": uid
                    }
                  ]
                }
              ]
             })
            break
        elif choice == 'evcs':
            type = 'ev_cs'
            verified_usr()
            # Craft payload for REST request
            payload = json.dumps({
              "validations": [
                {
                  "type": type,
                  "verified_users": [
                    {
                      "id": uid
                    }
                  ]
                }
              ]
             })
            break
        else:
            print('Please enter ov, ev, ovcs, or evcs.')
            choice = input('Submit org for OV, EV, OV CS, or EV CS? [ov/ev/ovcs/evcs] ')
    req_url = url + '/' + oid + '/validation'
    req = requests.post(req_url, headers=headers_post, data=payload)
    if req.status_code == 204:
        print('Org' + oid + ' has been submitted for ' + type + ' validation')
    rest_status(req)
    return req
