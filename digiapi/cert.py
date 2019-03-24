from digiapi import conf
from digiapi.conf import confd_cert, rest_status, confd_org, keyd, paginate, colorize, colorize_edit
from digiapi.org import get_active_org, view_org
from digiapi.domain import list_domains, view_domain
from digiapi.crypto import gen_csr, gen_key
from pathlib import Path
from configparser import ConfigParser
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import os
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
    resp = req.json()
    list = []
    col = ['Order Num', 'Common Name',  'Org','Expires', 'Sig Hash', 'Key Size', 'Status']
    list.append(col)
    array = []
    array.append(str(resp['id']))
    array.append(resp['certificate']['common_name'])
    array.append(str(resp['certificate']['organization']['id']))
    array.append(resp['certificate']['valid_till'])
    array.append(resp['certificate']['signature_hash'])
    array.append(str(resp['certificate']['key_size']))
    array.append(resp['status'])
    list.append(array)
    return list

def new_cert(type):
    # Pick org
    orgs = get_active_org()
    list = []
    col = ['Org id', 'Org Name', 'Display Name']
    list.append(col)
    for org in orgs['organizations']:
        array = []
        array.append(str(org['id']))
        array.append(org['name'])
        array.append(org['display_name'])
        list.append(array)
    paginate(list,10)
    oid = input('Pick organization id: ')
    # Get org name with oid
    org_name = view_org(oid)['name']
    # Test common name
    regex_test = re.compile('(\w+|-|\*)+(\.{1})(\w+|-)+')
    cn = input('Enter a common name: ')
    while not regex_test.match(cn):
        cn = input('Enter a valid common name: ')
    # Get array of SANs
    sans = []
    print('Type Subject Alternate Name and press enter (Enter d when done):')
    while 1 == 1:
        san = input('')
        if san == 'd':
            break
        elif not regex_test.match(san):
            print(san + ' is not a valid SAN')
        else:
            sans.append(san)
    # Create new entry in key.d for order
    x = oid + '.conf'
    org_conf = Path(confd_org / x)
    if not os.path.exists(str(org_conf)):
        print('Error: Initialize org ' + oid)
    else:
        with open(str(org_conf)) as oc:
            p = ConfigParser()
            p.read(str(org_conf))
            safe = p.get('Initialized Org', 'key_dir')
            key_path = safe + '/private.key'
            csr_path = safe + '/request.csr'
        # Generate and save private key
        key = gen_key()
        with open(key_path, 'wb+') as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
                ))
        # Generate a CSR from private key
        country = input('Enter the country: ')
        state = input('Enter the state/province: ')
        city = input('Enter the city: ')
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, city),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            ])).sign(key, hashes.SHA256(), default_backend())
        # Save csr
        with open(csr_path, 'wb+') as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))
        # Choose signature hash
        algs = ['1] sha256', '2] sha384', '3] sha512']
        print('Signature hash algorithms')
        print(*algs, sep='\t')
        alg = int(input('Choose an algorithm [1-3]: '))
        if alg == 1:
            hash_alg = 'sha256'
        elif alg == 2:
            hash_alg = 'sha384'
        elif alg == 3:
            hash_alg = 'sha512'
        else:
            hash_alg = 'sha256'
            print('Default delected: sha256')
        # Choose validity period
        val_periods = ['1] 1 year', '2] 2 year', '3] Custom Expiration']
        print(*val_periods, sep='\t')
        val_period = int(input('Choose certificate lifetime [1-3]: '))
        if val_period == 1:
            time = 1
        elif val_period == 2:
            time = 2
        else:
            time = 3
            custom = input('Pick a custom certificate lifetime in format YYYY-MM-DD: ')
            regx = re.compile('([0-9]{4}(\-){1}([0-9]){2}(\-){1}([0-9]){2})')
            while not regx.match(custom):
                print('Incorrect format. Try again.')
                custom = input('Pick a custom certificate lifetime in format YYYY-MM-DD: ')
        # List options for file format
        formats = ['1] p7b', '2] pem', '3] pem bundle', '4] code signing', '5] other']
        print('Possible file formats: ')
        print(*formats, sep='\t')
        format = int(input('Choose a format [1-5]: '))
        # Choose server platform
        if format == 1:
            platform = 10
        elif format == 2:
            platform = 2
        elif format == 3:
            platform = 45
        elif format == 4:
            platform = 55
        elif format == 5:
            platform = -1
        # Set server platform to Sun Java for code signing
        elif args.new_cert == 'cs':
            platform = 55
        else:
            print('Default chosen: pem format')
            platform = -1
        # If custom expiraion, include correct payload
        if time == 1 or time == 2:
            payload = {
              'certificate': {
                'common_name': cn,
                'dns_names': sans,
                'csr': str(csr.public_bytes(serialization.Encoding.PEM), 'utf-8'),
                'server_platform': {
                  'id': int(platform)
                },
                'signature_hash': hash_alg
              },
              'organization': {
                'id': int(oid)
              },
              'validity_years': int(time),
              'product': {
                'type_hint': type
              }
            }
        else:
            print('Time == 3')
            payload = {
              'certificate': {
                'common_name': cn,
                'dns_names': sans,
                'csr': str(csr.public_bytes(serialization.Encoding.PEM), 'utf-8'),
                'server_platform': {
                  'id': int(platform)
                },
                'signature_hash': hash_alg
              },
              'organization': {
                'id': int(oid)
              },
              'validity_years': 1,
              'custom_expiration_date': custom,
              'product': {
                'type_hint': type
              }
            }
        payload_data = json.dumps(payload)
        req_url = url + '/ssl'
        req = requests.post(req_url, headers=headers_post, data=payload_data)
        rest_status(req)
        if req.json()['requests'][0]['status'] == 'approved':
            # Move key to new order.d
            with open(str(org_conf)):
                p = ConfigParser()
                p.read(str(org_conf))
                safe = p.get('Initialized Org', 'key_dir')
                temp_key = safe + '/private.key'
            dir = Path(safe + '/' + str(req.json()['id']) + '.d')
            if not os.path.exists(str(dir)):
                os.makedirs(str(dir))
            key_name = Path(str(str(req.json()['id']) + '.key'))
            saved_key = Path( dir / key_name )
            with open(temp_key, 'r') as tk:
                t = tk.read()
            with open(str(saved_key), 'w+') as sk:
                sk.write(t)
            os.remove(temp_key)
            # Move csr to order.d
            temp_csr = Path( safe + '/request.csr')
            saved_csr = Path( dir / Path(str(str(req.json()['id']) + '.csr')) )
            with open(str(temp_csr), 'r') as tc:
                tcsr = tc.read()
            with open(str(saved_csr), 'w+') as sc:
                sc.write(tcsr)
            os.remove(str(temp_csr))
            # Create pending req in cert.d
            conf_name = str(req.json()['id']) + '.conf'
            cert_conf = Path( confd_cert / conf_name )
            with open(str(cert_conf), 'w+') as cc:
                scp = ConfigParser()
                scp.read(str(cert_conf))
                scp.add_section('Initialized Cert')
                scp.set('Initialized Cert', 'id', str(req.json()['id']))
                scp.set('Initialized Cert', 'key_dir', str(dir))
                scp.set('Initialized Cert', 'status', 'pending')
                scp.write(cc)
            print('Successfully placed new order # ' + str(req.json()['id']) + '\n')
    return req.json()

def revoke_cert(cid, comment):
    req_url = 'https://www.digicert.com/services/v2/order/certificate/' + cid + '/revoke'
    payload = json.dumps( { 'comments': comment } )
    req = requests.put(req_url, headers=headers_post, data=payload)
    rest_status(req)
    resp = req.json()
    if resp.get('status'):
        colorize('cyan')
        print('A request to revoke order ' + cid + ' was successfully submitted on ' + resp['status'])
        colorize_edit('reset')
    return resp

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
