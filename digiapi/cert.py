from digiapi import conf
from digiapi.conf import confd_cert, rest_status, confd_org, keyd, paginate, colorize, colorize_edit, regex_test
from digiapi.org import get_active_org, view_org
from digiapi.domain import list_domains, view_domain
from digiapi.crypto import gen_csr, gen_key
from pathlib import Path
from configparser import ConfigParser
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import os
import re
import json
import requests
import zipfile
import io
import shutil

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

def view_cert(ordernum, type):
    if type == 'list':
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
    elif type == 'json':
        req_url = url + '/' + ordernum
        req = requests.get(req_url, headers=headers_get)
        rest_status(req)
        return req.json()
    else:
        raise Exception('Must choose json or list to view certificate information. ')

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
        # Saves key and csr temporarily in the org folder until order id is created
        with open(str(org_conf)) as oc:
            p = ConfigParser()
            p.read(str(org_conf))
            safe = p.get('Initialized Org', 'key_dir')
            key_path = safe + '/private.key'
            csr_path = safe + '/request.csr'
        # Generate and save private key
        alg = input('Create a ECC or RSA private key? ' )
        while not alg in ['ecc','rsa']:
            colorize('red')
            alg = input('Enter ECC or RSA: ')
            colorize_edit('reset')
        key = gen_key(alg)
        with open(key_path, 'wb+') as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
                ))
        # Generate a CSR from private key
        csr = gen_csr(key)
        # Save csr
        with open(csr_path, 'w+') as f:
            f.write(csr)
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
                'csr': csr,
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
        # Move key to new key.d
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
        print('A request to revoke order ' + cid + ' was successfully submitted on ' + resp['date'])
        colorize_edit('reset')
    return resp

def download_cert(cid):
    req_url = 'https://www.digicert.com/services/v2/certificate/' + str(cid) + '/download/platform'
    req = requests.get(req_url, headers=headers_get)
    rest_status(req)
    if zipfile.is_zipfile(io.BytesIO(req.content)):
        return zipfile.ZipFile(io.BytesIO(req.content))
    else:
        return req.content

def download_cert_by_format(cid, format):
    req_url = 'https://www.digicert.com/services/v2/certificate/' + str(cid) + '/download/format/' + format
    req = requests.get(req_url, headers=headers_get)
    rest_status(req)
    return req.content

# List duplicate certificates
def list_duplicates(ordernum):
    req_url =  url + '/' + str(ordernum) + '/duplicate'
    req = requests.get(req_url, headers=headers_get)
    rest_status(req)
    return req.json()

# Reissue existing certificate order
def reissue_cert(cid):
    # Get cid
    cert_info = view_cert(cid, 'json')
    order_no = str(cert_info['id'])
    req_url = url + '/' + order_no + '/reissue'
    # Get request org info
    org_name = cert_info['organization']['name']
    org_city = cert_info['organization']['city']
    org_state = cert_info['organization']['state']
    org_country = cert_info['organization']['country']
    oid = cert_info['organization']['id']
    # Print current information
    old_cn = str(cert_info['certificate']['common_name'])
    old_sans = ', '.join(cert_info['certificate']['dns_names'])
    colorize('blue')
    print('Current Certificate:')
    print('CN = ' + old_cn)
    print('SANs = ' + old_sans)
    colorize_edit('reset')
    # Get common name
    cn = input('Enter a new common name: ')
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
    # Load existing conf and private key if exists
    order_conf = Path( str(confd_cert) + '/' + str(order_no) + '.conf')
    org_conf = Path( str(confd_org) + '/' + str(oid) + '.conf' )
    if os.path.exists(str(order_conf)):
        with open(str(order_conf), 'r'):
            scp = ConfigParser()
            scp.read(str(order_conf))
            key_dir = scp.get('Initialized Cert', 'key_dir')
            key_path = Path( key_dir + '/' + str(order_no) + '.key')
            csr_path = Path( key_dir + '/' + str(order_no) + '.csr')
            with open(str(key_path), 'rb') as f:
                key_bytes = f.read()
                key = load_pem_private_key(key_bytes, None, default_backend())
                # Generate a CSR from private key and org info
                signed_req = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, org_country),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, org_state),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, org_city),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
                    x509.NameAttribute(NameOID.COMMON_NAME, cn),
                    ])).sign(key, hashes.SHA256(), default_backend())
                csr = str(signed_req.public_bytes(serialization.Encoding.PEM), 'utf-8')
                # Save CSR
                with open(str(csr_path), 'w+') as f:
                    f.write(csr)
    # Create new conf file
    else:
        order_keyd = Path( str(keyd) + '/' + org_name + '/' + str(order_no) + '.d' )
        with open(str(order_conf), 'w+') as f:
            scp = ConfigParser()
            scp.read(str(order_conf))
            scp.add_section('Initialized Cert')
            scp.set('Initialized Cert', 'id', str(order_no))
            scp.set('Initialized Cert', 'key_dir', str(order_keyd))
            scp.set('Initialized Cert', 'status', cert_info['status'])
            scp.write(f)
        # Generate and save private key
        alg = input('Create a ECC or RSA private key? ' )
        while not alg in ['ecc','rsa']:
            colorize('red')
            alg = input('Enter ECC or RSA: ')
            colorize_edit('reset')
        key = gen_key(alg)
        key_path = Path( str(order_keyd) + '/' + str(order_no) + '.key' )
        if not os.path.exists(str(order_keyd)):
            os.makedirs(str(order_keyd))
        with open(str(key_path), 'wb+') as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
                ))
        # Generate csr
        csr_path = Path( str(order_keyd) + '/' + str(order_no) + '.csr' )
        csr = gen_csr(key)
        with open(str(csr_path), 'w+') as f:
            f.write(csr, 'utf-8')
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
        print('Default selected: sha256')
    # Create payload
    payload = json.dumps({
      'certificate': {
        'common_name': cn,
        'dns_names': sans,
        'csr': csr,
        'signature_hash': hash_alg
      }
    })
    req = requests.post(req_url, headers=headers_post, data=payload)
    rest_status(req)
    colorize('green')
    print('Reissue for ' + cn + ' has been submitted to Digicert for processing.\n')
    colorize_edit('reset')
    return req.json()

# Request duplicate of existing certificate order
def duplicate_cert(cid):
    # Get order information and load cert conf
    try:
        info = view_cert(cid,'json')
        ordernum = info['id']
        cert_path = Path(str(confd_cert) + '/' + cid + '.conf')
        r = ConfigParser()
        r.read(str(cert_path))
        cert_keyd = r.get('Initialized Cert', 'key_dir')
    except:
        raise LookupError('Missing cert.d entry. Reissue order with --reissue-crt.')
    # Get org information to create key.d
    org_id = info['organization']['id']
    org_name = info['organization']['name']
    # Generate and save private key
    alg = input('Create a ECC or RSA private key? ' )
    while not alg in ['ecc','rsa']:
        colorize('red')
        alg = input('Enter ECC or RSA: ')
        colorize_edit('reset')
    key = gen_key(alg)
    # Generate a CSR from private key
    dup_csr = gen_csr(key)
    # Get duplicate certificate information
    dups = list_duplicates(cid)
    # If no duplicates, create folder 001
    if not dups.get('certificates'):
        dup_keyd = Path(str(cert_keyd) + '/01.d')
        os.makedirs(str(dup_keyd))
    # Else count the number of dups and create new dup folder
    else:
        count = len(dups['certificates'])
        dup_num = count + 1
        dup_keyd = Path(str(cert_keyd) + '/0' + str(dup_num) + '.d')
        if dup_keyd.exists():
            try:
                shutil.rmtree(str(dup_keyd))
            except OSError as e:
                print("Error: %s - %s." % (e.filename,e.strerror))
        os.makedirs(str(dup_keyd))
    # Write CSR and KEY to new dup folder
    key_path = Path(str(dup_keyd) + '/private.key')
    with open(str(key_path), 'wb+') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
            ))
    csr_path = Path(str(dup_keyd) + '/request.csr')
    with open(str(csr_path), 'w+') as f:
        f.write(dup_csr)
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
    else:
        print('Default chosen: pem format')
        platform = -1
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
        print('Default selected: sha256')
    # Set common name
    cn = info['certificate']['common_name']
    colorize('blue')
    print("Current common name: " + cn)
    colorize_edit('reset')
    if info['product']['name_id'] == 'ssl_multi_domain' or info['product']['name_id'] == 'ssl_ev_multi_domain':
        # Convert sans list to array
        sans = info['certificate']['dns_names']
    if info['product']['name_id'] == 'ssl_cloud_wildcard' or info['product']['name_id'] == 'ssl_wildcard':
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
    # Make payload and submit to Digicert
    payload = json.dumps({
        'certificate': {
        'common_name': cn,
        'dns_names':
            sans
        ,
        'csr': dup_csr,
        'server_platform': {
          'id': platform
        },
        'signature_hash': 'sha256'
        }
    })
    req_url = url + '/' + str(ordernum) + '/duplicate'
    req = requests.post(req_url, headers=headers_post, data=payload)
    rest_status(req)
    # Get certificate id by listing new duplicate
    ld = list_duplicates(ordernum)
    cert_id = ld['certificates'][0]['id']
    # Download based on server platform
    if format == 1:
        # Download new duplicate from Digicert
        dup_cert = download_cert_by_format(cert_id,'p7b')
        # Set filename based on server platform to p7b
        dup_cert_path = Path( str(dup_keyd) + '/cert.p7b' )
        with open(str(dup_cert_path), 'wb+') as save:
            save.write(dup_cert)
    elif format == 2:
        # Download new duplicate from Digicert
        dup_cert = download_cert_by_format(cert_id,'apache')
        # Set filename based on server platform to pem (individual pem without root)
        dup_cert_path = Path( str(dup_keyd) + '/cert.zip' )
        with open(str(dup_cert_path), 'wb+') as save:
            save.write(dup_cert)
    elif format == 3:
        # Download new duplicate from Digicert
        dup_cert = download_cert_by_format(cert_id,'pem_all')
        # Set filename based on server platform to pem bundle
        dup_cert_path = Path( str(dup_keyd) + '/cert.pem' )
        with open(str(dup_cert_path), 'wb+') as save:
            save.write(dup_cert)
    elif format == 4:
        # Download new duplicate from Digicert
        dup_cert = download_cert_by_format(cert_id,'cer')
        # Set filename based on server platform to code signing
        dup_cert_path = Path( str(dup_keyd) + '/cert.cer' )
        with open(str(dup_cert_path), 'wb+') as save:
            save.write(dup_cert)
    elif format == 5:
        # Download new duplicate from Digicert
        dup_cert = download_cert_by_format(cert_id,'default_pem')
        # Set filename based on server platform to other (individual pem including root)
        dup_cert_path = Path( str(dup_keyd) + '/cert.zip' )
        with open(str(dup_cert_path), 'wb+') as save:
            save.write(dup_cert)
    colorize('green')
    print('Duplicate successfully created in:\n' + str(dup_cert_path))
    colorize_edit('reset')

# List all pending requests
def list_requests(pages,pend):
    req_url = 'https://www.digicert.com/services/v2/request'
    reqs = requests.get(req_url, headers=headers_get)
    rest_status(reqs)
    if pages == 'y':
        list = []
        col = ['Request ID', 'Date Requested', 'Status', 'Type', 'Order ID', 'Requested By', 'Approved By']
        list.append(col)
        if pend == 'y':
            for req in reqs.json()['requests']:
                if req['status'] == 'pending':
                    array = []
                    array.append(str(req['id']))
                    array.append(req['date'])
                    array.append(req['status'])
                    array.append(req['type'])
                    array.append(str(req['order']['id']))
                    requester_fname = req['requester']['first_name']
                    requester_lname = req['requester']['last_name']
                    requester_name = requester_fname + ' ' + requester_lname
                    array.append(requester_name)
                    if req.get('processor'):
                        approver_fname = req['processor']['first_name']
                        approver_lname = req['processor']['last_name']
                        approver_name = approver_fname + ' ' + approver_lname
                        array.append(approver_name)
                    else:
                        approver_name = ' '
                        array.append(approver_name)
                    list.append(array)
                return list
        else:
            for req in reqs.json()['requests']:
                array = []
                array.append(str(req['id']))
                array.append(req['date'])
                array.append(req['status'])
                array.append(req['type'])
                array.append(str(req['order']['id']))
                requester_fname = req['requester']['first_name']
                requester_lname = req['requester']['last_name']
                requester_name = requester_fname + ' ' + requester_lname
                array.append(requester_name)
                if req.get('processor'):
                    approver_fname = req['processor']['first_name']
                    approver_lname = req['processor']['last_name']
                    approver_name = approver_fname + ' ' + approver_lname
                array.append(approver_name)
                list.append(array)
            return list
    else:
        return reqs.json()

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
    else:
        colorize('red')
        print('Please enter valid status. [ submitted, pending, approved, rejected ]')
        colorize_edit('reset')
