import argparse
import os
from configparser import ConfigParser
from pathlib import Path
from digiapi.conf import api_key, cert_lib, confd, main_conf, confd_org, confd_dom, confd_cert, keyd, page_parse, paginate
from digiapi.org import url, headers_get, headers_post, view_org, list_org, new_org, submit_org, active_org_val
from digiapi.cert import url, headers_get, headers_post, list_cert, view_cert, new_cert, revoke_cert, download_cert, download_cert_by_format, list_duplicates, list_requests, view_request, update_request
from digiapi.domain import list_domains, view_domain, submit_domain

# Main ArgParse Parser
parser = argparse.ArgumentParser(prog='digiutil', add_help=True)
subparsers = parser.add_subparsers()

# Main options
parser.add_argument("--init", help="Initialize configuration scripts", action="store_true")
parser.add_argument("--init-org", help="Validate a organization", action="store_true")
parser.add_argument("--init-dom", help="Validate a domain", action="store_true")

# Argparse Certificate Management Sub Parser
parser_cert = subparsers.add_parser('crt')
parser_cert.add_argument("-l", "--list-cert", help="List all orders", action='store_true')
parser_cert.add_argument("-v", "--view-cert", help="View order details by id")
parser_cert.add_argument("-n", "--new-cert", help="New order, requires csr", choices=['dv','ov', 'ev', 'cs'])
parser_cert.add_argument("-r", "--revoke-cert", help="Revoke order")
parser_cert.add_argument("-e", "--edit-cert", help="Edit order (reissue)")
parser_cert.add_argument("-d", "--duplicate-cert", help="Create copy of an order with a different CSR")
parser_cert.add_argument("-a", "--duplicate-list", help="List the duplicate certificates of an order")

# Argparse Domain Management Sub Parser
parser_dom = subparsers.add_parser('dom')
parser_dom.add_argument("-l", "--list-dom", help="List active domains", action="store_true")
parser_dom.add_argument("-a", "--activate-dom", help="Activate domain", action="store_true")
parser_dom.add_argument("-d", "--deactivate-dom", help="Deactivate domain", action="store_true")
parser_dom.add_argument("-s", "--submit-dom", help="Submit domain for validation", choices=['dv','ov','ev'])
parser_dom.add_argument("-dcv", help="Domain control verification", choices=['txt', 'cname', 'email', 'http'])
parser_dom.add_argument("-dns", help ="Test DNS to complete DCV", choices=['txt','cname'])
parser_dom.add_argument("-n", "--new-dom", help="New domain", action='store_true')
parser_dom.add_argument("-v", "--view-dom", help="View domain details by id")

# Argparse Organization Management Sub Parser
parser_org = subparsers.add_parser('org')
parser_org.add_argument("-l", "--list-org", help="List organizations", action="store_true")
parser_org.add_argument("-v", "--view-org", help="View details of organization by org id")
parser_org.add_argument("-s", "--submit-org", help="Submit organization for validation", choices=['ov', 'ev', 'ovcs', 'evcs', 'ds'])
parser_org.add_argument("-n", "--new-org", help="New organization", action="store_true")

# argparse Request Management Sub Parser
parser_req = subparsers.add_parser('req')
parser_req.add_argument('-l', '--list-req', help='List all pending requests', action='store_true')
parser_req.add_argument('-v', '--view-req', help='View request details')
parser_req.add_argument('-r', '--reject-req', help='Reject a pending certificate request.')
parser_req.add_argument('-a', '--approve-req', help='Approve a pending certificate request.')

# Argparse User Management Sub Parser
parser_usr = subparsers.add_parser('usr')
parser_usr.add_argument("-n", "--new-usr", help="New user account", action='store_true')
parser_usr.add_argument("-e", "--edit-usr", help="Edit user account")
parser_usr.add_argument("-v", "--view-usr", help="View existing user account")
parser_usr.add_argument("-d", "--del-usr", help="Delete user account")
parser_usr.add_argument("-l", "--list-usr", help="List user accounts", action='store_true')

# Argparse Cryptography Sub Parser
parser_crypto = subparsers.add_parser('crypto')
parser_crypto.add_argument('--new-csr', help="Create a new CSR")
parser_crypto.add_argument('--new-key', help='Create a new private key', choices=['ecc', 'rsa'])
parser_crypto.add_argument('--decode-cert', help='View encoded details in the certificate')
parser_crypto.add_argument('--decode-csr', help='View encoded details in the CSR')
parser_crypto.add_argument('--test-csr', help='Generate hash of CSR')
parser_crypto.add_argument('--test-key', help='Generate hash of private key')
parser_crypto.add_argument('--test-cert', help='Generate hash of certificate')

# Parse argument list
args = parser.parse_args()

# Initial configuration
if args.init:
    print("Running configuration scripts. This will overwrite any existing files.")
    # Collect user input
    key = input("Enter your Digicert API key: ")
    dir = Path(input("Where do you want to save everything? [./] "))
    conf = Path(dir / 'conf.d')
    file = str(Path(conf / 'init.conf'))
    # If dir exists
    if dir.exists():
        print('Directory already exists')
    # Else create dir
    else:
        os.mkdir(str(dir))
        os.mkdir(str(conf))
    # Delete existing init.conf
    if main_conf.exists():
        os.remove(str(main_conf.resolve()))
        # Create init.conf
        parser = ConfigParser()
        parser.read(file)
        parser.add_section('DigiUtil-Cli Conf')
        parser.add_section('Organization Validation')
        parser.add_section('Domain Validation')
        parser.set('DigiUtil-Cli Conf', 'api_key', key)
        parser.set('DigiUtil-Cli Conf', 'cert_lib', str(dir.resolve()))
        with open(file, "w+") as f:
            parser.write(f)
        print('init.conf was saved in: ' + str(conf.resolve()))
    else:
        # Create init.conf
        parser = ConfigParser()
        parser.read('init.conf')
        parser.add_section('DigiUtil-Cli Conf')
        parser.add_section('Organization Validation')
        parser.add_section('Domain Validation')
        parser.set('DigiUtil-Cli Conf', 'api_key', key)
        parser.set('DigiUtil-Cli Conf', 'cert_lib', str(dir))
        with open(file, 'w+') as f:
            parser.write(f)
        print('init.conf was saved in: ' + str(conf.resolve()))

# Validate org
if args.init_org:
    reval = input('Is this the FIRST time registering the org with Digicert? ')
    if reval == 'y':
        new_org()
    elif reval == 'n':
        resp = list_org('n')
        org_list = []
        col = ['Org ID', 'Org Name', 'Address', 'Activated']
        org_list.append(col)
        for org in resp["organizations"]:
            array = []
            array.append(str(org['id']))
            array.append(org['name'])
            array.append(org['address'])
            array.append(str(org['is_active']))
            org_list.append(array)
        pages = paginate(org_list, 5)
        org = input('Enter the id of the org you want to validate: ')
        # Get org name and confd path
        org_name = view_org(org)['name']
        conf = Path(confd_org / str(org + '.conf'))
        if os.path.exists(str(conf)):
            os.remove(str(conf))
        # Add org to init.conf
        p1 = ConfigParser()
        p1.read(str(main_conf.resolve()))
        p1.set('Organization Validation', str('org_' + org), str(Path(conf)))
        with open(str(main_conf.resolve()), 'w') as f:
            p1.write(f)
        # Create org entry in key.d
        key_dir = Path( keyd / org_name )
        if not os.path.exists(str(key_dir)):
            os.makedirs(str(key_dir))
        # Get active org validations
        vals = active_org_val(org)
        a = []
        if vals.get('validations'):
            for val in vals['validations']:
                # If active, set in configuration file
                if val['status'] == 'active':
                    a.append(val['type'])
        # Else submit for validation
        else:
            submit_org(org)
        # Create org.conf
        p2 = ConfigParser()
        p2.read(str(conf))
        p2.add_section('Initialized Org')
        p2.set('Initialized Org', 'id', org)
        p2.set('Initialized Org', 'name', org_name)
        p2.set('Initialized Org', 'validated_for', ', '.join(a))
        p2.set('Initialized Org', 'key_dir', str(key_dir.resolve()))
        with open(str(conf), 'w+') as f:
            p2.write(f)
    else:
        'Please choose y or n'
    # If no active validations, submit for validation
    print('Org ' + org + ' was initialized: ' + str(conf))

# Validate domain
if args.init_dom:
    print('Initializing domain...')
    # Pick from list of existing domains
    resp = list_domains()
    list = []
    col = ['Domain ID', 'Domain', 'Activated', 'Validation Status']
    list.append(col)
    for dom in resp["domains"]:
        if dom.get('validations'):
            array = []
            array.append(str(dom['id']))
            array.append(dom['name'])
            if dom['is_active'] == True:
                array.append('yes')
            else:
                array.append('no')
            for validated in dom['validations']:
                val_array = []
                val_array.append(validated['type'])
            array.append(', '.join(val_array))
            list.append(array)
        else:
            array = []
            array.append(str(dom['id']))
            array.append(dom['name'])
            if dom['is_active'] == True:
                array.append('yes')
            else:
                array.append('no')
            array.append('')
            list.append(array)
    paginate(list, 10)
    # Get domain info by did
    did = input('Which domain do you want to configure? (Use domain id) ')
    dom_resp = view_domain(did)
    # Get org.conf path
    x = str(dom_resp['organization']['id']) + '.conf'
    org_conf = Path(confd_org / x)
    # Print error if org.conf doesnt exist
    if not os.path.exists(str(org_conf)):
        print('Error: Initialize org ' + str(dom_resp['organization']['id']))
    else:
        conf = Path(confd_dom / str(did + '.conf'))
        if os.path.exists(str(conf)):
            os.remove(str(conf))
        # Add domain to init.conf
        p1 = ConfigParser()
        p1.read(str(main_conf))
        p1.set('Domain Validation', str('dom_' + did), str(Path(conf)))
        with open(str(main_conf), 'w') as f:
            p1.write(f)
        # Create domain.conf
        p2 = ConfigParser()
        p2.read(str(conf))
        p2.add_section('Initialized Domain')
        p2.set('Initialized Domain', 'id', did)
        p2.set('Initialized Domain', 'name', dom_resp['name'])
        p2.set('Initialized Domain', 'org', str(dom_resp['organization']['id']))
        p2.set('Initialized Domain', 'dcv_status', dom_resp['status'])
        # If domain is validated, set validation
        if dom['is_active'] == True:
            p2.set('Initialized Domain', 'activated', 'yes')
        # Else submit domain for validation
        else:
            p2.set('Initialized Domain', 'activated', 'no')
            submit_domain(did)
        with open(str(conf), 'w+') as f:
            p2.write(f)
        print('Domain ' + did + ' was initialized: ' + str(conf))

# List orders on account
if args.list_cert:
    try:
        resp = list_cert()
        paginate(resp,10)
    except:
        raise Exception('Unable to list certificates.')

# View a orders details
if args.view_cert:
    try:
        resp = view_cert(args.view_cert)
        paginate(resp,10)
    except:
        raise TypeError('Argument is not an integer.')

# Enroll in new certificate
if args.new_cert:
    try:
        new_cert(args.new_cert)
    except:
        raise Exception('Unable to enroll new certificate.')

# Revoke certificate
if args.revoke_cert:
    try:
        cmt = input('Why are you revoking this order? ')
        revoke_cert(args.revoke_cert, cmt)
    except:
        raise Exception('Unable to revoke certificate.')
