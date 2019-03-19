import argparse
import os
from configparser import ConfigParser
from pathlib import Path
from digiapi.conf import api_key, cert_lib, confd, main_conf, confd_org, confd_dom, confd_cert, keyd, page_parse, paginate
from digiapi.org import url, headers_get, headers_post, view_org, list_org, new_org, submit_org, active_org_val
from digiapi.cert import url, headers_get, headers_post, list_cert, view_cert, new_cert, revoke_cert, download_cert, download_cert_by_format, list_duplicates, list_requests, view_request, update_request

# Main ArgParse Parser
parser = argparse.ArgumentParser(prog='digiutil', add_help=True)
subparsers = parser.add_subparsers()

# Main options
parser.add_argument("--init", help="Initialize configuration scripts", action="store_true")
parser.add_argument("--init-org", help="Validate a organization", action="store_true")
parser.add_argument("--init-dom", help="Validate a domain", action="store_true")
parser.add_argument("--test", action="store_true")

# Argparse Certificate Management Sub Parser
parser_cert = subparsers.add_parser('crt')
parser_cert.add_argument("-l", "--list-cert", help="List all orders", action='store_true')
parser_cert.add_argument("-v", "--view-cert", help="View order details by id")
parser_cert.add_argument("-n", "--new-cert", help="New orde, requires csr", choices=['dv','ov', 'ev', 'cs'])
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
        pages = paginate(org_list, 4)
        org = input('Enter the id of the org you want to validate: ')
        # Get org name
        org_name = view_org(org)['name']
        # Get org validation by chosen oid
        vals = active_org_val(org)
        if vals.get('validations'):
            for val in vals['validations']:
                if val['status'] == 'active':
                    a.append(val['type'])
        print(a)
        # Add org to init.conf
        conf = Path(confd_org / str(org + '.conf'))
        p1 = ConfigParser()
        p1.read(str(main_conf.resolve()))
        p1.set('Organization Validation', str('org_' + org), str(Path(conf)))
        with open(str(main_conf.resolve()), 'w') as f:
            p1.write(f)
        # Create org entry in key.d
        key_dir = Path( keyd / org_name )
        if not os.path.exists(str(key_dir)):
            os.makedirs(str(key_dir))
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
    print('Org ' + org + ' was initialized: ' + str(conf))
# Validate domain
