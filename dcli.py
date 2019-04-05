#!/usr/bin/python
import argparse
import os
import json
from configparser import ConfigParser
from pathlib import Path
from digiapi.conf import api_key, cert_lib, confd, main_conf, confd_org, confd_dom, confd_cert, keyd, page_parse, paginate
from digiapi.org import url, headers_get, headers_post, view_org, list_org, new_org, submit_org, active_org_val
from digiapi.cert import url, headers_get, headers_post, list_cert, view_cert, new_cert, revoke_cert, download_cert, download_cert_by_format, reissue_cert, list_duplicates, list_requests, view_request, update_request, duplicate_cert
from digiapi.domain import list_domains, view_domain, submit_domain, activate_domain, deactivate_domain
from digiapi.usr import check_api_key

def dcli():
    # Main ArgParse Parser
    parser = argparse.ArgumentParser(prog='dcli', add_help=True)
    subparsers = parser.add_subparsers(dest='cmd')

    # Main options
    parser.add_argument("--init", help="Initialize configuration scripts", action="store_true")
    parser.add_argument("--init-org", help="Validate a organization", action="store_true")
    parser.add_argument("--init-dom", help="Validate a domain", action="store_true")

    # Argparse Certificate Management Sub Parser
    parser_cert = subparsers.add_parser('crt')
    parser_cert.add_argument("-l", "--list-crt", help="List all orders", action='store_true')
    parser_cert.add_argument("-v", "--view-crt", help="View order details by id")
    parser_cert.add_argument("-n", "--new-crt", help="New order, requires csr", choices=['dv','ov', 'ev', 'cs'])
    parser_cert.add_argument("-r", "--revoke-crt", help="Revoke order")
    parser_cert.add_argument("-e", "--edit-crt", help="Edit order (reissue)")
    parser_cert.add_argument("-d", "--duplicate-crt", help="Create copy of an order with a different CSR")
    parser_cert.add_argument("-a", "--duplicate-list", help="List the duplicate certificates of an order")

    # Argparse Domain Management Sub Parser
    parser_dom = subparsers.add_parser('dom')
    parser_dom.add_argument("-l", "--list-dom", help="List active domains", action="store_true")
    parser_dom.add_argument("-a", "--activate-dom", help="Activate domain")
    parser_dom.add_argument("-d", "--deactivate-dom", help="Deactivate domain")
    parser_dom.add_argument("-s", "--submit-dom", help="Submit domain for validation")
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
    parser_usr.add_argument("-l", "--list-usr", help="List user accounts", action="store_true")
    parser_usr.add_argument("-c", "--check-api", help="Check Digicert API key for permissions.", action="store_true")

    # Argparse Cryptography Sub Parser
    parser_crypto = subparsers.add_parser('crypto')
    parser_crypto.add_argument('--new-csr', help="Create a new CSR")
    parser_crypto.add_argument('--new-key', help='Create a new private key', choices=['ecc', 'rsa'])
    parser_crypto.add_argument('--decode-crt', help='View encoded details in the certificate')
    parser_crypto.add_argument('--decode-csr', help='View encoded details in the CSR')
    parser_crypto.add_argument('--test-csr', help='Generate hash of CSR')
    parser_crypto.add_argument('--test-key', help='Generate hash of private key')
    parser_crypto.add_argument('--test-crt', help='Generate hash of certificate')

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

    # If crt subparser
    if args.cmd == 'crt':
        # List orders on account
        if args.list_crt:
            try:
                resp = list_cert()
                paginate(resp,10)
            except:
                raise Exception('Unable to list certificates.')

        # View a orders details
        if args.view_crt:
            try:
                resp = view_cert(args.view_crt, 'list')
                paginate(resp,10)
            except:
                raise TypeError('Argument is not an integer.')

        # Enroll in new certificate
        if args.new_crt:
            try:
                new_cert(args.new_crt)
            except:
                raise Exception('Unable to enroll new certificate.')

        # Revoke certificate
        if args.revoke_crt:
            try:
                cmt = input('Why are you revoking this order? ')
                revoke_cert(args.revoke_crt, cmt)
            except:
                raise Exception('Unable to revoke certificate.')

        # Edit certificate order
        if args.edit_crt:
            try:
                reissue_cert(args.edit_crt)
            except:
                raise Exception('Unable to reissue certificate.')
        # Get duplicate certificate
        if args.duplicate_crt:
            try:
                duplicate_cert(args.duplicate_crt)
            except:
                raise Exception('Unable to request duplicate certificate.')
        # List all created duplicates on an order
        if args.duplicate_list:
            try:
                resp = list_duplicates(args.duplicate_list)
                # Create pages from json
                list = []
                col = ['Commmon Name', 'Serial Number', 'Status', 'Date Issued', 'Valid Till', 'Key Size', 'Requested By']
                list.append(col)
                for i in resp['certificates']:
                    array = []
                    array.append(i['common_name'])
                    array.append(i['serial_number'])
                    array.append(i['status'])
                    array.append(i['valid_from'])
                    array.append(i['valid_till'])
                    array.append(str(i['key_size']))
                    fname = i['firstname']
                    lname = i['lastname']
                    usrname = fname + ' ' + lname
                    array.append(usrname)
                    list.append(array)
                paginate(list,10)
            except:
                raise Exception('Unable to list duplicate certificates of order ' + str(args.duplicate_list))
    # If dom subparser
    if args.cmd == 'dom':
        # List Domains
        if args.list_dom:
            try:
                resp = list_domains()
                list = []
                col = ['Domain ID','Domain Name','Parent Org','Parent Org ID','DCV Method','Ready For']
                list.append(col)
                for domain in resp['domains']:
                    if domain['is_active'] == True:
                        array = []
                        array.append(str(domain['id']))
                        array.append(domain['name'])
                        array.append(domain['organization']['name'])
                        array.append(str(domain['organization']['id']))
                        if domain.get('dcv_method'):
                            if domain['dcv_method'] == 'dns-cname-token':
                                array.append('cname')
                            elif domain['dcv_method'] == 'dns-txt-token':
                                array.append('txt')
                            elif domain['dcv_method'] == 'http-token':
                                array.append('http')
                            elif domain['dcv_method'] == 'email':
                                array.append('email')
                        else:
                            array.append('')
                        array_val = []
                        for val in domain['validations']:
                            if val['status'] == 'active':
                                array_val.append(val['type'])
                        array.append(', '.join(array_val))
                        list.append(array)
                paginate(list,10)
            except:
                raise LookupError('Unable to list domains on account.')
        # Activate domain
        if args.activate_dom:
            try:
                resp = activate_domain(args.activate_dom)
                if resp.status_code == 204:
                    print('Domain ' + str(args.activate_dom) + ' has been activated.')
            except:
                raise LookupError('Unable to activate the domain with Digicert.')
        # Deactivate domain
        if args.deactivate_dom:
            try:
                resp = deactivate_domain(args.deactivate_dom)
                if resp.status_code == 204:
                    print('Domain ' + str(args.deactivate_dom) + ' has been deactivated.')
            except:
                raise LookupError('Unable to deactivate the domain with Digicert.')
        # Submit domain for validation
        if args.submit_dom:
            try:
                resp = submit_domain(args.submit_dom)
            except:
                raise LookupError('Unable to submit domain for validation.')
    # If crt subparser
    if args.cmd == 'org':
        print('org sub parser')
    # If crt subparser
    if args.cmd == 'req':
        print('req sub parser')
    # If crt subparser
    if args.cmd == 'usr':
        # Check API Key permissions
        if args.check_api:
            try:
                resp = check_api_key()
                list = []
                col = ['Username', 'Status',  'Access Role', 'Division']
                list.append(col)
                array = []
                array.append(resp['username'])
                array.append(resp['status'])
                roles = []
                for role in resp['access_roles']:
                    roles.append(role['name'])
                array.append(', '.join(roles))
                array.append(resp['container']['name'])
                list.append(array)
                paginate(list, 10)
            except:
                raise Exception('Unable to check status of API key.')
    # If crt subparser
    if args.cmd == 'crypto':
        print('crypto sub parser')
# Run application
if __name__ == '__main__':
    dcli()
