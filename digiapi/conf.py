import os
import itertools
from itertools import islice, tee, chain
from pathlib import Path
from configparser import SafeConfigParser

# Global variables
api_key = "[Add your Digicert API key here]"
cert_lib = Path("./")
confd = Path(cert_lib / 'conf.d')
main_conf = Path(confd / 'init.conf')
confd_org = Path(confd / 'org.d')
confd_dom = Path(confd / 'dom.d')
confd_cert = Path(confd / 'cert.d')
keyd = Path(cert_lib / 'key.d')

# Find conf.d, else create conf.d
if not os.path.exists(str(confd)):
    os.makedirs(str(confd))
    if not os.path.exists(str(confd_org)):
        os.makedirs(str(confd_org))
    if not os.path.exists(str(confd_dom)):
        os.makedirs(str(confd_dom))
    if not os.path.exists(str(confd_cert)):
        os.makedirs(str(confd_cert))
    if not os.path.exists(str(keyd)):
        os.makedirs(str(keyd))
    print('Cannot find init.conf. Use --init to configure.')
    conf = SafeConfigParser()
    conf.read('init.conf')
    conf.add_section('DigiUtil-Cli Conf')
    conf.set('DigiUtil-Cli Conf', 'api_key', api_key)
    conf.set('DigiUtil-Cli Conf', 'cert_lib', '/etc/ssl/digiutil')
# Else load init.conf
else:
    # Load init.conf
    if main_conf.exists():
        conf = SafeConfigParser()
        conf.read(str(main_conf))
        api_key = conf.get('DigiUtil-Cli Conf', 'api_key')
        cert_lib = Path(conf.get('DigiUtil-Cli Conf', 'cert_lib'))
    else:
        print('Cannot find init.conf. Use --init to configure.')
        conf = SafeConfigParser()
        conf.read('init.conf')
        conf.add_section('DigiUtil-Cli Conf')
        conf.set('DigiUtil-Cli Conf', 'api_key', api_key)
        conf.set('DigiUtil-Cli Conf', 'cert_lib', '/etc/ssl/digiutil')

# Global Functions
# Create columns for paginate function
def page_parse(data, num_col):
    i = iter(data)
    while True:
        page = list(itertools.islice(i, 0, num_col))
        if len(page):
            yield page
        else:
            return

# Print interactive output with pages
def paginate(data, num_col):
    pages = list(page_parse(data, num_col))
    pnum = 0
    while pnum < len(pages):
        widths = [max(map(len, col)) for col in zip(*pages[pnum])]
        for row in pages[pnum]:
            print("\t".join((val.ljust(width) for val, width in zip(row, widths))))
        print("\nPage " + str(pnum) + ": ")
        cursor = input('Press [n]ext, [b]ack, or [q]uit. ')
        print('-' * sum(widths))
        print('\n')
        if cursor == 'b':
            pnum -= 1
        elif cursor == 'n':
            pnum += 1
        elif cursor == 'q':
            return False
        else:
            print('Press "n", "b", or "q"')
            break

def rest_status(req):
    if req.status_code is not 200 or 201 or 202:
        resp = req.json()
        print("\n\n$$$$$$ COPY BELOW FOR SUPPORT $$$$$$")
        for msg in resp["errors"]:
            print(msg["message"])
        raise LookupError("Bad API request. Error Code: " + str(req.status_code))
