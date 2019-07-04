from digiapi.conf import regex_test, colorize, colorize_edit, get_ctry_code
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from asn1crypto import pem
from OpenSSL import crypto
from OpenSSL.crypto import _lib, _ffi, X509
import hashlib
import base64

# Generate private key
def gen_key(alg):
    if alg == 'rsa':
        print('Generating new private key')
        size = int(input('Choose a bit size between [2048-4096]: '))
        while not size >= 2048 and size <= 4096:
            print('Choose 2048, 3072, or 4096.')
            size = int(input(''))
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=size,
            backend=default_backend()
        )
    elif alg == 'ecc':
        curve = input('Use a p256, p384, or p521 curve? ')
        while not curve in ['p256','p384','p521']:
            colorize('red')
            curve = input('Use a p256, p384, or p521 curve? ')
            colorize_edit('reset')
        if curve == 'p256':
            key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        elif curve == 'p384':
            key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        elif curve == 'p521':
            key = ec.generate_private_key(ec.SECP521R1(), default_backend())
    return key

def gen_csr(key):
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
    ])).add_extension(
        # Define SANs
        x509.SubjectAlternativeName([
        x509.DNSName(u"mysite.com"),
        x509.DNSName(u"www.mysite.com"),
        x509.DNSName(u"subdomain.mysite.com"),
    ]),
    critical=False,
    # Sign the CSR with key
    ).sign(key, hashes.SHA256(), default_backend())
    return str(csr.public_bytes(serialization.Encoding.PEM), 'utf-8')

def gen_custom_csr(alg):
    # Generate private key
    key = gen_key(alg)
    with open('private.key','xb') as sf:
        sf.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
            ))
    # Compile custom csr info
    try:
        ctry = input('What country are you located in: ')
        ctry_code = get_ctry_code(ctry)
    except:
        raise LookupError('Unable to find matching country code for ' + ctry)
    st = input('What locality are you located in: ')
    city = input('What city are you located in: ')
    org = input('What organization is the request for (Example, Inc): ')
    cn = input('Enter a common name (example.com): ')
    while not regex_test.match(cn):
        colorize('red')
        print(cn + ' is not a valid common name.')
        colorize_edit('reset')
        cn = input('Enter a common name (example.com): ')
    # Get array of SANs
    test = input('Enter SANs? [y/n]: ')
    while not test in [ 'y', 'n']:
        print('Choose y or n')
        test = input('Enter SANs? [y/n]: ')
    if test == 'y':
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
        csr_sans = []
        for san in sans:
            string = x509.DNSName("(%s)" % san)
            csr_sans.append(string)
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, ctry_code ),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, st ),
            x509.NameAttribute(NameOID.LOCALITY_NAME, city ),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org ),
            x509.NameAttribute(NameOID.COMMON_NAME, cn ),
        ])).add_extension(
            # Define SANs
            x509.SubjectAlternativeName(csr_sans),
        critical=False,
        # Sign the CSR with key
        ).sign(key, hashes.SHA256(), default_backend())
    else:
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, ctry_code ),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, st ),
            x509.NameAttribute(NameOID.LOCALITY_NAME, city ),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org ),
            x509.NameAttribute(NameOID.COMMON_NAME, cn ),
        ])).add_extension(
            # Define SANs
            x509.SubjectAlternativeName(''),
        critical=False,
        # Sign the CSR with key
        ).sign(key, hashes.SHA256(), default_backend())
    with open('request.csr', 'xt') as sf:
        sf.write(str(csr.public_bytes(serialization.Encoding.PEM), 'utf-8'))

def decode_cert(cert_path):
    # Open certificate and deserialize
    with open(str(cert_path),'rb') as rf:
        pem_obj = rf.read()
        if pem.detect(pem_obj):
            type, _, _ = pem.unarmor(pem_obj)
            # Determine type of certificate
            if type == "PKCS7":
                pkcs7 = crypto.load_pkcs7_data(crypto.FILETYPE_PEM,pem_obj)
                certs = get_certificates(pkcs7)
                count = 0
                for cert in certs:
                    pem_cert = x509.load_pem_x509_certificate(cert, default_backend())
                    # Print cert issued to
                    colorize('green')
                    print('Issued to: (Chain ' + str(count) + ')')
                    count += 1
                    colorize_edit('reset')
                    print(pem_cert.subject.rfc4514_string())
                    print("Serial No: " + str(pem_cert.serial_number))
                    print("Fingerprint: " + str(base64.b64encode(pem_cert.fingerprint(hashes.SHA256())), 'utf-8'))
                    print("Valid from: " + str(pem_cert.not_valid_before))
                    print("Valid to: " + str(pem_cert.not_valid_after))
                    print("Signature hash algorithm: " + pem_cert.signature_hash_algorithm.name)
                    # Print issued by
                    colorize('green')
                    print('Issued by: ')
                    colorize_edit('reset')
                    print(pem_cert.issuer.rfc4514_string())
                    print('\n')

            elif type == "CERTIFICATE":
                cert = x509.load_pem_x509_certificate(pem_obj, default_backend())
                # Print cert issued to
                colorize('green')
                print('Issued to: ')
                colorize_edit('reset')
                print(cert.subject.rfc4514_string())
                print("Serial No: " + str(cert.serial_number))
                print("Fingerprint: " + str(base64.b64encode(cert.fingerprint(hashes.SHA256())), 'utf-8'))
                print("Valid from: " + str(cert.not_valid_before))
                print("Valid to: " + str(cert.not_valid_after))
                print("Signature hash algorithm: " + cert.signature_hash_algorithm.name)
                # Print issued by
                colorize('green')
                print('Issued by: ')
                colorize_edit('reset')
                print(cert.issuer.rfc4514_string())
            else:
                raise TypeError('Not a PEM or PKCS7 file.')

def get_certificates(self):
        """
        https://github.com/pyca/pyopenssl/pull/367/files#r67300900

        Returns all certificates for the PKCS7 structure, if present. Only
        objects of type ``signedData`` or ``signedAndEnvelopedData`` can embed
        certificates.

        :return: The certificates in the PKCS7, or :const:`None` if
            there are none.
        :rtype: :class:`tuple` of :class:`X509` or :const:`None`
        """
        certs = _ffi.NULL
        if self.type_is_signed():
            certs = self._pkcs7.d.sign.cert
        elif self.type_is_signedAndEnveloped():
            certs = self._pkcs7.d.signed_and_enveloped.cert

        pycerts = []
        for i in range(_lib.sk_X509_num(certs)):
            pycert = X509.__new__(X509)
            pycert._x509 = _lib.sk_X509_value(certs, i)
            pem_cert = crypto.dump_certificate(crypto.FILETYPE_PEM,pycert)
            pycerts.append(pem_cert)

        if not pycerts:
            return None
        return tuple(pycerts)
