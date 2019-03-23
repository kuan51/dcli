import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

# Generate private key
def gen_key():
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
