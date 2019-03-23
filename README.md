**DigiCert Python Cli Utility README**

*This utility will seek to automate the certificate request process as best as possible. However there are limits to this process. You will need to submit your organization and domains for validation. DigiCert may require your assistance with the identity verification. If you dont hear from them within a day or so, reach out to support@digicert.com with the order number in the subject line.*

## Requirements

1. A digicert account with API access
2. An API key from above account
3. Python3

## Dependencies
You will need to install the following dependencies using pip:

1. configparser **pip install configparser**
2. requests **pip install requests**
3. cryptography **pip install cryptography**

---

## Initial set up

1. Initialize the app with **--init**
2. Paste your DigiCert API key
3. Enter the directory where you want to save the files. Leave blank for the current directory.

---

## Placing your first order

If possible, complete the domain approval first by DNS txt or cname. See **-dns** and **-dcv**. This will allow your order to be processed faster.
Also submit your organization for approval with **--new-org**.

1. Once the domain and org validation is complete you can submit a new order and instantly complete the request with **--init-cert**.
2. Run the app with **--new-cert**. It will show you a list of validated organizations ready for use. Type the org id and press enter.
3. A list of validated domains will be shown, *but you can enter any valid domain or sub-domain.* Type the common name you want to use.
4. A private will be generated. 2048 is the current minimum and 4096 is the highest. Most modern devices can support 4096 and this is the recommended choice for those security oriented.
5. A CSR will also be generated for your order. Enter the country, state/province, and city as prompted.
6. Choose a signature hash algorithm. *sha256* is a good default, but it can be increased to *sha512* for the security oriented.
7. Pick how long the certificate is valid for. 1 or 2 years. Use 3 for a custom expiration date with the format *YYYY-MM-DD*.
8. Choose a file format. Choose *p7b* for Windows and *other* for Mac/Linux.

---

## Initializing your first org

1. Create your organization with **--new-org**. Fill in the info as prompted and copy the new org id.
2. Submit the organization for validation with **--submit-org [ov/ev/cs/evcs]**. Paste the org id.
3. Choose a user to be the organization contact.
4. Initialize the org with **--init-org**.

---

## Initializing your first domain

*The organization must be approved before creating the domain.*

1. Create the domain in the account with **--new-dom**.
2. Choose whether to submit for OV or EV.
3. Enter the org id to submit the domain under.
4. Choose the DCV method with **-dcv [email/txt/cname/http]**.
5. Enter the domain id to submit. Copy the unique string if you chose txt, cname, or http.
6. Complete the DCV. If you chose txt, cname, or http, you can test for approval with **--dns**
7. Initialize the domain with **--init-dom**
