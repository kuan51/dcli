**THIS UTILITY IS IN BETA. PLEASE SUBMIT ANY ISSUES/BUGS DISCOVERED, THANKS!**

**DigiCert Python Cli Utility README**

*This utility will seek to automate the certificate request process as best as possible. However there are limits to this process. You will need to submit your organization and domains for validation. DigiCert may require your assistance with the identity verification. If you dont hear from them within a day or so, reach out to validation@digicert.com with the order number in the subject line.*

## Requirements

1. A Digicert CertCentral account
2. An API key from above account
3. Python3

## Dependencies
You will need to install the following dependencies

1. configparser **pip install configparser**
2. requests **pip install requests**
3. cryptography **pip install cryptography**

or you can install in one step with **pip install -r requirements.txt**

## Installation

1. Download the utility to a folder where you would like to configure the application. It is recommended to use an empty folder.
2. The application can be executed as a script **./dcli.py -h** on Mac or Linux where python is already installed. If you are on windows, configure python as a system variable and then open a command prompt and run **python3.exe [filepath_to_app]/dcli.py -h**

*Refer to the following guide for help configuring python as a system variable on Windows: https://superuser.com/questions/143119/how-do-i-add-python-to-the-windows-path*

---

## Initial set up

1. Initialize the app with **--init**
2. Paste your DigiCert API key
3. Enter the directory where you want to save the files. Leave blank for the current directory (Recommended).

---

## Initializing your first org

*Use the --init-org option to submit an organization to Digicert for validation. A configuration file will also be generated for the organization in the conf.d directory. This file is crucial for the application to work. If the configuration file is accidentally deleted, you must re-initialize the organization with --init-org. Your organization must be initialized before you can request a certificate for it.*

*Digicert performs a identity verification on all orders it receives (unless it is a DV or Domain Validated order). Contact their validation department at 1-801-701-9600 option 1 if you need to expedite the approval for your organization.*

1. Create or submit an existing organization for validation by using **--init-org**
2. Enter **y** if you want to create a new organization, **n** if you want to use an existing organization.
3. Complete the form as prompted.

---

## Initializing your first domain

*The organization must be approved before creating the domain.*

*You cannot use **--init-dom** to create a new domain. Use **--new-dom** if you want to create a new domain. **--init-dom** will initialize an existing domain by creating a configuration file in conf.d and submitting the domain for validation with Digicert. Your domain must be initialized before you can request a certificate for it.*

1. Create the domain in the account with **--init-dom**.
2. Pick a domain to submit for validation by entering its domain id when prompted.
3. Complete the form as prompted.

---

## Placing your first order

*You must run **--init-org** and **--init-dom** before you can place an order for a certificate. If possible, complete the domain approval first by DNS txt or cname. See **-dns** and **-dcv**. This will allow your order to be processed faster.*

1. Once the domain and org are both 'initialized', you can begin requesting certificates with **--new-crt [ov/ev]**. It will show you a list of validated organizations ready for use. Type the org id and press enter.
3. A list of validated domains will be shown, *but you can enter any valid domain or sub-domain.* Type the common name you want to use.
4. A private will be generated. 2048 is the current minimum and 4096 is the highest. Most modern devices can support 4096 and this is the recommended choice for those security oriented. 2048 is recommended for compatibility and supporting legacy devices.
5. A CSR will also be generated for your order. Enter the country, state/province, and city as prompted.
6. Choose a signature hash algorithm. *sha256* is a good default, but it can be increased to *sha512* for the security oriented.
7. Pick how long the certificate is valid for. 1 or 2 years. Use option 3 for a custom expiration date with the format *YYYY-MM-DD*.
8. Choose a file format. Choose *p7b* for Windows, *pem* for Apache,  *pem bundle* for nginx or tomcat. Select *other* if you are unsure.
