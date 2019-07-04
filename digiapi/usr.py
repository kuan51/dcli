from digiapi import conf
from digiapi.conf import rest_status, paginate, colorize, colorize_edit
from digiapi.container import root_container
import requests
import json

# Rest resources
url = 'https://www.digicert.com/services/v2/user'
headers_get = {"X-DC-DEVKEY" : conf.api_key, "Accept" : "application/json"}
headers_post = {"X-DC-DEVKEY" : conf.api_key, "Content-Type" : "application/json"}

def list_usr(pages):
    req = requests.get(url, headers=headers_get)
    rest_status(req)
    resp = req.json()
    list = []
    col = ['Usr ID', 'Name', 'Email', 'Job Title']
    list.append(col)
    for usr in resp["users"]:
        array = []
        array.append(str(usr['id']))
        name = str(usr['first_name']) + ' ' + str(usr['last_name'])
        array.append(name)
        array.append(usr['email'])
        if 'job_title' in usr:
            array.append(usr['job_title'])
        else:
            array.append(" ")
        list.append(array)
    if pages == 'y':
        return list
    else:
        return req.json()

def view_usr(uid):
    req_url = url + '/' + str(uid)
    req = requests.get(req_url, headers=headers_get)
    rest_status(req)
    resp = req.json()
    list = []
    col = ['Usr ID', 'Usr Name', 'Email', 'Status', 'Has Access To']
    list.append(col)
    array = []
    array.append(str(resp['id']))
    name = str(resp['first_name']) + ' ' + str(resp['last_name'])
    array.append(name)
    array.append(resp['email'])
    array.append(resp['status'])
    temp = []
    for cont in resp['container_visibility']:
        temp.append(cont['name'])
    array.append(', '.join(temp))
    list.append(array)
    paginate(list,10)

def new_usr():
    username = input("Enter a username: ")
    # Prompt to assign user access role
    roles = access_roles()
    list = []
    col = ['Role', 'Role ID']
    list.append(col)
    array = []
    for role in roles['access_roles']:
        array.append(role['name'])
        array.append(str(role['id']))
    list.append(array)
    paginate(list,10)
    rid = input('Choose a user role by id: ')
    # Check username availability
    check = check_usr(username)
    if check['available'] == bool(1):
        f_name = input("Enter a firstname: ")
        l_name = input("Enter a lastname: ")
        email = input("Enter a email: ")
        job = input("Enter a job title: ")
        phone = input("Enter a phone number: ")
        payload = json.dumps({
          'username': username,
          'first_name': f_name,
          'last_name': l_name,
          'email': email,
          'job_title': job,
          'telephone': phone,
          'container': {
            'id': root_container()
          },
          'access_roles': [{
              'id': rid
            }]
        })
        req = requests.post(url, headers=headers_post, data=payload)
        rest_status(req)
        if req.status_code == 201:
            colorize('green')
            print('Successfully created new user. New User ID: ' + str(req.json()['id']))
            print('\n')
            colorize_edit('reset')
        else:
            colorize('red')
            print('Error: ' + str(req.status_code))
            colorize_edit('reset')
    else:
        colorize('red')
        print("Username is taken. Try a different one.\n")
        colorize_edit('reset')

def check_usr(username):
    req_url = url + '/availability/' + username
    req = requests.get(req_url, headers=headers_get)
    rest_status(req)
    return req.json()

def access_roles():
    cid = root_container()
    req_url = 'https://www.digicert.com/services/v2/container/' + str(cid) + '/role'
    req = requests.get(req_url, headers=headers_get)
    rest_status(req)
    return req.json()

def delete_usr(uid):
    req_url = url + '/' + str(uid)
    req = requests.delete(req_url, headers= headers_get)
    rest_status(req)
    if req.status_code == 204:
        colorize('green')
        print('Successfully deleted user.\n')
        colorize_edit('reset')

def verified_usr():
    # Prompt to select a verified user for the Digicert validation process
    usrs = list_usr()
    list = []
    col = ['Usr ID', 'Username', 'Email']
    list.append(col)
    for usr in usrs['users']:
        array =[]
        array.append(str(usr['id']))
        array.append(usr['username'])
        array.append(usr['email'])
        list.append(array)
    paginate(list, 10)
    uid = input("Choose a verified user for the org by their id: ")
    return uid

def check_api_key():
    req_url = url + '/me'
    req = requests.get(req_url, headers=headers_get)
    rest_status(req)
    return req.json()

def edit_usr(uid):
    req_url = url + '/' + str(uid)
    uname = input('Enter a new username: ')
    fname = input('Enter a new first name: ')
    lname = input('Enter a new last name: ')
    email = input('Enter a new email: ')
    job = input('Enter a new job title: ')
    phone = input('Enter a new phone number: ')
    payload = json.dumps({
        'username': uname,
        'first_name': fname,
        'last_name': lname,
        'email': email,
        'job_title': job,
        'telephone': phone
    })
    req = requests.put(req_url, headers=headers_post, data=payload)
    rest_status(req)
    if req.status_code == 204:
        colorize('green')
        print('Successfully updated user.\n')
        colorize_edit('reset')
