from digiapi import conf
from digiapi.conf import rest_status
from digiapi.container import root_container
import requests

# Rest resources
url = 'https://www.digicert.com/services/v2/user'
headers_get = {"X-DC-DEVKEY" : conf.api_key, "Accept" : "application/json"}
headers_post = {"X-DC-DEVKEY" : conf.api_key, "Content-Type" : "application/json"}

def list_usr():
    req = requests.get(url, headers=headers_get)
    rest_status(req)
    return req.json()

def view_usr(uid):
    req_url = url + '/' + uid
    req = requests.get(req_url, headers=headers_get)
    rest_status(req)
    return req.json()

def new_usr(payload):
    req = requests.post(url, headers=headers_post, data=payload)
    rest_status(req)
    return req.json()

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

def del_usr(uid):
    req_url = url + '/' + uid
    req = requests.delete(req_url, headers= headers_get)
    rest_status(req)
    return req

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
