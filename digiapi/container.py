from digiapi import conf
from digiapi.conf import rest_status
import requests

# REST resources
url = 'https://www.digicert.com/services/v2/container'
headers_get = {"X-DC-DEVKEY" : conf.api_key, "Accept" : "application/json"}
headers_post = {"X-DC-DEVKEY" : conf.api_key, "Content-Type" : "application/json"}

def view_container(cid):
    endpoint = url + '/' + str(cid)
    req = requests.get(endpoint, headers=headers_get)
    rest_status(req)
    return req.json()

def list_container():
    req = requests.get(url, headers=headers_get)
    rest_status(req)
    return req.json()

def new_container(cid, name, tid):
    endpoint = url + '/' + str(cid) + '/children'
    payload = {'name': name, 'template_id': str(tid)}
    req = requests.post(endpoint, headers=headers_post, data=payload)
    rest_status(req)
    return req.json()

def list_template(cid):
    endpoint = url + '/' + str(cid) + '/template'
    req = requests.get(url, headers=headers_get)
    rest_status(req)
    return req.json()

def root_container():
    containers = list_container()
    for container in containers["containers"]:
        if container['parent_id'] == 0:
            cid = container['id']
            return cid
