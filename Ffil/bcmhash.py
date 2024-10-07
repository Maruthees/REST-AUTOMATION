import requests,re
import pytest
import json

def hashfunc(ip):
    print(ip)
    print(''' This TC sets IPv4 protocol & Ipv6 next-header GLOBAL POLICY  ''')
    headers = {
        "Content-Type": "application/json"
    }
    payload = {
        "type": 0,
        "value": [
            15, 16
        ]
    }

    url_post = "https://" + ip + "/pm/1.2/portgroup/portchannel/hash"
    response = requests.post(url_post, headers=headers, auth=('root', 'admin123'), json=payload, verify=False)
    return response
