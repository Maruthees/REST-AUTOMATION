import requests,re
import pytest
import json

def clearcounter(ip):
    print(ip)
    print(''' Library called clears the counters on all ports before sending traffic  ''')
    headers = {
        "Content-Type": "application/json"
    }
    payload={
            "id":[0]
            }

    url_put = "https://" + ip + "/pm/1.2/ports/stats/clear"
    response = requests.put(url_put, headers=headers, auth=('root', 'admin123'),json=payload, verify=False)
    return response