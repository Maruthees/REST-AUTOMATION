import requests
import pytest
import json
import sys
import os
import time
from Ffile import *
#pytest -s -v --html=report.html --capture sys
#pytest -v -s --alluredir=./reports --capture sys
#allure serve ./reports


def test_TC1_booking():
    response=requests.get("https://restful-booker.herokuapp.com/booking/4")
    print(response.text)
    print(response.json())
    print(response.json()["firstname"])
    print(response.json()["bookingdates"]["checkin"])
    assert response.status_code ==200

@pytest.fixture
def test_token_post():
    payload = {
        "username": "admin",
        "password": "password123"
    }

    headers = {
        "Content-Type": "application/json"
    }

    response = requests.post("https://restful-booker.herokuapp.com/auth",headers=headers,json=payload)
    print(response.text)
    print(response.json()["token"])
    temp_tok=response.json()["token"]
    assert response.status_code == 200
    return temp_tok


def test_tc3_put(test_token_post):
    print(test_token_post)
    tok1= "token=" +test_token_post
    print(tok1)
    print(type(tok1))

    headers = {
        "Content-Type": "application/json",
        "Cookie" :tok1
         }

    payload={
    "firstname": "MARU",
    "lastname": "RENG",
    "totalprice": 111,
    "depositpaid": True,  #Json boolean is true,false ; python boolean is True , False
    "bookingdates": {
    "checkin": "2018-01-01",
    "checkout": "2018-02-02"
    },
    "additionalneeds": "Breakfast"
    }
    url_put="https://restful-booker.herokuapp.com/booking/"+str(4)
    print(url_put)
    response = requests.put(url_put, headers=headers, json=payload)
    print(response.text)
    print(response.status_code)
    assert response.status_code ==200

#
# # def test_tc3_put():
#
#     headers = {
#         "Content-Type": "application/json"
#          }
#
#     payload={
#     "firstname": "MARU",
#     "lastname": "RENG",
#     "totalprice": 111,
#     "depositpaid": True,  #Json boolean is true,false ; python boolean is True , False
#     "bookingdates": {
#     "checkin": "2018-01-01",
#     "checkout": "2018-02-02"
#     },
#     "additionalneeds": "Breakfast"
#     }
#     url_put="https://restful-booker.herokuapp.com/booking/"+"183"
#     print(url_put)
#
#     with open("../Ffil/a.json") as jsondata:
#         data=json.load(jsondata)
#         print(data.values())
#         a=data.values()
#         datat=tuple(a)
#         print(datat)
#     response = requests.put(url_put, headers=headers,auth=datat, json=payload)
#
#     print(response.text)
#     print(response.status_code)


# def test_dummy():
#     with open("../Ffil/a.json") as jsondata:
#         data=json.load(jsondata)
#         print(data.values())
#         datat=tuple(data)
#         print(datat)
#
#
# def test_json_text():
#     with open("../Ffile/f.txt") as txt:
#         data=json.load(txt)
#         print(type(data))

def test_link_put():
    headers = {
        "Content-Type": "application/json"
    }

    payload1 = {
        "id": "Ex0/6",
        "status": 2,
        "hbStatus": 0,
        "linkMode": 0
    }

    payload2 = {
        "id": "Ex0/6",
        "status": 1,
        "hbStatus": 0,
        "linkMode": 0
    }

    payload3 = {
        "id": "Ex0/2",
        "status": 2,
        "hbStatus": 0,
        "linkMode": 0
    }

    payload4 = {
        "id": "Ex0/2",
        "status": 1,
        "hbStatus": 0,
        "linkMode": 0
    }


    url_put = "https://192.168.0.153/pm/1.2/ports/status"
    response = requests.put(url_put, headers=headers,auth=('root','admin123'), json=payload1,verify=False)
    print(response.text)
    # time.sleep(0.1)
    url_put = "https://192.168.0.153/pm/1.2/ports/status"
    response = requests.put(url_put, headers=headers,auth=('root','admin123'), json=payload2,verify=False)
    print(response.text)

    url_put = "https://192.168.0.153/pm/1.2/ports/status"
    response = requests.put(url_put, headers=headers,auth=('root','admin123'), json=payload3,verify=False)
    print(response.text)

    url_put = "https://192.168.0.153/pm/1.2/ports/status"
    response = requests.put(url_put, headers=headers,auth=('root','admin123'), json=payload4,verify=False)
    print(response.text)
    # time.sleep(0.1)


def test_cmap_put():
    headers = {
        "Content-Type": "application/json"
    }

    payload1 = {
        "id": 1,
        "status": "enable"
    }

    payload2 = {
        "id": 1,
        "status": "disable"
    }


    url_put = "https://192.168.0.150/pm/1.2/configmaps/state"
    response = requests.put(url_put, headers=headers,auth=('root','admin123'), json=payload1,verify=False)
    print(response.text)

    url_put = "https://192.168.0.150/pm/1.2/configmaps/state"
    response = requests.put(url_put, headers=headers,auth=('root','admin123'), json=payload2,verify=False)
    print(response.text)