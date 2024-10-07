import requests,re
import pytest
import json
import sys
import os
import time
import pysnmp
from pysnmp.hlapi import *
import paramiko,pexpect
from Ffil.counter import *
from Ffil.bcmhash import *

## IMPORTANT FOR EXECUTION
## 1) Test case test_reboot should be enabled for versions earlier than 12.7.0
## 2) Test case test_configsave should be enabled for versions <= 12.7.0
## 3) Test case  test_tc9_remotemgmtv6 for v6 version we should check the PC IPv6 address and replace accordingly
#     3.143 PC IPv6 for negative check test_tc23_remotemgmtv6_regexp
## 4) Assign IPv6 address static to DUT's such that they are in SLAAC network 9001:db7:1:2:: prefix


dut1='192.168.2.65'               #BCM DUT IP
dut2='192.168.2.236'              #3299 DUT IP
dut3='192.168.2.50'              #3808E DUT IP

dut1v6='9001:db7:1:2:1:1:1:1'    # BCM DUT v6 IP Prefix 64
dut2v6='9001:db7:1:2:1:1:1:2'   # 3299 DUT v6 IP Prefix 64
dut3v6='9001:db7:1:2:1:1:1:3'   # 3808 DUT V6 IP Prefix 64

@pytest.fixture(params=[dut3])
def test_ip(request):
    print(request.param)
    return request.param

@pytest.fixture(params=[dut3v6])
def testv6_ip(request):
    print(request.param)
    return request.param

@pytest.fixture
def test_dut1():
    ip=dut1
    return ip
    print(ip)


@pytest.fixture
def test_dut2():
    ip=dut2
    return ip
    print(ip)

@pytest.fixture
def test_dut3():
    ip=dut3
    return ip
    print(ip)

def test_tc1_version_beforeupgrade(test_ip):
    ip = test_ip
    print(ip)
    headers = {
        "Content-Type": "application/json"
    }
    url_get = "https://" + ip + "/pm/1.2/system"
    response = requests.get(url_get, headers=headers, auth=('root', 'admin123'), verify=False)
    print("The version running before upgrade is = ", response.json()["response"]["webObjects"][0]["firmversion"])


def test_tc2_enable_autosave(test_ip):
    print("\n This TC ENABLES AUTOSAVE \n")
    ip=test_ip
    headers = {
        "Content-Type": "application/json"
    }
    payload = {
        "configAutoSave": "enable"
    }

    url_post="https://"+ip+"/pm/1.2/system"
    response = requests.post(url_post, headers=headers,auth=('root','admin123'),json=payload,verify=False)
    print(response.text)
    time.sleep(10)
    val=response.json()["respMsg"]
    assert val=="Configuration successful"




def test_tc3_adduser_beforeupgrade(test_ip):
    ip=test_ip
    print("BEFORE UPGRADE \n")
    print("On a freshboot system we are adding new users \n")
    headers = {
        "Content-Type": "application/json"
    }
    payload1 = {
        "id": 0,
        "username": "qa1",
        "password": "Admin123!",
        "action": "setUser"
    }
    payload2 = {
        "id": 0,
        "username": "qa2",
        "password": "Admin123!",
        "action": "setUser"
    }
    payload3 = {
        "id": 0,
        "username": "qa3",
        "password": "Admin123!",
        "action": "setUser"
    }
    url_post="https://"+ip+"/pm/1.2/users"
    response = requests.post(url_post, headers=headers,auth=('root','admin123'),json=payload1,verify=False)
    print(response.text)
    response = requests.post(url_post, headers=headers,auth=('root','admin123'),json=payload2,verify=False)
    print(response.text)
    response = requests.post(url_post, headers=headers,auth=('root','admin123'),json=payload3,verify=False)
    print(response.text)


def test_tc4_group_beforeupgrade(test_ip):
    ip=test_ip
    headers = {
        "Content-Type": "application/json"
    }

    payload1 = {
        "id": 0,
        "name": "GP1",
        "desc": "string",
        "portsPriv": 1,
        "pgPriv": 1,
        "vtPriv": 1,
        "filterMacPriv": 1,
        "filterUdbPriv": 1,
        "filterPriv": 1,
        "configmapPriv": 1,
        "bypassPriv": 1,
        "systemPriv": 1,
        "rmonPriv": 1,
        "userPriv": 1,
        "tacacsPriv": 1,
        "radiusPriv": 1,
        "syslogPriv": 1,
        "snmpPriv": 1,
        "sntpPriv": 1,
        "mplsPriv": 1,
        "startupConfigsavePriv": 1,
        "flashsavePriv": 1,
        "remotesavePriv": 1
    }

    payload2 = {
        "id": 0,
        "name": "GP2",
        "desc": "string",
        "portsPriv": 0,
        "pgPriv": 0,
        "vtPriv": 0,
        "filterMacPriv": 0,
        "filterUdbPriv": 0,
        "filterPriv": 0,
        "configmapPriv": 0,
        "bypassPriv": 1,
        "systemPriv": 1,
        "rmonPriv": 1,
        "userPriv": 1,
        "tacacsPriv": 1,
        "radiusPriv": 1,
        "syslogPriv": 1,
        "snmpPriv": 1,
        "sntpPriv": 1,
        "mplsPriv": 1,
        "startupConfigsavePriv": 1,
        "flashsavePriv": 1,
        "remotesavePriv": 1
    }

    url_post = "https://"+ip+"/pm/1.2/groups"
    response = requests.post(url_post, headers=headers, auth=('root', 'admin123'), json=payload1, verify=False)
    print(response.text)

    response = requests.post(url_post, headers=headers, auth=('root', 'admin123'), json=payload2, verify=False)
    print(response.text)


def test_tc5_adduser_group(test_ip):
    ip=test_ip

    headers = {
        "Content-Type": "application/json"
    }

    payload1 = {
        "groupid": 2,
        "userlist": ["2"]
    }

    payload2 = {
        "groupid": 3,
        "userlist": ["3"]
    }

    url_put = "https://"+ip+"/pm/1.0/groups/adduser"


    response = requests.put(url_put, headers=headers, auth=('root', 'admin123'), json=payload1, verify=False)
    print(response.text)

    response = requests.put(url_put, headers=headers, auth=('root', 'admin123'), json=payload2, verify=False)
    print(response.text)
    assert response.status_code == 200


def test_tc6_add_tacacs(test_ip):
    headers = {
        "Content-Type": "application/json"
    }

    payload = {
        "ipAddressType": "IPv4",
        "ipAddress": "192.168.2.132",
        "primaryServer": "Yes",
        "singleConnection": "Yes",
        "sharedSecret": "testing123",
        "serverPort": 49,
        "serverTimeout": 5
    }
    ip=test_ip
    print(ip)
    url_post = "https://"+ip+"/pm/1.2/system/remote-authentication/tacacs"
    print(url_post)
    response = requests.post(url_post, headers=headers, auth=('root', 'admin123'), json=payload, verify=False)
    print(response.text)
    assert response.status_code == 200


def test_tc7_add_radius(test_ip):
    headers = {
        "Content-Type": "application/json"
    }

    payload = {
        "ipAddressType": "IPv4",
        "ipAddress": "192.168.2.48",
        "primaryServer": "Yes",
        "sharedSecret": "testing123",
        "serverPortNumber": 1812,
        "responseTimeout": 4,
        "retryCount": 3,
        "type": "UDP"
    }
    ip=test_ip
    url_post = "https://"+ip+"/pm/1.2/system/remote-authentication/radius"
    print(url_post)

    response = requests.post(url_post, headers=headers, auth=('root', 'admin123'), json=payload, verify=False)
    print(response.text)
    assert response.status_code == 200

def test_tc7A_syslogtcp_udp(test_ip):
    ip=test_ip
    print(ip)
    username = 'root'
    password = 'admin123'
    session = paramiko.SSHClient()
    session.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    session.connect(ip, username=username, password=password)
    connection = session.invoke_shell()
    connection.send("c t \n")
    time.sleep(1)
    connection.send("logging-server 134 ipv4 192.168.2.48  \n")
    time.sleep(1)
    connection.send("logging-server 134 ipv4 192.168.3.122 port  10514 tcp \n")
    time.sleep(1)
    connection.send("end \n")
    time.sleep(1)
    output = connection.recv(65535)
    print(output)
    connection.close


def test_tc_7B_syslogserver_clear():
    c1 = r"sudo sh -c 'echo > /var/log/syslog'"
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect('192.168.2.48', username='qa', password='admin123')
    print("TC logs into a PC where syslog server is cleared\n")
    stdin, stdout, stderr = client.exec_command(c1, get_pty=True)
    stdin.write('admin123\n')
    stdin.flush()

    for line in stdout:
        print(line)
    client.close()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect('192.168.3.122', username='qa', password='admin123')
    print("TC logs into a PC where syslog server is cleared\n")
    stdin, stdout, stderr = client.exec_command(c1, get_pty=True)
    stdin.write('admin123\n')
    stdin.flush()
    for line in stdout:
        print(line)
    client.close()


def test_tc8_remotemgmtv4(test_ip):
    ip=test_ip
    headers = {
        "Content-Type": "application/json"
    }

    payload1 = {
        "ipv4_address": "172.17.1.0",
        "ipv4_prefix_len": 24,
        "allowed_services": [
            "snmp",
            "http",
            "https",
            "ssh",
            "scp",
            "tftp"
        ]
    }

    payload2 = {
        "ipv4_address": "192.168.2.48",
        "ipv4_prefix_len": 32,
        "allowed_services": [
            "snmp",
            "http",
            "https",
            "ssh",
            "scp",
            "tftp"
        ]
    }

    payload3 = {
        "ipv4_address": "192.168.2.132",
        "ipv4_prefix_len": 32,
        "allowed_services": [
            "snmp",
            "http",
            "https",
            "ssh",
            "scp",
            "tftp"
        ]
    }

    payload4 = {
        "ipv4_address": "192.168.3.122",
        "ipv4_prefix_len": 32,
        "allowed_services": [
            "snmp",
            "http",
            "https",
            "ssh",
            "scp",
            "tftp"
        ]
    }

    url_post = "https://"+ip+"/pm/1.2/system/remote-manager/ipv4"
    print(url_post)


    response = requests.post(url_post, headers=headers, auth=('root', 'admin123'), json=payload1, verify=False)
    print(response.text)


    response = requests.post(url_post, headers=headers, auth=('root', 'admin123'), json=payload2, verify=False)
    print(response.text)

    response = requests.post(url_post, headers=headers, auth=('root', 'admin123'), json=payload3, verify=False)
    print(response.text)


    response = requests.post(url_post, headers=headers, auth=('root', 'admin123'), json=payload4, verify=False)
    print(response.text)

    assert response.status_code == 200




def test_tc9_remotemgmtv6(test_ip):
    ip = test_ip
    headers = {
        "Content-Type": "application/json"
    }


    ## Ipv6 of 192.168.2.48 PC

    payload = {
        "ipv6_address": "9001:db7:1:2:a618:4ed:cae8:42b1",
        "ipv6_prefix_len": 128,
        "allowed_services": [
            "snmp",
            "http",
            "https",
            "ssh",
            "scp",
            "tftp"
        ]
    }
    url_post = "https://" + ip + "/pm/1.2/system/remote-manager/ipv6"
    print(url_post)
    response = requests.post(url_post, headers=headers, auth=('root', 'admin123'), json=payload, verify=False)
    print(response.text)
    assert response.status_code == 200




def test_tc10_user_snmp(test_ip):
    ip=test_ip
    print(ip)
    username = 'root'
    password = 'admin123'
    #ip = '192.168.2.65'

    session = paramiko.SSHClient()
    session.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    session.connect(ip, username=username, password=password)
    connection = session.invoke_shell()
    connection.send("c t \n")
    time.sleep(1)
    connection.send("snmp user qa1  \n")
    time.sleep(1)
    connection.send("auth HMAC-MD5 \n")
    time.sleep(1)
    connection.send("admin123\n")
    time.sleep(1)
    connection.send("priv DES-CBC \n")
    time.sleep(1)
    connection.send("admin123\n")
    connection.send("storage-type nonvolatile  \n")
    connection.send("end \n")
    time.sleep(1)
    connection.send("c t \n")
    time.sleep(1)
    connection.send("snmp group qa1 user qa1 security-model v3  \n")
    time.sleep(1)
    connection.send("snmp access  qa1 v3 priv read iso write iso notify iso \n")
    time.sleep(1)
    connection.send("end \n")
    time.sleep(1)
    output = connection.recv(65535)
    print(output)
    connection.close

def test_tc11_snmp(test_ip):
    print(test_ip)
    ip=test_ip
    print(ip)
    authentication = UsmUserData(
        userName='qa1',
        authKey='admin123',
        authProtocol=usmHMACMD5AuthProtocol,
        privKey='admin123',
        privProtocol=usmDESPrivProtocol
    )

    iterator = getCmd(
        SnmpEngine(),
        authentication,
        # CommunityData('PUBLIC'),
        UdpTransportTarget((ip, 161)),
        ContextData(),
        ObjectType(ObjectIdentity('1.3.6.1.2.1.1.4.0')),
        ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0'))

    )

    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    #print(varBinds)

    for varBind in varBinds:  # SNMP response contents
        print(' = '.join([x.prettyPrint() for x in varBind]))

# def test_firmware_upgrade(test_ip):
#     ip=test_ip
#     print(''' This TC performs upgrade and ensure to have full permission for image file''')
#     headers = {
#         "Content-Type": "application/json"
#     }
#
#     payload = {
#         "fwUpgradeType": "system",
#         "transferMode": "scp",
#         "username": "qa",
#         "password": "admin123",
#         "ipversion": 1,
#         "ip": "192.168.2.48",
#         "filename": "/home/qa/Downloads/iss-update-img-BCM-release-iss-12.10.0-rc3.bin"
#     }
#     #time.sleep(30)
#     url_post = "https://"+ip+"/pm/1.2/fwupgrade/remote"
#     response = requests.post(url_post, headers=headers, auth=('root', 'admin123'), json=payload, verify=False)
#     print(response.text)
#     time.sleep(800)
#     assert response.status_code == 200


def test_tc11A_mpls_filtering_BCM(test_dut1):
    ip = test_dut1
    print(ip)
    print(''' This TC reserves MPLS tunnel mode and L2-Ipv4-L4  standard template ''')
    headers = {
        "Content-Type": "application/json"
    }

    payload = {
        "tunnelmode": "mpls",
        "filteringaction": "none",
        "optimizeHBFilter": "disable",
        "selectedIngressQualifierTemplates": ["L2-IPv4-L4"]
    }

    url_post = "https://" + ip + "/pm/1.2/resourcesreservation"
    response = requests.post(url_post, headers=headers, auth=('root', 'admin123'), json=payload, verify=False)
    print(response.text)

    assert response.status_code == 200

    with open(r"C:\Users\LENOVO\PycharmProjects\REST-AUTOMATION\Ffil\filter.json") as txt:
        payload1 = json.load(txt)
        print(payload1)

    url_post = "https://" + ip + "/pm/1.2/configmaps"
    response = requests.post(url_post, headers=headers, auth=('root', 'admin123'), json=payload1, verify=False)
    print(response.text)

    assert response.status_code == 200



#Enable this TC for versions where AUTOSAVE is not enabled , for firmwares before 12.8.0
@pytest.mark.skip(reason="just testing skip")
def test_configsave(test_ip):
    ip=test_ip
    print(ip)
    headers = {
        "Content-Type": "application/json"
              }
    payload= {
	     "saveType": 4,
	     "downgrade": 0
      }
    url_post = "https://"+ip+"/pm/1.2/system/config/save"
    print(url_post)
    response = requests.post(url_post, headers=headers, auth=('root', 'admin123'),json=payload, verify=False)
    print(response.text)



def test_tc12_firmware_upgradeBCM(test_dut1):
    ip = test_dut1
    print(ip)
    print(''' This TC performs upgrade and ensure to have full permission for image file''')
    headers = {
        "Content-Type": "application/json"
    }

    payload = {
        "fwUpgradeType": "system",
        "transferMode": "scp",
        "username": "qa",
        "password": "admin123",
        "ipversion": 1,
        "ip": "192.168.2.48",
        "filename": "/home/qa/Downloads/restmigration/iss-update-img-BCM-release-iss-12.10.0-rc9.bin"
    }
    # time.sleep(30)
    url_post = "https://" + ip + "/pm/1.2/fwupgrade/remote"
    response = requests.post(url_post, headers=headers, auth=('root', 'admin123'), json=payload, verify=False)
    print(response.text)
    time.sleep(800)
    assert response.status_code == 200


def test_tc13_firmware_upgrade3299(test_dut2):
    ip = test_dut2
    print(''' This TC performs upgrade and ensure to have full permission for image file''')
    headers = {
        "Content-Type": "application/json"
    }

    payload = {
        "fwUpgradeType": "system",
        "transferMode": "scp",
        "username": "qa",
        "password": "admin123",
        "ipversion": 1,
        "ip": "192.168.2.48",
        "filename": "/home/qa/Downloads/restmigration/firmware-MVL-ARM-release-iss-12.10.0-rc9.img"
    }
    # time.sleep(30)
    url_post = "https://" + ip + "/pm/1.2/fwupgrade/remote"
    response = requests.post(url_post, headers=headers, auth=('root', 'admin123'), json=payload, verify=False)
    print(response.text)
    time.sleep(600)
    assert response.status_code == 200


def test_tc14_firmware_upgrade3808(test_dut3):
    ip = test_dut3
    print(''' This TC performs upgrade and ensure to have full permission for image file''')
    headers = {
        "Content-Type": "application/json"
    }

    payload = {
        "fwUpgradeType": "system",
        "transferMode": "scp",
        "username": "qa",
        "password": "admin123",
        "ipversion": 1,
        "ip": "192.168.2.48",
        "filename": "/home/qa/Downloads/restmigration/iss-update-img-MVL-release-iss-12.10.0-rc43.bin"
    }
    # time.sleep(30)
    url_post = "https://" + ip + "/pm/1.2/fwupgrade/remote"
    response = requests.post(url_post, headers=headers, auth=('root', 'admin123'), json=payload, verify=False)
    print(response.text)
    time.sleep(800)
    assert response.status_code == 200


#Enable this TC for versions where reboot will not happen after firmware upgrade versions <=12.7.0
@pytest.mark.skip(reason="just testing skip")
def test_reboot(test_ip):
    ip=test_ip
    print(ip)
    headers = {
        "Content-Type": "application/json"
    }
    url_post = "https://"+ip+"/pm/1.2/system/reboot"
    print(url_post)
    response = requests.post(url_post, headers=headers, auth=('root', 'admin123'), verify=False)
    print(response.text)
    v=response.json()["respMsg"]
    assert v=="The system will reboot , Please wait upto 5 minutes before logging back in!"


###### After FIRMWARE UPGRADE #############


def test_tc15_version_after_upgrade(test_ip):
    ip = test_ip
    print(ip)
    headers = {
        "Content-Type": "application/json"
    }
    url_get = "https://" + ip + "/pm/1.2/system"
    response = requests.get(url_get, headers=headers, auth=('root', 'admin123'), verify=False)
    print("The version running before upgrade is = ", response.json()["response"]["webObjects"][0]["firmversion"])





def test_tc15A_mpls_traffic_send(test_dut1):
        # Clear counters on BCM device then send traffic from PC and check the input & output counters
        print(test_dut1)
        response = clearcounter(test_dut1)
        assert response.status_code == 200

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect('192.168.3.143', username='user', password='admin123')
        print("TC logs into a PC from where we can send mpls traffic \n")
        c1=r"sudo tcpreplay --intf1 enp10s0f0 Maruthees/Packets/mplsinput.pcap"
        print(c1)
        stdin,stdout,stderr = client.exec_command(c1,get_pty=True)
        stdin.write('admin123\n')
        stdin.flush()
        for line in stdout:
                 print(line)
                 pattern = "\s*(Failed packets:            0)\s*"
                 match = re.search(pattern, line, re.DOTALL)
                 if match != None:
                     print(match.group(1))
                     x=match.group(1)

        assert x=='Failed packets:            0'


def test_tc15B_traffic_counter_BCM(test_dut1):
    ip = test_dut1
    print(ip)
    print(''' This TC checks the input & output counters ''')
    headers = {
        "Content-Type": "application/json"
    }

    url_get = "https://" + ip + "/pm/1.2/ports/0/34/stats"
    response = requests.get(url_get, headers=headers, auth=('root', 'admin123'), verify=False)
    print(response.text)

    url_get1 = "https://" + ip + "/pm/1.2/ports/0/30/stats"
    response1 = requests.get(url_get1, headers=headers, auth=('root', 'admin123'), verify=False)
    print(response1.text)

    assert response.json()["response"]["webObjects"][0]["HCInUcastPkts"] == response1.json()["response"]["webObjects"][0]["HCOutUcastPkts"]

    print("\n Input packets = ",response.json()["response"]["webObjects"][0]["HCInUcastPkts"])
    print("\n Output packets = ",response1.json()["response"]["webObjects"][0]["HCOutUcastPkts"])


def test_tc15C_clear_traffic_counter_BCM(test_dut1):
    ip = test_dut1
    print(ip)
    print(''' This TC clears the counters on all ports before sending traffic  ''')
    headers = {
        "Content-Type": "application/json"
    }
    payload = {
        "id": [0]
    }

    url_put = "https://" + ip + "/pm/1.2/ports/stats/clear"
    response = requests.put(url_put, headers=headers, auth=('root', 'admin123'), json=payload, verify=False)
    print(response.text)
    assert response.status_code == 200


def test_tc15D_delete_cmapall(test_dut1):
    ip = test_dut1
    print(ip)
    print(''' This TC deletes all cmap ''')
    headers = {
        "Content-Type": "application/json"
    }
    payload = {
        "id": [0]
    }

    url_del = "https://" + ip + "/pm/1.2/configmaps"
    response = requests.delete(url_del, headers=headers, auth=('root', 'admin123'), json=payload, verify = False)
    print(response.text)
    assert response.status_code == 200



def test_tc15E_PORTGROUP_BCM(test_dut1):

    print("1) Library is called to set the global hash policy to IPv4-protocol & V6-Next-header")
    response=hashfunc(test_dut1)
    assert response.status_code == 200
    ip = test_dut1
    print("2) Port-channel is created")
    headers = {
        "Content-Type": "application/json"
    }
    #port-channel ports taken from bcmportgroup.json file
    with open(r"C:\Users\LENOVO\PycharmProjects\REST-AUTOMATION\Ffil\bcmportgroup.json") as txt:
        payload = json.load(txt)

    url_post = "https://"+ ip +"/pm/1.2/portgroup"
    print(url_post)
    response = requests.post(url_post, headers=headers, auth=('root', 'admin123'),json=payload, verify=False)
    print(response.text)
    assert response.status_code == 200

    print(" 3) Cmap with port-channel is created")
    with open(r"C:\Users\LENOVO\PycharmProjects\REST-AUTOMATION\Ffil\portgroupcmap.json") as txt:
        payload1 = json.load(txt)

    url_post = "https://" + ip + "/pm/1.2/configmaps"
    response = requests.post(url_post, headers=headers, auth=('root', 'admin123'), json=payload1, verify=False)
    print(response.text)

    assert response.status_code == 200

def test_tc15F_BCMLB_traffic_send(test_dut1):
        # Clear counters on BCM device then send traffic from PC and check the input & output counters
        print(test_dut1)
        response = clearcounter(test_dut1)
        assert response.status_code == 200

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect('192.168.3.143', username='user', password='admin123')
        print("TC logs into a PC from where we can send sum of Ipv4protocol & Ipv6 nextheader packets \n")
        c1 = r"sudo tcpreplay --intf1 enp10s0f0 Maruthees/Packets/bcmlbhash.pcap"
        print(c1)
        stdin, stdout, stderr = client.exec_command(c1, get_pty=True)
        stdin.write('admin123\n')
        stdin.flush()
        for line in stdout:
            print(line)
            pattern = "\s*(Failed packets:            0)\s*"
            match = re.search(pattern, line, re.DOTALL)
            if match != None:
                print(match.group(1))
                x = match.group(1)

        assert x == 'Failed packets:            0'


def test_tc15E_BCMLB_traffic_check(test_dut1):
    ip=test_dut1
    with open(r"C:\Users\LENOVO\PycharmProjects\REST-AUTOMATION\Ffil\bcmportgroup.json") as txt:
        port = json.load(txt)

    p1=port["portid"][0]
    p2=port["portid"][1]


    P1=p1.lstrip("Ex0/")
    P2=p2.lstrip("Ex0/")


    print(''' TC checks the loadbalanced output counters ''')
    headers = {
        "Content-Type": "application/json"
    }

    url_get = "https://" + ip + "/pm/1.2/ports/0/"+P1+"/stats"
    response = requests.get(url_get, headers=headers, auth=('root', 'admin123'), verify=False)
    port1=response.json()["response"]["webObjects"][0]["HCOutUcastPkts"]
    print("P1 port %s has count of %s packets"%(p1,port1))


    url_get = "https://" + ip + "/pm/1.2/ports/0/"+P2+"/stats"
    response = requests.get(url_get, headers=headers, auth=('root', 'admin123'), verify=False)
    port2=response.json()["response"]["webObjects"][0]["HCOutUcastPkts"]
    print("P2 port %s has count of %s packets"%(p2,port2))

    assert(int(port1) and int(port2)  > 1)



def test_tc15F_PORTGROUP_3808E(test_dut3):

    ip = test_dut3
    print(" 1) Port-channel is created")
    headers = {
        "Content-Type": "application/json"
    }
    #port-channel ports taken from marvelportgroup.json file
    with open(r"C:\Users\LENOVO\PycharmProjects\REST-AUTOMATION\Ffil\marvelportgroup.json") as txt:
        payload = json.load(txt)

    url_post = "https://"+ ip +"/pm/1.2/portgroup"
    print(url_post)
    response = requests.post(url_post, headers=headers, auth=('root', 'admin123'),json=payload, verify=False)
    print(response.text)
    assert response.status_code == 200

    print(" 2) Cmap with port-channel is created")
    with open(r"C:\Users\LENOVO\PycharmProjects\REST-AUTOMATION\Ffil\3808Ecmap.json") as txt:
        payload1 = json.load(txt)

    url_post = "https://" + ip + "/pm/1.2/configmaps"
    response = requests.post(url_post, headers=headers, auth=('root', 'admin123'), json=payload1, verify=False)
    print(response.text)

    assert response.status_code == 200

def test_tc15G_3808EMPLS_LB_traffic_send(test_dut3):
        # Clear counters on BCM device then send traffic from PC and check the input & output counters
        print(test_dut3)
        response = clearcounter(test_dut3)
        assert response.status_code == 200

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect('192.168.3.143', username='user', password='admin123')
        print("TC logs into a PC from where we can send MPLS label stacked traffic  \n")
        c1 = r"sudo tcpreplay --intf1 enp10s0f1 Maruthees/Packets/mplslthreepog.pcap"
        print(c1)
        stdin, stdout, stderr = client.exec_command(c1, get_pty=True)
        stdin.write('admin123\n')
        stdin.flush()
        for line in stdout:
            print(line)
            pattern = "\s*(Failed packets:            0)\s*"
            match = re.search(pattern, line, re.DOTALL)
            if match != None:
                print(match.group(1))
                x = match.group(1)

        assert x == 'Failed packets:            0'


def test_tc15H_3808E_traffic_check(test_dut3):
    ip = test_dut3
    with open(r"C:\Users\LENOVO\PycharmProjects\REST-AUTOMATION\Ffil\marvelportgroup.json") as txt:
        port = json.load(txt)

    p1 = port["portid"][0]
    p2 = port["portid"][1]

    P1 = p1.lstrip("Ex0/")
    P2 = p2.lstrip("Ex0/")

    print(''' TC checks the loadbalanced output counters ''')
    headers = {
        "Content-Type": "application/json"
    }

    url_get = "https://" + ip + "/pm/1.2/ports/0/" + P1 + "/stats"
    response = requests.get(url_get, headers=headers, auth=('root', 'admin123'), verify=False)
    port1 = response.json()["response"]["webObjects"][0]["HCOutUcastPkts"]
    print("P1 port %s has count of %s packets" % (p1, port1))

    url_get = "https://" + ip + "/pm/1.2/ports/0/" + P2 + "/stats"
    response = requests.get(url_get, headers=headers, auth=('root', 'admin123'), verify=False)
    port2 = response.json()["response"]["webObjects"][0]["HCOutUcastPkts"]
    print("P2 port %s has count of %s packets" % (p2, port2))

    assert (int(port1) and int(port2) >= 1)


def test_tc15I_PORTGROUP_3299(test_dut2):

    ip = test_dut2
    print(" 1) Port-channel is created")
    headers = {
        "Content-Type": "application/json"
    }
    #port-channel ports taken from 3299portgroup.json file
    with open(r"C:\Users\LENOVO\PycharmProjects\REST-AUTOMATION\Ffil\3299portgroup.json") as txt:
        payload = json.load(txt)

    url_post = "https://"+ ip +"/pm/1.2/portgroup"
    print(url_post)
    response = requests.post(url_post, headers=headers, auth=('root', 'admin123'),json=payload, verify=False)
    print(response.text)
    assert response.status_code == 200

    print(" 2) Cmap with port-channel is created")
    with open(r"C:\Users\LENOVO\PycharmProjects\REST-AUTOMATION\Ffil\3299cmap.json") as txt:
        payload1 = json.load(txt)

    url_post = "https://" + ip + "/pm/1.2/configmaps"
    response = requests.post(url_post, headers=headers, auth=('root', 'admin123'), json=payload1, verify=False)
    print(response.text)

    assert response.status_code == 200

def test_tc15J_3299MPLS_LB_traffic_send(test_dut2):
        # Clear counters on BCM device then send traffic from PC and check the input & output counters
        print(test_dut2)
        response = clearcounter(test_dut2)
        assert response.status_code == 200

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect('192.168.3.143', username='user', password='admin123')
        print("TC logs into a PC from where we can send MPLS label stacked traffic to 3299  \n")
        c1 = r"sudo tcpreplay --intf1 enp10s0f0 Maruthees/Packets/mplslthreepog.pcap"
        print(c1)
        stdin, stdout, stderr = client.exec_command(c1, get_pty=True)
        stdin.write('admin123\n')
        stdin.flush()
        for line in stdout:
            print(line)
            pattern = "\s*(Failed packets:            0)\s*"
            match = re.search(pattern, line, re.DOTALL)
            if match != None:
                print(match.group(1))
                x = match.group(1)

        assert x == 'Failed packets:            0'


def test_tc15K_3299_traffic_check(test_dut2):
    ip = test_dut2
    with open(r"C:\Users\LENOVO\PycharmProjects\REST-AUTOMATION\Ffil\3299portgroup.json") as txt:
        port = json.load(txt)

    p1 = port["portid"][0]
    p2 = port["portid"][1]

    P1 = p1.lstrip("Ex0/")
    P2 = p2.lstrip("Ex0/")

    print(''' TC checks the loadbalanced output counters ''')
    headers = {
        "Content-Type": "application/json"
    }

    url_get = "https://" + ip + "/pm/1.2/ports/0/" + P1 + "/stats"
    response = requests.get(url_get, headers=headers, auth=('root', 'admin123'), verify=False)
    port1 = response.json()["response"]["webObjects"][0]["HCOutUcastPkts"]
    print("P1 port %s has count of %s packets" % (p1, port1))

    url_get = "https://" + ip + "/pm/1.2/ports/0/" + P2 + "/stats"
    response = requests.get(url_get, headers=headers, auth=('root', 'admin123'), verify=False)
    port2 = response.json()["response"]["webObjects"][0]["HCOutUcastPkts"]
    print("P2 port %s has count of %s packets" % (p2, port2))

    assert (int(port1) and int(port2) > 1)




def test_tc16_tacacs_set(test_ip):
    print("TC after restoration sets Login Method as Tacacs & Local\n")
    ip = test_ip

    headers = {
        "Content-Type": "application/json"
    }

    payload = {
        "sshState": "enable",
        "login_authentication_mode": "Tacacs and Local",
        "httpsport": 443,
        "hstsmode": "disable",
        "hstsMaxAge": 0
    }

    url_post = "https://" + ip + "/pm/1.2/system/management-if"
    print(url_post)

    response = requests.post(url_post, headers=headers, auth=('root', 'admin123'), json=payload, verify=False)
    print(response.text)
    assert response.status_code == 200


def test_tc17_tacacs_check(test_ip):
    print("TACACS user jane is checked from server running at 192.168.2.132 PC\n")
    ip = test_ip

    headers = {
        "Content-Type": "application/json"
    }
    payload = {
        "username": "jane",
        "password": "admin123"
    }
    url_post = "https://"+ip+"/pm/1.2/login"
    print(url_post)
    response = requests.post(url_post, headers=headers, json=payload, verify=False)
    print(response.text)
    assert response.status_code == 200

def test_tc18_tacacs_negative_check(test_ip):
    ip = test_ip
    print("Negative TC- TACACS invalid user checked from server running at 192.168.2.132 PC \n")
    headers = {
        "Content-Type": "application/json"
    }
    payload = {
        "username": "nouser",
        "password": "admin123"
    }
    url_post = "https://"+ip+"/pm/1.2/login"
    print(url_post)
    response = requests.post(url_post, headers=headers, json=payload, verify=False)
    print(response.text)
    assert response.status_code == 401


def test_tc19_radius_set(test_ip):
    ip = test_ip
    print("Login method is changed to Radius & LOCAL \n")
    headers = {
        "Content-Type": "application/json"
    }
    payload = {
        "sshState": "enable",
        "login_authentication_mode": "Radius and Local",
        "httpsport": 443,
        "hstsmode": "disable",
        "hstsMaxAge": 0
    }

    url_post = "https://"+ip+"/pm/1.2/system/management-if"
    print(url_post)
    response = requests.post(url_post, headers=headers, auth=('root', 'admin123'), json=payload, verify=False)
    print(response.text)
    assert response.status_code == 200


def test_tc20_radius_check(test_ip):
    ip = test_ip
    print("RADIUS user jaackradius is checked from server running at 192.168.2.48 PC\n")
    headers = {
        "Content-Type": "application/json"
    }
    payload = {
        "username": "jackradius",
        "password": "admin123"
    }
    url_post = "https://"+ip +"/pm/1.2/login"
    print(url_post)
    response = requests.post(url_post, headers=headers, json=payload, verify=False)
    print(response.text)
    assert response.status_code == 200

def test_tc21_radius_negative_check(test_ip):
    ip = test_ip
    print("Negative TC- RADIUS invalid user checked from server running at 192.168.2.132 PC \n")
    headers = {
        "Content-Type": "application/json"
    }
    payload = {
        "username": "Rafa",
        "password": "admin123"
    }
    url_post = "https://"+ip +"/pm/1.2/login"
    print(url_post)
    response = requests.post(url_post, headers=headers, json=payload, verify=False)
    print(response.text)
    assert response.status_code == 401
#
# def test_remotemgmt_check():
#     import paramiko
#
#     client = paramiko.SSHClient()
#     client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#     client.connect('192.168.2.48', username='qa', password='admin123')
#     stdin, stdout, stderr = client.exec_command('ping -c 5 192.168.2.65')
#
#     for line in stdout:
#         print(line)
#
#     client.close()
#
#     client = paramiko.SSHClient()
#     client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#     client.connect('192.168.3.143', username='user', password='admin123')
#     client.exec_command('sssh-keygen -f "/home/user/.ssh/known_hosts" -R 192.168.2.65')
#     stdin, stdout, stderr = client.exec_command('ssh root@192.168.2.65')
#
#     for line in stderr:
#         print(line)
#
#     stdin, stdout, stderr = client.exec_command('snmpget -v2c -c PUBLIC 192.168.2.65 1.3.6.1.2.1.31.1.1.1.10 ')
#     for line in stderr:
#         print(line)
#
#     client.close()


def test_tc22_remotemgmtv4_regexp(test_ip):
    ip=test_ip
    c1='ping -c 5 '+ip
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect('192.168.2.48', username='qa', password='admin123')
    print("TC logs into a PC which is allowed for all services to DUT and PING is CHECKED\n")
    stdin, stdout, stderr = client.exec_command(c1)

    for line in stdout:
        print(line)
        pattern = '(.*\s+)(0% packet loss).*'
        match = re.search(pattern, line, re.DOTALL)
        if match != None:
            print(match.group(2))
            x=match.group(2)
    assert x=='0% packet loss'

    client.close()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect('192.168.3.143', username='user', password='admin123')
    print("TC logs into a PC which is not allowed for Remotemgmt and SSH connection is checked\n ")
    e1='''ssh-keygen -f "/home/user/.ssh/known_hosts" -R '''+ip
    print(e1)
    stdin, stdout, stderr = client.exec_command(e1)
    for line in stderr:
        print(line)

    c2='ssh root@'+ip
    stdin, stdout, stderr = client.exec_command(c2)

    for line in stderr:
        print(line)
        pattern = '(ssh:.*:) (Connection refused)'
        match = re.search(pattern, line, re.DOTALL)
        if match != None:
            print(match.group(2))
            x1=match.group(2)

    assert x1 == 'Connection refused',"The SSH connection is refused and sub test case passes "
    client.close()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect('192.168.3.143', username='user', password='admin123')
    print("TC logs into a PC where no services are allowed and SNMP GET request is executed\n")
    c3='snmpget -v2c -c PUBLIC '+ip+' 1.3.6.1.2.1.31.1.1.1.10'
    stdin, stdout, stderr = client.exec_command(c3)

    for line in stderr:
        print(line)
        pattern = '(Timeout:).*'
        match = re.search(pattern, line, re.DOTALL)
        if match != None:
            print(match.group(1))
            x3=match.group(1)

    assert x3 == 'Timeout:'
    client.close()

def test_tc23_remotemgmtv6_regexp(testv6_ip):
    ip=testv6_ip
    print(type(ip))
    print('ip')
    c1='ping -c 5 '+ip
    print(c1)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect('192.168.2.48', username='qa', password='admin123')
    print("TC logs into a PC which is allowed for all services to DUT and PING is CHECKED\n")
    stdin, stdout, stderr = client.exec_command(c1)

    for line in stdout:
        print(line)
        pattern = '(.*\s+)(0% packet loss).*'
        match = re.search(pattern, line, re.DOTALL)
        if match != None:
            print(match.group(2))
            x=match.group(2)
    assert x=='0% packet loss','PING request from remote authentication PC passed without any loss '

    client.close()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect('192.168.3.143', username='user', password='admin123')
    print("TC logs into a PC which is not allowed for Remotemgmt and SSH connection is checked\n ")

    c2='ssh -6 root@'+ip
    print(c2)
    stdin, stdout, stderr = client.exec_command(c2)

    for line in stderr:
        print(line)
        pattern = '(ssh:.*:) (Connection refused)'
        match = re.search(pattern, line, re.DOTALL)
        if match != None:
            print(match.group(2))
            x1=match.group(2)

    assert x1 == 'Connection refused','The SSH connection is refused and sub test case passes '
    client.close()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect('192.168.3.143', username='user', password='admin123')
    print("TC logs into a PC where no services are allowed and SNMP GET request is executed\n")
    c3='snmpget -v2c -c PUBLIC --clientaddr=9001:db7:1:2:116d:eb1d:48c8:fa0d '+ip+' 1.3.6.1.2.1.1.6.0'
    print(c3)
    stdin, stdout, stderr = client.exec_command(c3)

    for line in stderr:
        print(line)
        pattern = '(Timeout:).*'
        match = re.search(pattern, line, re.DOTALL)
        if match != None:
            print(match.group(1))
            x3=match.group(1)

    assert x3 == 'Timeout:',' SNMP request has timed out from a PC which has not V6 Authentication entries'
    client.close()

def test_tc24_mgmtv6_slaac(test_ip):
    ip = test_ip
    headers = {
        "Content-Type": "application/json"
    }
    payload = {
        "ipv6_allocation_method": "slaac",
        "login_authentication_mode": "Local",
        "httpsport": 443,
        "hstsmode": "disable",
        "hstsMaxAge": 16000000
    }

    url_post = "https://" + ip + "/pm/1.2/system/management-if"
    print(url_post)
    response = requests.post(url_post, headers=headers, auth=('root', 'admin123'), json=payload, verify=False)
    print(response.text)
    time.sleep(10)
    response1 = requests.get(url_post, headers=headers, auth=('root', 'admin123'),verify=False)
    print(response1.text)
    assert response.status_code == 200


def test_tc25_v3snmp_check(test_ip):
    print(test_ip)
    ip=test_ip
    print(ip)
    print("SNMP v3 user created before upgrade is checked by doing a SNMPGET from PC where test is executed and this PC is allowed for RemoteMGMT\n")
    authentication = UsmUserData(
        userName='qa1',
        authKey='admin123',
        authProtocol=usmHMACMD5AuthProtocol,
        privKey='admin123',
        privProtocol=usmDESPrivProtocol
    )

    iterator = getCmd(
        SnmpEngine(),
        authentication,
        # CommunityData('PUBLIC'),
        UdpTransportTarget((ip, 161)),
        ContextData(),
        ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0')),
        ObjectType(ObjectIdentity('1.3.6.1.2.1.1.4.0'))
    )

    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    #print(varBinds)

    for varBind in varBinds:  # SNMP response contents
        print(' = '.join([x.prettyPrint() for x in varBind]))


def test_tc26_remotemgmt_snmp_check(test_ip):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect('192.168.2.48', username='qa', password='admin123')

    ip = test_ip
    cmd = 'snmpget -v2c -c PUBLIC ' + ip + ' 1.3.6.1.2.1.1.4.0'
    print(cmd)

    stdin, stdout, stderr = client.exec_command(cmd)

    for line in stdout:
        print(line)

    x=line.rstrip()
    print(x)

    assert x =='iso.3.6.1.2.1.1.4.0 = STRING: "support@niagaranetworks.com"'

    client.close()


def test_tc27_user_accessprivilege(test_ip):
    ip = test_ip
    print("\nUSER with ACCESS level privilege tries to edit the system device name and will be denied \n")
    headers = {
        "Content-Type": "application/json"
    }

    payload = {
        "devicename": "QAMIGRATION",
        "devicecontact": "support@niagaranetworks.com",
        "devicelocation": "Niagara Networks, San Jose, CA"
    }

    url_post = "https://" + ip + "/pm/1.2/system/"
    print(url_post)

    response = requests.post(url_post, headers=headers, auth=('qa1', 'Admin123!'), json=payload, verify=False)
    print(response.json)
    print(response.text)
    val=response.json()["respMsg"]
    assert val=="Permission denied"


def test_tc_28_syslog_check():
    c1 = r"cat /var/log/syslog"
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect('192.168.2.48', username='qa', password='admin123')
    print("###################### \n")
    print(r"TC logs into 192.168.2.48 PC where syslog ~~UDP server ~~ is running and provides the /var/syslog output ")
    stdin, stdout, stderr = client.exec_command(c1, get_pty=True)


    stdin.write('admin123\n')
    stdin.flush()

    for line in stdout:
        print(line)
    client.close()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect('192.168.3.122', username='qa', password='admin123')
    print("###################### \n")
    print(r"TC logs into 192.168.3.122 PC where syslog ~~TCP server ~~~ is running and provides the /var/syslog output")
    stdin, stdout, stderr = client.exec_command(c1, get_pty=True)
    stdin.write('admin123\n')
    stdin.flush()

    for line in stdout:
        print(line)
    client.close()



def test_cmap_put():
    headers = {
        "Content-Type": "application/json"
              }
    url_put = "https://192.168.2.164/pm/1.2/configmaps"
    for i in range(1,10):
               print('''payload%d= {
                                "id": %d,
                                "scheduleCmap": {
                                "status": "enable",
                                "configMapStatus": "disable",
                                "period": "daily",
                                "startTime": "17:35",
                                "endTime": "17:36"
                                }
                                }'''%(i,i))
               response = requests.put(url_put, headers=headers, auth=('root', 'admin123'), json=payload1, verify=False)









    #
    # print(response.text)


def test_maxcmap(test_dut3):
    ip = test_dut3
    i = 1
    headers = {
        "Content-Type": "application/json"
    }
    while i > 0:
        with open(r"C:\Users\LENOVO\PycharmProjects\REST-AUTOMATION\Ffil\3808Ecmap.json") as txt:
            payload1 = json.load(txt)

        url_post = "https://" + ip + "/pm/1.2/configmaps"
        response = requests.post(url_post, headers=headers, auth=('root', 'admin123'), json=payload1, verify=False)
        #print(response.text)