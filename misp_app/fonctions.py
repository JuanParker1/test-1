import re
import requests
import socket
from misp_app import db
from misp_app.models import User, Attributes, Clients, Attributesaccount
from flask import redirect
from flask_login import login_user, current_user, logout_user, login_required
from flask import render_template, url_for, flash, redirect, request, abort


def IOCcount():
    Att = Attributes.query.all()
    fs = Attributesaccount.query.all()
    if len(fs) == 0:
        fs = Attributesaccount(MD5=0,SHA1 = 0,SHA256 = 0,IPs = 0,Domains = 0,URLs = 0)
        db.session.add(fs)
        db.session.commit()

    var = [0,0,0,0,0,0];
    for a in Att:
        if a.Type == 'md5':
            var[4] = var[4] + 1;
        elif a.Type == 'sha1':
            var[5] = var[5] + 1;
        elif a.Type == 'ip-dst' or a.Type == 'ip-src' :
            var[2] = var[2] + 1;
        elif a.Type == 'sha256':
            var[3] = var[3]+1;
        elif a.Type == 'domain':
            var[1] = var[1] + 1;
        elif a.Type == 'url':
            var[0] = var[0] + 1;
    fs = Attributesaccount.query.first()
    fs.MD5 = var[4]
    fs.SHA1 = var[5]
    fs.SHA256 = var[3]
    fs.IPs = var[2]
    fs.Domains = var[1]
    fs.URLs = var[0]
    db.session.commit()
    return var

def emailcheck(email):
    regex = r'\b[a-z]+@dataprotect\.[a-z]{2,3}\b'
    if(re.search(regex,email)):   
        return True  
    else:   
        return False   

def QRadarCheck():
    client = Clients.query.all()
    for cl in client:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((cl.q_ip, int(443)))
        if result == 0:
            cl.status = 'Up'
            db.session.commit()
        else:
            cl.status = 'Down'
            db.session.commit()
    return client

def Misp(category,typ,last):
    url_pull = 'https://192.168.43.92/attributes/restSearch/'
    headers_pull = {'Authorization': 'PiYsxO0qsa3Un1meVSUYmkpt0YHrr1R5xhxoyuKE', 'Content-Type': 'application/json', 'Accept': 'application/json'}
    data_pull = {"request": {"type": typ, "category": category, "last": last, "enforceWarnlinglist": "True"}}
    try:
        r = requests.post(url_pull, headers=headers_pull, json=data_pull, verify=False)
        r.raise_for_status()
        j1 = r.json()
        j2 = j1['response']
        j3 = j2['Attribute']
        iocs = []
        for value in j3:
             iocs.append(value["value"])
    except Exception as e:
        iocs = "Unexpected error"
    return iocs

def feedtable(iocs, category, Type):
    for ioc in iocs:
        one = Attributes(Category=category, Type=Type, Value=ioc, Threat_Level='Low', Creator_user=current_user.username, Comment='from Misp', user_id=current_user.id)
        db.session.add(one)
        db.session.commit()

def qradar(**kwargs):
    Client_name= kwargs["Client_name"]
    Client_status=kwargs["Client_status"]
    iocs = kwargs["Iocs"]
    client = kwargs["Client"]
    reference_set = kwargs["Reference_set"]
    sec = kwargs["SEC_token"]
    requests.packages.urllib3.disable_warnings()
    url_push = 'https://'+ client +'/api/reference_data/sets/bulk_load/' + reference_set
    headers_push = {'SEC': sec, 'Content-Type': 'application/json', 'Version': '9.0', 'Accept': 'application/json'}
    try:  
        p = requests.post(url_push, headers=headers_push, json=iocs,verify=False)
        p.raise_for_status()
        result = {'client':Client_name,'ip address':client, 'client status':Client_status, 'feedstatus':'done' }
    except Exception:
        result = {'client':Client_name,'ip address':client, 'client status':Client_status, 'feedstatus':'error' }
    return result


def manualqradarfeeds(**kwargs):
    Client_name= kwargs["Client_name"]
    Client_status=kwargs["Client_status"]
    iocs = []
    iocs.append(kwargs["Iocs"])
    client = kwargs["Client"]
    reference_set = kwargs["Reference_set"]
    sec = kwargs["SEC_token"]
    requests.packages.urllib3.disable_warnings()
    url_push = 'https://'+ client +'/api/reference_data/sets/bulk_load/' + reference_set
    headers_push = {'SEC': sec, 'Content-Type': 'application/json', 'Version': '9.0', 'Accept': 'application/json'}
    try:  
        p = requests.post(url_push, headers=headers_push, json=iocs,verify=False)
        p.raise_for_status()
        result = {'client':Client_name,'ip address':client, 'client status':Client_status, 'feedstatus':'done' }
    except Exception:
        result = {'client':Client_name,'ip address':client, 'client status':Client_status, 'feedstatus':'error' }
    return result

def EventToMisp(json_data):
    requests.packages.urllib3.disable_warnings()
    headers = {
        'Accept': 'application/json',
        'content-type': 'application/json',
        'Authorization': 'DOvgdvdupFaFHOoQU1t6KwawhTBxcY9ayUdB4BAl',
    }
    try:
        response = requests.post('https://192.168.43.92/events/add', headers=headers, json=json_data, verify=False)
        response.raise_for_status()
        flash('The event has been Updated successfully', 'success')
    except Exception:
        return flash('event not added to MISP, please check MISP!', 'danger')

def addtoreferenceSet(**kwargs):
    Client_name= kwargs["Client_name"]
    Client_status=kwargs["Client_status"]
    iocs = kwargs["Iocs"]
    client = kwargs["Client"]
    sec = kwargs["SEC_token"]
    requests.packages.urllib3.disable_warnings()
    for ioc in iocs:
        r = []
        r.append(ioc["value"])
        url_push = 'https://'+ client +'/api/reference_data/sets/bulk_load/' + ioc["type"]
        headers_push = {'SEC': sec, 'Content-Type': 'application/json', 'Version': '9.0', 'Accept': 'application/json'}
        try:  
            p = requests.post(url_push, headers=headers_push, json=r,verify=False)
            p.raise_for_status()
            result = {'client':Client_name,'ip address':client, 'client status':Client_status, 'feedstatus':'done' }
        except Exception:
            result = {'client':Client_name,'ip address':client, 'client status':Client_status, 'feedstatus':'error' }
    return result





    

       
