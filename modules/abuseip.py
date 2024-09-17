from . import network
import requests
from requests.models import Response
import json
import sys

MIN_REPORTS = 4
MAX_SCORE = 30

def check(address,key,output=False):
    #check address if its real ip, if it fails we're gonna assume its a domain and try to resolve it. 
    if network.ipcheck(address) != True: 
        if network.resolveHostName(address) != False:
            ip_address = network.resolveHostName(address)
            print("resolving domain name to ",ip_address.format())
        else:
            return False, "Error IP address couldn't resolve\n"
    else:
        ip_address = address         
        
    url = 'https://api.abuseipdb.com/api/v2/check'
    queryString = {
        'ipAddress': ip_address,
        'maxAgeInDays': '180'
    }

    headers = {
        'Accept': 'application/json',
        'Key': key
    }

    response = requests.request(method='GET',url=url, headers=headers,params=queryString)
    if response.status_code == 200:
        return analysis(response.json(),ip_address)
    else:        
        return False, "Something went wrong please see response message: "+response+"\n"

def analysis(dataInput,address):
    score = dataInput['data']['abuseConfidenceScore']
    reports = dataInput['data']['totalReports']
    blockVerdict = score > MAX_SCORE and reports > MIN_REPORTS
    verdict = "Block IP " if blockVerdict else "No action necessary"
    result = "[*] AbuseIPDB:  "+verdict+"\n"
    if blockVerdict:
        result += "\tScore: "+str(score)+" \t| Reports: "+str(reports)+"\n"
        result += "\tResult Link: https://www.abuseipdb.com/check/"+address.strip()+"\n"
    return blockVerdict, result