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
            print("Error IP address couldn't resolve")
            return 0
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
        ret = analysis(response.json(),ip_address)
        if output: 
            output(response.json(),ip_address)
    else:        
        print("Something went wrong please see response message: ",response)
    
    return ret

def output(dataInput,address):
    #output for data receieved
    sys.stdout = open("output_results.txt", 'w')
    if dataInput:
        print("[*] AbuseIPDB:  ", end=' ')
        #print(dataInput)
        print("Score: ",str(dataInput['data']['abuseConfidenceScore']))
        print("ISP: ",str(dataInput['data']['isp']), end=" | ")                
        print("Domain: ",str(dataInput['data']['domain']), end = '\n')
        #print("Country: ",str(dataInput['data']['countryName']),end ='\n')
        print("Usage Type: ",str(dataInput['data']['usageType']))                
        print("Result Link: https://www.abuseipdb.com/check/"+address.strip()+'\n')
    else:
        print("No Data from AbuseIP. Note: AbuseIP only takes IP addresses")    

def analysis(dataInput,address):
    score = dataInput['data']['abuseConfidenceScore']
    reports = dataInput['data']['totalReports']
    blockVerdict = score > MAX_SCORE and reports > MIN_REPORTS
    verdict = "Block IP " if blockVerdict else "No action necessary"
    print("[*] AbuseIPDB:  "+verdict)
    if blockVerdict:
        print("\tScore: ",score," \t| Reports: ",reports)
        print("\tResult Link: https://www.abuseipdb.com/check/"+address.strip())
    return blockVerdict