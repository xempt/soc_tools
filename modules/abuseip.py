from . import network
import requests
from requests.models import Response
import json

def check(address,key):
    #check address if its real ip, if it fails we're gonna assume its a domain and try to resolve it. 
    if network.ipcheck(address) != True: 
        if network.resolveHostName(address) != False:
            ip_address = network.resolveHostName(address)
            print("resolving donmain name to ",ip_address.format())
        else:
            print("Error IP address coulnd't resolve")
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
        decodedResponse = response.json()
        results = decodedResponse
        return output(results,ip_address)
    else:        
        print("Something went wrong please see response message: ",response)

def output(dataInput,address):
    #output for data receieved
    if dataInput != 0:
        print("[*] AbuseIPDB:  ", end=' ')
        #print(dataInput)
        print("Score: ",str(dataInput['data']['abuseConfidenceScore']))
        print("ISP: ",str(dataInput['data']['isp']), end=' ')                
        print("Domain: ",str(dataInput['data']['domain']), end = ' ')
        #print("Country: ",str(dataInput['data']['countryName']),end =' ')
        print("Usage Type: ",str(dataInput['data']['usageType']),"\n")                
        print("Result Link https://www.abuseipdb.com/check/"+address.strip()+"\n")
    else:
        print("No Data from AbuseIP. Note: Abuseip only takes IP addresses")    
