from . import network
import requests
from requests.models import Response

def check(address,key):#
    #check address if its real ip, if it fails we're gonna assume its a domain and try to resolve it. 
    if network.ipcheck(address) == False: 
        if resolveHostName(address) != False:
            address = resolveHostName(address)
        else:
            return 0 
        
    url = 'https://api.abuseipdb.com/api/v2/check'
    queryString = {
        'ipAddress': address,
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
        return results
    else:
        return 0
