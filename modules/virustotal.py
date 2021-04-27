from . import network
import requests
from requests.models import Response

def check(address,key):
    
    headers = {
        'x-apikey': key
    }
    #if its not an IP assume its a domain...... 
    if network.ipcheck(address):
        url = 'https://www.virustotal.com/api/v3/ip_addresses/'+address
    else:
        url = 'https://www.virustotal.com/api/v3/domains/'+address    
    
    response = requests.get(url=url, headers=headers)
    if response.status_code == 200:
        decodedResponse = response.json()
        results = decodedResponse
        #print(results)
        return results
    else:
        return 0
   