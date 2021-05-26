from . import network
import requests
from requests.models import Response

def check(address,key):
    
    headers = {
        'x-apikey': key
    }    
    
    if network.ipcheck(address.strip()):#if its not an IP assume its a domain...... 
        url = 'https://www.virustotal.com/api/v3/ip_addresses/'+address
    else:
        url = 'https://www.virustotal.com/api/v3/domains/'+address            

    response = requests.get(url=url, headers=headers)
    #print(response)
    if response.status_code == 200:
        decodedResponse = response.json()
        #print(decodedResponse)
        return output(decodedResponse,address)
    else:
        return print("Something went wrong please see response message: ",response)
   
def output(dataInput,address):
    #output for data receieved
    if dataInput != 0:
        print('[*] VirusTotal: ', end=' ')
        print('Harmless:',str(dataInput['data']['attributes']['last_analysis_stats']['harmless']), end =' ')
        print('Malcious:',str(dataInput['data']['attributes']['last_analysis_stats']['malicious']), end =' ')
        print('Suspicious:', str(dataInput['data']['attributes']['last_analysis_stats']['suspicious']) )
    if str(dataInput['data']['type']) == 'ip_address':#if its an IP address show the asn info. 
        print('AS OWNER:', str(dataInput['data']['attributes']['as_owner']), end = ' ')
        print('ASN:', str(dataInput['data']['attributes']['asn']), end = ' ')
        print('Country ',str(dataInput['data']['attributes']['country']))                       
        print('Result link https://www.virustotal.com/gui/search/'+address.strip()+"")
    else:
        print("no data from VirusTotal")