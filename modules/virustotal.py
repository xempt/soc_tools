from . import network
import requests
from requests.models import Response

MIN_REPORTS = 4
MAX_SCORE = 5

def check(address,key,output=False, flag=False):
    
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
        ret = analysis(response.json(),address, flag)
        if output:
            output(response.json(),address)
    else:
        print("Something went wrong please see response message: ",response)
    
    return ret
   
def output(dataInput,address):
    #output for data receieved
    if dataInput != 0:
        print('[*] VirusTotal: ', end=' ')
        print('Harmless:',str(dataInput['data']['attributes']['last_analysis_stats']['harmless']), end =' | ')
        print('Malicious:',str(dataInput['data']['attributes']['last_analysis_stats']['malicious']), end =' | ')
        print('Suspicious:', str(dataInput['data']['attributes']['last_analysis_stats']['suspicious']) )
    if str(dataInput['data']['type']) == 'ip_address':#if its an IP address show the asn info. 
        print('AS Owner:', str(dataInput['data']['attributes']['as_owner']), end = ' | ')
        print('ASN:', str(dataInput['data']['attributes']['asn']), end = ' | ')
        print('Country: ',str(dataInput['data']['attributes']['country']))                       
        print('Result link https://www.virustotal.com/gui/search/'+address.strip())
    else:
        print("no data from VirusTotal")

def analysis(dataInput,address, flag):
    score = dataInput['data']['attributes']['reputation']
    reports = dataInput['data']['attributes']['total_votes']['harmless'] + dataInput['data']['attributes']['total_votes']['malicious']
    blockVerdict = abs(score) > MAX_SCORE and reports > MIN_REPORTS
    verdict = "Block IP " if blockVerdict else "No action necessary"
    print("[*] VirusTotal: "+verdict)
    if blockVerdict or flag:
        print("\tScore: ",score," \t| Reports: ",reports)
        print("\tResult link https://www.virustotal.com/gui/search/"+address.strip())
    print('[*] AS:', str(dataInput['data']['attributes']['as_owner']))
    return blockVerdict