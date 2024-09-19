from . import network
import requests

MIN_REPORTS = 4
MAX_SCORE = 5

def check(address,key,output=False, flag=False):
    headers = {
        'x-apikey': key
    }    
    
    if network.ipcheck(address.strip()): #if its not an IP assume its a domain...... 
        url = 'https://www.virustotal.com/api/v3/ip_addresses/'+address
    else:
        url = 'https://www.virustotal.com/api/v3/domains/'+address            

    response = requests.get(url=url, headers=headers)
    if response.status_code == 200:
        return analysis(response.json(),address, flag)
    else:
        return False, "[V] Error in request/response\n", "N/A"

def analysis(dataInput,address, flag):
    as_owner = None
    if dataInput != 0: 
        score = dataInput['data']['attributes']['reputation']
        reports = dataInput['data']['attributes']['total_votes']['harmless'] + dataInput['data']['attributes']['total_votes']['malicious']
        blockVerdict = abs(score) > MAX_SCORE and reports > MIN_REPORTS
        verdict = "Block IP " if blockVerdict else "No action necessary"
        result = "[*] VirusTotal: "+verdict+"\n"
        if blockVerdict or flag:
            result += "\tScore: "+str(score)+" \t| Reports: "+str(reports)+"\n"
            result += "\tResult link https://www.virustotal.com/gui/search/"+address.strip()+"\n"
        if 'as_owner' in dataInput['data']['attributes']:
            as_owner = str(dataInput['data']['attributes']['as_owner'])
        return blockVerdict, result, as_owner