from . import network
import requests
from requests.models import Response


def check(address):
    headers = {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36'
    }
    if network.ipcheck(address):
        url = 'http://www.threatcrowd.org/searchApi/v2/ip/report/'
        params = {
            'ip': address
        }        
    else:
        url = 'http://www.threatcrowd.org/searchApi/v2/domain/report'
        params = {
            'domain': address
        }
    response = requests.get(url=url,params=params,headers=headers)
    #print(response.text)
    if response.status_code == 200:
        decodedResponse = response.json()        
        #print(decodedResponse)
        if decodedResponse['response_code'] == '0':
            return output(0)
        else:
            return output(decodedResponse)
    else:
        return print("Something went wrong please see response message: ",response)

def output(dataInput):
    #output for data receieved
    
    print("[*] Threatcrowd: ")
    #print(dataInput)
    if dataInput != 0:
        if str(dataInput['votes']) == '-1':
            print("Most users have voted this malicious.")
        elif str(dataInput['votes']) == '0':
            print("An equal number of users have voted this malicious.")
        elif str(dataInput['votes']) == '1': 
            print("Most users have voted this not malicious")
        else:
             print("Unknown value maybe api update? ")        
        print("Result link: ", str(dataInput['permalink']))
    else:
        print("No data from threatcrowd,address too new or error")          