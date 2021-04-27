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
            return 0
        else:
            return decodedResponse
    else:
        return 0 