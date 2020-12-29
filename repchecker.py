"""
date: 12/16/2020 
Author: Dang Lim
Version 1
Revision: 
"""

import os,sys, getopt,argparse , mimetypes, time
import ipaddress,socket
import requests
import json

from requests.models import Response

#api keys here
abuseIPkey = ''
virusTotalKey = ''

def main():
    #todo: check if api key section is filled out. 


    try:
        #parser info 
        desc = 'This script will read an input file of ip addressess/domains or individual ip/domain and check the reputation against various sources'
        default_help = ("repchecker.py -h for more info")
        parser = argparse.ArgumentParser(description = desc)
        parser.add_argument("-v","--version",help="show version",action='version',version='%(prog)s 1.0')
        parser.add_argument("-f","--file",help="file location",type=str,dest="path")
        parser.add_argument("-i","--input",help="check single ip/domain",type=str,dest="i",default='')
    
        #read argumetns from cli
        args = parser.parse_args()
    
        if len(sys.argv) < 2 :
            parser.print_help()
            sys.exit(0)
        
        if args.path:
            print("[*] reading list from", args.path.format(), "\n")
            readList = readFile(args.path)
            time.sleep(1)
            for i in readList:
                #print(i)
                print("[*] Getting reputation for", i.format(), "")
                print("---------------------------------------------------")
                if ipcheck(i):
                    abuseIPResults = abuseIP(i)
                    if abuseIPResults != 0:
                        print("Score: ",str(abuseIPResults['data']['abuseConfidenceScore']))
                        print("ISP: ",str(abuseIPResults['data']['isp']), end=' ')                
                        print("Domain: ",str(abuseIPResults['data']['domain']), end = ' ')                        
                        print("Usage Type: ",str(abuseIPResults['data']['usageType']),"\n")       
                        print("Result Link https://www.abuseipdb.com/check/"+i.strip()+"\n")
                    else: 
                        print("No Data from AbuseIP")                    
                else:
                    print("[*]AbuseIP takes IP only. Skipping\n")                            
                #vtResults
                time.sleep(15)#since we currently do not have a pro api key for vt, we will rate limit ourselves. 
                vtResults = virusTotal(i)
                if vtResults != 0:
                    print('[*] VirusTotal: ', end=' ')
                    print('Harmless:',str(vtResults['data']['attributes']['last_analysis_stats']['harmless']), end =' ')
                    print('Malcious:',str(vtResults['data']['attributes']['last_analysis_stats']['malicious']), end =' ')
                    print('Suspicious:', str(vtResults['data']['attributes']['last_analysis_stats']['suspicious']) )
                if str(vtResults['data']['type']) == 'ip_address':#if its an IP address show the asn info. 
                    print('AS OWNER:', str(vtResults['data']['attributes']['as_owner']), end = ' ')
                    print('ASN:', str(vtResults['data']['attributes']['asn']), end = ' ')
                    print('Country ',str(vtResults['data']['attributes']['country']))                       
                    print('Result link https://www.virustotal.com/gui/search/'+i.strip()+"")
                else:
                    print("no data from VirusTotal")
                #threatcrowd
                tcResults = threatCrowd(i)
                print("[*] Threatcrowd: ")
                #print(tcResults)
                if tcResults != 0:                    
                    if str(tcResults['votes']) == '-1':
                        print("Most users have voted this malicious.")
                    elif str(tcResults['votes']) == '0':
                        print("An equal number of users have voted this malicious.")
                    elif str(tcResults['votes']) == '1': 
                        print("Most users have voted this not malicious")
                    else:
                        print("Unknown value maybe api update? ")          
                    print("Result link: ", str(tcResults['permalink']))
                else:
                    print("No data from threatcrowd,address too new or error")                

                print("---------------------------------------------------\n")
       
        if args.i:
            print("[*] Getting reputation for", args.i.format(), "\n")
                #AbuseIpDB Results
            abuseIPResults = abuseIP(args.i)                
            if abuseIPResults != 0:
                print("[*] AbuseIPDB:  ", end=' ')
                #print(abuseIPResults)
                print("Score: ",str(abuseIPResults['data']['abuseConfidenceScore']))
                print("ISP: ",str(abuseIPResults['data']['isp']), end=' ')                
                print("Domain: ",str(abuseIPResults['data']['domain']), end = ' ')
                #print("Country: ",str(abuseIPResults['data']['countryName']),end =' ')
                print("Usage Type: ",str(abuseIPResults['data']['usageType']),"\n")                
                print("Result Link https://www.abuseipdb.com/check/"+args.i.strip()+"\n")
            else: 
                print("No Data from AbuseIP. Note: Abuseip only takes IP addresses")

            #VT Results
            vtResults = virusTotal(args.i)
            #print(vtResults)
            if vtResults != 0:
                print('[*] VirusTotal: ', end=' ')
                print('Harmless:',str(vtResults['data']['attributes']['last_analysis_stats']['harmless']), end =' ')
                print('Malcious:',str(vtResults['data']['attributes']['last_analysis_stats']['malicious']), end =' ')
                print('Suspicious:', str(vtResults['data']['attributes']['last_analysis_stats']['suspicious']) )
                if str(vtResults['data']['type']) == 'ip_address':#if its an IP address show the asn info. vt does not do that with domain searches. 
                    print('AS OWNER:', str(vtResults['data']['attributes']['as_owner']), end = ' ')
                    print('ASN:', str(vtResults['data']['attributes']['asn']), end = ' ')
                    print('Country ',str(vtResults['data']['attributes']['country']))                   
                print('Result link https://www.virustotal.com/gui/search/'+args.i.strip()+"")
            else:
                print("No Data from VirusTotal")                
            #threatcrowd
            tcResults = threatCrowd(args.i)
            print("[*] Threatcrowd: ")
            #print(tcResults)
            if tcResults != 0:                    
                if str(tcResults['votes']) == '-1':
                    print("Most users have voted this malicious.")
                elif str(tcResults['votes']) == '0':
                    print("An equal number of users have voted this malicious.")
                elif str(tcResults['votes']) == '1': 
                    print("Most users have voted this not malicious")
                else:
                    print("Unknown value maybe api update? ")          
                print("Result link: ", str(tcResults['permalink']))
            else:
                print("No data from threatcrowd,maybe too new or error")                

    except Exception as e:
        print(e)

def threatCrowd(address):
    headers = {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36'
    }
    if ipcheck(address):
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

def virusTotal(address):
    key = virusTotalKey
    headers = {
        'x-apikey': key
    }
    #if its not an IP assume its a domain...... 
    if ipcheck(address):
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
   

def abuseIP(address):#
    #check address if its real ip, if it fails we're gonna assume its a domain and try to resolve it. 
    if ipcheck(address) == False: 
        if resolveHostName(address) != False:
            address = resolveHostName(address)
        else:
            return 0 
        
    key = abuseIPkey
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
    #results = ip +","+ str(decodedResponse['data']['abuseConfidenceScore']) + "," + str(decodedResponse['data']['lastReportedAt'])
    

#check if ip address is a valid ip
def ipcheck(ipAddress):
    try:
        ipaddress.IPv4Network(ipAddress)
        return True
    except ValueError:
        return False

def resolveHostName(address):
    hostname = address
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except socket.gaierror as e:
        print(e)
        return False        

def readFile(inputFile):
    newList=[]
    try:
        with open(inputFile,'r') as f:
            data = f.readlines() #use readlines to read it line by line  
            for list in data: #remove \n from list
                newList.append(list.replace("\n",""))
            f.close()
        return newList #returns data from cleaned up list 
    except (FileNotFoundError):
        return False

if __name__ == '__main__':
    main()