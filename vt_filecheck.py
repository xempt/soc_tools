"""
Author: Dang Lim
Version 1
Todo: Add more functionality based on feed back from other analyst. Bug fixes.
Revision: 
"""

import os,sys, getopt,argparse , mimetypes, time
import ipaddress,socket
import requests
import json
import hashlib

import logging

from configparser import ConfigParser

#read keys.ini 
iniParser = ConfigParser()
iniParser.read('keys.ini')

virusTotalKey = iniParser.get('keys','virustotal')

def main():
    
    try:
        #parser info 
        desc = 'Get file information from VT based on hash or upload file.'
        default_help = (__file__ + " -h for more info")
        parser = argparse.ArgumentParser(description = desc)
        parser.add_argument("-v","--version",help="show version",action='version',version='%(prog)s 1.0')
        parser.add_argument("-f","--file",help="file location",type=str,dest="path")
        parser.add_argument("-s","--hash",help="check VT using hash of md5 or sha256",type=str,dest="hash",default='')
    
        #read arguments from cli
        args = parser.parse_args()
    
        if virusTotalKey == '':
            print("Missing virustotal api key")
            sys.exit(0)


        print(args)
        if len(sys.argv) < 2 :
            parser.print_help()
            sys.exit(0)
        
        if args.hash: 
            print("[*]Searching VT with this hash ", args.hash )
            results = virusTotalGetHash(args.hash)
            #print(results)
            printResults(results)
        
        if args.path:
            #check if file is really a file or not. 
            if os.path.isfile(args.path):                
                file_hash = getFileHash(args.path)
                print("[*]Hash of file is ",file_hash)
                print("[*]Sending hash to VT ")
                
                vtResults = virusTotalGetHash(file_hash)
                #do a quick check if there is data
                if str(vtResults) != "0":
                    print('[*]Last Analysis: ',epochTime(int(vtResults['data']['attributes']['last_analysis_date'])))                    
                    printResults(vtResults)
                else:
                    inputUpload = yes_no("[*] Submit file to VT?")
                    if inputUpload:
                        print("[*]Uploading data")
                    
                        uploadID = virusTotalFileUpload(args.path)
                        print("[*]Waiting for VT to finish analyzing file.")
                        time.sleep(35)                         
                        id=str(uploadID['data']['id']) #get id 
                        print("This is the VT ID:",str(id)) 
                        vtUploadResults = virusTotalGetID(id)
                    
                        virusTotalAnalysesReport(vtUploadResults)
                    else:
                        print("nothing to do. ")
                
            else:
                print("[*]Error not a file. Try again.")
                sys.exit(0)

    except Exception as e:
        print("[*]ERORR There was somethign wrong see below:")        
        print(e)   

def virusTotalGetID(id):
    key = virusTotalKey

    headers = {
        'x-apikey': key        
    }

    url = 'https://www.virustotal.com/api/v3/analyses/'+id

    response = requests.get(url=url, headers=headers)

    print(response)

    if response.status_code == 200:
        decodedResponse = response.json()
        
        return decodedResponse
    else:
        return 0

def virusTotalAnalysesReport(input_results):
    input = input_results
    if str(input) != "0":
        #print(input_results)
        print('[*] VirusTotal file uclspload analysis: ')
        print('Submission Date: ',epochTime(int(input['data']['attributes']['date'])), end =' ')
        print('[*] Stats: ')
        print('Harmless:',str(input['data']['attributes']['stats']['harmless']), end =' ')
        print('type-unsupported:',str(input['data']['attributes']['stats']['type-unsupported']), end =' ')
        print('suspicious:',str(input['data']['attributes']['stats']['suspicious']), end =' ')
        print('confirmed-timeout:',str(input['data']['attributes']['stats']['confirmed-timeout']), end =' ')
        print('timeout:',str(input['data']['attributes']['stats']['timeout']), end =' ')
        print('failure:',str(input['data']['attributes']['stats']['failure']), end =' ')
        print('malicious:',str(input['data']['attributes']['stats']['malicious']), end =' ')
        print('undetected:',str(input['data']['attributes']['stats']['undetected']))
        print('[*] File Information: ')
        print('Size:',str(input['meta']['file_info']['size']), end =' ')
        print('SHA256:',str(input['meta']['file_info']['sha256']), end =' ')
        print('Name:',str(input['meta']['file_info']['name']), end =' ')
        print('md5:',str(input['meta']['file_info']['md5']), end =' ')        
        print('sha1:',str(input['meta']['file_info']['sha1']), end =' ')      
    else:
        print("[*] No Data Returned! You may want to submit the file. ")



def virusTotalGetHash(fileHash):
    key = virusTotalKey
    headers = {
        'x-apikey': key
        
    }
    
    url = 'https://www.virustotal.com/api/v3/files/'+fileHash
    
    response = requests.get(url=url, headers=headers)

    if response.status_code == 200:
        decodedResponse = response.json()
        #print(decodedResponse)
        return decodedResponse
    else:
        return 0

def virusTotalFileUpload(filePath):
    print("[*]Uploading file")
    key = virusTotalKey
    headers = {
        'x-apikey': key,
     }
    files = {'file': open(filePath, 'rb')}
    
    print(files)

    url = 'https://www.virustotal.com/api/v3/files'

    response = requests.post(url=url,headers=headers, files=files)


    #print(response)

    if response.status_code == 200:
        decodedResponse = response.json()
        #print(decodedResponse)
        return decodedResponse
    else:
        return 0

def printResults(input_results):
    input = input_results
    if str(input) != "0":
        #print(input_results)
        print('[*] VirusTotal: ')
        print('Submission Date: ',epochTime(int(input['data']['attributes']['first_submission_date'])), end =' ')
        print('Last Analysis: ',epochTime(int(input['data']['attributes']['last_analysis_date'])))
        print('Reputation: ',str(input['data']['attributes']['reputation']))
        print('Times Submitted: ',str(input['data']['attributes']['times_submitted']))   
        print('[*] Last Analysis Stats: ')
        print('confirmed timeout:',str(input['data']['attributes']['last_analysis_stats']['confirmed-timeout']), end =' ')
        print('Failure:',str(input['data']['attributes']['last_analysis_stats']['failure']), end =' ')
        print('harmless:',str(input['data']['attributes']['last_analysis_stats']['harmless']), end =' ')
        print('malicious:',str(input['data']['attributes']['last_analysis_stats']['malicious']), end =' ')
        print('suspicious:',str(input['data']['attributes']['last_analysis_stats']['suspicious']), end =' ')
        print('time:',str(input['data']['attributes']['last_analysis_stats']['timeout']), end =' ')
        print('type unsupported:',str(input['data']['attributes']['last_analysis_stats']['type-unsupported']), end =' ')
        print('undetected:',str(input['data']['attributes']['last_analysis_stats']['undetected']))
        print('[*] File Information: ')
        print('Magic:',str(input['data']['attributes']['magic']), end =' ')
        print('Meaningful Name:',str(input['data']['attributes']['meaningful_name']))
        print('[*] Virustotal Link for more information: https://www.virustotal.com/gui/file/'+str(input['data']['id']) )
    else:
        print("[*] No Data Returned! You may want to submit the file. ")


def getFileHash(filePath):
    print("[*]Getting hash of file. ")
    getHash = hashlib.sha256(open(filePath,'rb').read()).hexdigest()#get sha256 hash of file. 
    return getHash

def epochTime(epoch_time):#converts epoch time to standard time format m/d/yyyy H:M:S AM/PM
    convert_time = time.strftime('%m-%d-%Y %I:%M:%S %p',time.localtime(epoch_time))
    return convert_time

def yes_no(answer):
    yes = set(['yes','y'])
    no = set(['no','n'])

    while True:
        choice = input(answer).lower()
        if choice in yes:
            return True
        elif choice in no:
            return False
        else:
            print("Respond yes or no")
            


if __name__ == '__main__':
    main()