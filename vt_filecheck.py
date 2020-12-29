"""
Author: Dang Lim
Version 1
Todo: Add more functionality from other analyst feed back. Bug fixes.
Revision: 
"""

import os,sys, getopt,argparse , mimetypes, time
import ipaddress,socket
import requests
import json
import hashlib

#vt api key
virusTotalKey = ''


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
            #quick chck if file is really a file or not. 
            if os.path.isfile(args.path):
                print("[*]Getting has off file.")
                file_hash = getFileHash(args.path)
                print("[*]Hash of file is ",file_hash)
            else:
                print("[*]Error not a file. Tryy again.")
                sys.exit(0)

    except Exception as e:
        print("[*]ERORR There was somethign wrong see below:")        
        print(e)   

def virusTotalGetHash(fileHash):
    key = virusTotalKey
    headers = {
        'x-apikey': key
    }
    
    url = 'https://www.virustotal.com/api/v3/files/'+fileHash
    
    response = requests.get(url=url, headers=headers)

    if response.status_code == 200:
        decodedResponse = response.json()
        results = decodedResponse
        #print(results)
        return results
    else:
        return 0

def virusTotalFileUpload(filePath):
    print("[*] Checking file hash first.")
    #check file hash first give user a choice if they want to refresh the scan. 
    #check file size. lets limit this to < 60mbs. 

def printResults(input_results):
    input = input_results
    print(input_results)
    print('[*] VirusTotal: ')
    print('First seen in the wild: ',epochTime(int(input['data']['attributes']['first_seen_itw_date'])), end =' ')
    print('Submission Date: ',epochTime(int(input['data']['attributes']['first_submission_date'])), end =' ')
    print('Last Analysis: ',epochTime(int(input['data']['attributes']['last_analysis_date'])))
    print('Reputation: ',str(input['data']['attributes']['reputation']))
    print('Times Submitted: ',str(input['data']['attributes']['times_submitted']))   
    print('[*] Last Analysis Stats: ')
    print('Harmless:',str(input['data']['attributes']['last_analysis_stats']['confirmed-timeout']), end =' ')
    print('Malcious:',str(input['data']['attributes']['last_analysis_stats']['failure']), end =' ')
    print('Malcious:',str(input['data']['attributes']['last_analysis_stats']['harmless']), end =' ')
    print('Malcious:',str(input['data']['attributes']['last_analysis_stats']['malicious']), end =' ')
    print('Malcious:',str(input['data']['attributes']['last_analysis_stats']['suspicious']), end =' ')
    print('Malcious:',str(input['data']['attributes']['last_analysis_stats']['timeout']), end =' ')
    print('Malcious:',str(input['data']['attributes']['last_analysis_stats']['type-unsupported']), end =' ')
    print('Malcious:',str(input['data']['attributes']['last_analysis_stats']['undetected']))
    print('[*] File Information: ')
    print('Magic:',str(input['data']['attributes']['magic']), end =' ')
    print('Meaningful Name:',str(input['data']['attributes']['meaningful_name']))
    print('[*] Virustotal Link for more information: https://www.virustotal.com/gui/file/'+str(input['data']['id']) )


def getFileHash(filePath):
    print("[*]Getting hash of file. ")
    getHash = hashlib.sha256(open(filePath,'rb').read()).hexdigest()#get sha256 hash of file. 
    return getHash

def epochTime(epoch_time):#converts epoch time to standard time format m/d/yyyy H:M:S AM/PM
    convert_time = time.strftime('%m-%d-%Y %I:%M:%S %p',time.localtime(epoch_time))
    return convert_time


if __name__ == '__main__':
    main()