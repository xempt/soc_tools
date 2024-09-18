"""
date: 12/16/2020 
Author: Dang Lim
Version 1
Revision: 
"""

import configparser
import os,sys, getopt,argparse , mimetypes, time
import requests
import json
from requests.models import Response
from configparser import ConfigParser

from modules import threatcrowd
from modules import network
from modules import virustotal
from modules import abuseip


#read keys.ini
iniParser = ConfigParser()
iniParser.read('keys.ini')

abuseIPkey = iniParser.get('keys','abuseip')
virusTotalKey = iniParser.get('keys','virustotal')


def main():

    try:
        #parser info 
        desc = 'This script will read an input file of ip addresses/domains or individual ip/domain and check the reputation against various sources'

        default_help = ("repchecker.py -h for more info")
        parser = argparse.ArgumentParser(description = desc)
        parser.add_argument("-v","--version",help="show version",action='version',version='%(prog)s 1.0')
        parser.add_argument("-f","--file",help="file location",type=str,dest="path")
        parser.add_argument("-i","--input",help="check single ip/domain",type=str,dest="i",default='')
        #parser.add_argument("-o","--output",help="location\filename to save. default: "+os.getcwd()+"\output.txt",type=str,dest="output",default=os.getcwd()+"\output.txt")
        #output not working yet.... 

        #read arguments from cli
        args = parser.parse_args()
        
        if len(sys.argv) < 2 :
            parser.print_help()
            sys.exit(0)
        
        if args.path:
            print("[*] Reading list from", args.path.format())
            readList = readFile(args.path)

            # MAP : AS to IPs
            AS_providers = {
                "AMAZON" : [],
                "GOOGLE" : [], 
                "AZURE"  : [],
                "OTHER"  : [],
            }
            # MAP : IP to OUTPUT TEXT
            IP_results = {}

            for i in readList:
                print("[*] Getting reputation for", i.format(), "")
                out_text = "[*] Results for " + str(i) + ":\n"
                
                #abuseip
                abuseip_flag, abuseip_output = abuseip.check(i,abuseIPkey)       
                out_text += abuseip_output
                
                #virustotal
                time.sleep(15) #api rate limit
                virustotal_flag, virustotal_output, as_owner =virustotal.check(i,virusTotalKey, flag=abuseip_flag)
                out_text += virustotal_output
                if as_owner:
                    out_text += '[*] AS: ' + as_owner + "\n"                
                out_text += "---------------------------------------------------"

                #save results to maps to print after complete 
                IP_results[i] = out_text
                if as_owner and "AMAZON" in as_owner.upper():
                    AS_providers["AMAZON"].append(i)
                elif as_owner and "GOOGLE" in as_owner.upper():
                    AS_providers["GOOGLE"].append(i)
                elif as_owner and "AZURE" in as_owner.upper():
                    AS_providers["AZURE"].append(i)
                else:
                    AS_providers["OTHER"].append(i)

            # print out saved results
            print("========================== RESULTS ==========================")
            for provider in AS_providers:
                if len(AS_providers[provider]) > 0:
                    print(provider)
                    for ip in AS_providers[provider]:
                        print(IP_results[ip])
       
        if args.i:
            print("[*] Getting reputation for "+args.i.format())
            #abuseip
            abuseip_flag, abuseip_output = abuseip.check(args.i,abuseIPkey)   
            out_text = abuseip_output

            #virustotal
            virustotal_flag, virustotal_output, as_owner = virustotal.check(args.i,virusTotalKey, flag=abuseip_flag)
            out_text += virustotal_output
            out_text += '[*] AS: ' + as_owner + "\n"

            print(out_text)
        
    except Exception as e:
        print(e)


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