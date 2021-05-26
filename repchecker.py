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
        desc = 'This script will read an input file of ip addressess/domains or individual ip/domain and check the reputation against various sources'

        default_help = ("repchecker.py -h for more info")
        parser = argparse.ArgumentParser(description = desc)
        parser.add_argument("-v","--version",help="show version",action='version',version='%(prog)s 1.0')
        parser.add_argument("-f","--file",help="file location",type=str,dest="path")
        parser.add_argument("-i","--input",help="check single ip/domain",type=str,dest="i",default='')
        #parser.add_argument("-o","--output",help="location\filename to save. default: "+os.getcwd()+"\output.csv",type=str,dest="output",default=os.getcwd()+"\output.csv")
        #output not working yet.... 

        #read arguments from cli
        args = parser.parse_args()
        
        if len(sys.argv) < 2 :
            parser.print_help()
            sys.exit(0)
        
        if args.path:
            print("[*] reading list from", args.path.format(), "\n")
            readList = readFile(args.path)
            #print(readList)
            time.sleep(1)
            for i in readList:
                #print(i)
                print("[*] Getting reputation for", i.format(), "")
                print("---------------------------------------------------")
                abuseip.check(i,abuseIPkey)               
                #vtResults
                time.sleep(15)#since we currently do not have a pro api key for vt, we will rate limit ourselves. 
                #virus total
                virustotal.check(i,virusTotalKey)
                #threatcrowd
                threatcrowd.check(i) 
                print("---------------------------------------------------\n")
       
        if args.i:
            print("[*] Getting reputation for", args.i.format(), "\n")
            #AbuseIpDB Results
            abuseip.check(args.i,abuseIPkey)               
            #VT Results
            virustotal.check(args.i,virusTotalKey)
            #threatcrowd            
            threatcrowd.check(args.i)

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