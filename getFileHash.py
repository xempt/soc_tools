import os,sys, argparse , time
import hashlib
def main():
    try:
        #parser info 
        desc = 'Get Hash MD5, SHA1, SHA256 & SHA512 of a file '
        default_help = (__file__ + " -h for more info")
        parser = argparse.ArgumentParser(description = desc)
        parser.add_argument("-v","--version",help="show version",action='version',version='%(prog)s 1.0')
        parser.add_argument("-f","--file",help="file location",type=str,dest="path")
    
        #read arguments from cli
        args = parser.parse_args()

        if args.path:
            #check if file is really a file. 
            if os.path.isfile(args.path):
                for kv in getFileHash(args.path).items():
                    print(kv)
            else:
                print("Not a file. Try again")

    except Exception as e:
        print("[*]ERORR There was somethign wrong see below:")        
        print(e)   

def getFileHash(filePath):
    print("[*]Getting hash of file. ")
    fileHash = {}
    fileHash['MD5'] = hashlib.md5(open(filePath,'rb').read()).hexdigest()#get md5 hash of file. 
    fileHash['SHA1'] = hashlib.sha1(open(filePath,'rb').read()).hexdigest()#get sha1 hash of file. 
    fileHash['SHA256'] = hashlib.sha256(open(filePath,'rb').read()).hexdigest()#get sha256 hash of file. 
    fileHash['SHA512'] = hashlib.sha512(open(filePath,'rb').read()).hexdigest()#get sha512 hash of file. 
    return fileHash

if __name__ == '__main__':
    main()