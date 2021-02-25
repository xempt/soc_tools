# SOC Tools 

Just some tools used in our SOC for doing day to day  tasks. 

## Installation 
### Get API keys from Virustotal & Abuseip and edit edit the  scripts that need it. 

Use package manager pip to install required librarys. 

```bash
pip install -r requirements.txt
```
edit keys.ini and add your api keys. 

## Usage

### repchecker.py -h # for help
This script will read an input file of ip addressess/domains or individual ip/domain and check the reputation against
various sources

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show version
  -f PATH, --file PATH  file location
  -i I, --input I       check single ip/domain


### vt_filecheck.py -h # for help
Get file information from VT based on hash or upload file.

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show version
  -f PATH, --file PATH  file location
  -s HASH, --hash HASH  check VT using hash of md5 or sha256

### getFfileHash.py  -h # for help
Get Hash MD5, SHA1, SHA256 & SHA512 of a file

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show version
  -f PATH, --file PATH  file location


## License
GNU GPL V3
Check out LICENSE file. 
