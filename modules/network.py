import ipaddress,socket

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
