import base64
import json
import os
import requests
import socket
import urllib
import time

def vaildAddress(ipAddr,port):
    try:
        print('Testing Socket')
        port = int(str(port).replace("'", ""))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        result = sock.connect_ex((ipAddr,port))
    except Exception as e:
        result = -1
        print(e,ipAddr,port)
    finally:
        print('Test End')
        
        print('Tested',ipAddr,port)
        return True if result == 0 else False

def decode_str(s):
    missing_padding = len(s) % 4
    if missing_padding != 0:
        s += '='* (4 - missing_padding)
    try:
        s = s.encode('utf-8')
        s = bytes(s)
        # s = base64.decodestring(s)
        s = base64.decodebytes(s)
        # s = base64.b64decode(bytes(s),'-_')
        # s = base64.urlsafe_b64decode(s)
    except Exception as e:
        print(e,s)
      
    return s

def decode_url(v):
    v = v.strip('\n')
    v = parseUrl(v)
    
    protocol = v.scheme
    s = v.netloc + v.path
    print('Current protocol is:',protocol)
    print('Current address is:',s)
    
    if protocol is None:
        return None,None
    
    if s.find('@')>0:
        s = s[s.find('@')+1:]
    else:
        s = decode_str(s)
        try:
            s = json.loads(s)
            s = '{}:{}'.format(s['add'],s['port'])
        except:
            if str(s).find('@')>0:
                s = s[str(s).find('@')+1:]
            else:
                s = str(s).replace('\n', '').replace('\r', '')
                print('*'*100)
                print(s)
                print('*'*100)
                time.sleep(5)
                return None,None

    print('Address parse result is:',s)
        
    return str(s).replace("'", "").split(':')
    
def decode_url_bak(v):
    v = v.replace('\n', '')
    protocol = v[:v.find('://')+3] if v.find('://')>=0 else None
    
    s = v[len(protocol):]
    if protocol.startswith('ss'):
        index = s.find('#')
    else:
        index = s.find('?')
    
    try:
        if protocol.startswith('trojan'):
            if s.find('?')>0:
                s = s[s.find('@')+1:s.find('?')]
            elif s.find('#')>0:
                s = s[s.find('@')+1:s.find('#')]
            else:
                s= s[s.find('@')+1:]

            return s.split(':')
            
        if index > 0:
            s = s[:index]
            
            if protocol.startswith('vless'):
                pass
            elif protocol.startswith('ss') and s.find('@')>0:
                print(s)
                pass
            else:
                s = decode_str(s)
            print(s)
            s = s[s.find('@')+1:]
            return s.split(':')
            
        else:
            s = decode_str(s)
            s = json.loads(s)
            return s['add'],s['port']
        
    except Exception as e:
        # print(e, index,s,v)
        return None,None

def encrypt_base64(filename='fly'):
    with open("{}.txt".format(filename),"r") as f:
        vStr = f.readlines()
        
    with open("{}.txt".format(filename),"w") as f:
        f.seek(0)
        f.truncate()
        
    for v in sorted(vStr):
        print('Current test url is:',v)
        i,p = decode_url(v)
        if i is None:
            print('Address is None')
            continue
        
        r = vaildAddress(i,p)
        print('Test url result is:',r)
        
        if r is False:
            continue
        
        with open("{}.txt".format(filename),'a+') as f:
            f.writelines(v)

    
    with open("{}.txt".format(filename),"r+") as f:
        encodeStr = f.read()
        encodeStr = bytes(encodeStr,'utf-8')
        encodeStr = base64.b64encode(encodeStr)
        encodeStr = str(encodeStr, 'utf-8')
    
    with open(filename,"w") as f:
        f.write(encodeStr)

def walkFile(file="."):
    fileList = []
    for root, dirs, files in os.walk(file):
        # for f in files:
        #     print(os.path.join(root, f))
            
        # for d in dirs:
        #     print(os.path.join(root, d))
        fileList += [f.replace('.txt', '') for f in files if f.endswith('txt')]
    return fileList

def parse_from_source(source, filename):
    try:
        source = source.replace('\n', '')
        print('='*50)
        print('source is: {}'.format(source))
        print('='*50)
        rsp = requests.get(source)
        if rsp.status_code==200:
            rsp = rsp.text
            rsp = rsp.encode('utf-8')
            rsp = bytes(rsp)
            rsp = base64.decodebytes(rsp)
            rsp = str(rsp,'utf-8')
            
            lines = rsp.splitlines()
            with open(filename,'r') as f:
                existList = f.readlines()
            for line in lines:
                if (line + '\n') not in existList:
                    print('Add URL is:',line)
                    with open(filename,"a+") as f2:
                        f2.write(line + '\n')
                    with open('fly.txt',"a+") as f3:
                        f3.write(line + '\n')
                else:
                    print('Ignore the URL',line)
        else:
            print(rsp.status_code,rsp.url)
        
    except Exception as e:
        print(e,source)
    
def parseUrl(url):
    p = urllib.parse.urlparse(url)
    print('The URL parse result is:',p)
    
    return p
    
    
if __name__=="__main__":
    with open('source.txt','r') as f:
        sourcelist = f.readlines()
        
    for source in sourcelist:
        parse_from_source(source,'collection.txt')
        
    fList = walkFile()
    fList.remove('collection')
    fList.remove('source')
    for f in fList:
        encrypt_base64(f)
    