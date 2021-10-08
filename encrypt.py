import base64
import json
import os
import socket


def vaildAddress(ipAddr,port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((ipAddr,int(port)))
    except Exception as e:
        result = False
        print(e,ipAddr,port)
    finally:
        return True if result == 0 else False

def decode_str(s):
    missing_padding = len(s) % 4
    if missing_padding != 0:
        s += b'='* (4 - missing_padding)
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
    v = v.replace('\n', '')
    protocol = v[:v.find('://')+3] if v.find('://')>=0 else None
    
    if protocol is not None:
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
                s = decode_str(s)
                s = s[s.find('@')+1:]
                return s.split(':')
                
            else:
                s = decode_str(s)
                s = json.loads(s)
                return s['add'],s['port']
            
        except Exception as e:
            # print(e, index,s,v)
            return None,None
    else:
        return None,None

def encrypt_base64(filename='fly'):
    with open("{}.txt".format(filename),"r") as f:
        vStr = f.readlines()
        
    with open("{}.txt".format(filename),"w") as f:
        f.seek(0)
        f.truncate()
        
    for v in sorted(vStr):
        i,p = decode_url(v)
        if i is not None:
            r = vaildAddress(i,p)
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
            
            # if f.endswith('txt'):
            #     print(type(f))
            #     fileList.append(f)

        # for d in dirs:
        #     print(os.path.join(root, d))
        fileList += [f.replace('.txt', '') for f in files if f.endswith('txt')]
    return fileList

if __name__=="__main__":
    fList = walkFile()
    for f in fList:
        encrypt_base64(f)
