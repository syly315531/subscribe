import base64
import json
import os
import re
import socket
import time
import urllib

import geoip2.database
import requests


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
    s = re.sub('=','',s)
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
        s = str(s, encoding='utf-8')
    except Exception as e:
        print(e,s)
    
    return s

def decode_url(url):
    url = url.strip('\n')
    url = parseUrl(url)
    
    protocol = url.scheme
    s = url.netloc + url.path
    print('Current protocol is:',protocol)
    print('Current address is:',s,type(s))
    
    if protocol is None:
        return None,None
    
    if protocol == 'ssr':
        s = s[0:s.find('_')] if s.find('_')>0 else s
        s = decode_str(s)
        s = s.strip().split(':')
        s = '{}:{}'.format(s[0],s[1])
    elif s.find('@')>0:
        s = s[s.find('@')+1:]
    else:
        s = decode_str(s)
        try:
            s = json.loads(s)
            s = '{}:{}'.format(s['add'],s['port'])
        except:
            s = str(s)
            if s.find('@')>0:
                s = s[s.find('@')+1:]
            else:
                s = s.replace('\n', '').replace('\r', '')
                print('*'*100)
                print(s)
                print(url)
                print('*'*100)
                time.sleep(5)
                return None,None,None

    print('Address parse result is:',s,type(s))
    
    result = s.replace("'", "").split(':')
    country = getCountry(result[0])
    tagName = '[{}{}]{}:{}'.format(country,url.scheme.upper(),result[0].upper(),result[1])
    nu = buildUrl(url,tagName)
    # print(nu)
    result.append(nu)

    return result

def parseUrl(url):
    p = urllib.parse.urlparse(url)
    # print('The URL parse result is:',p)
    
    return p

def buildUrl(obj,tagName):
    print('Add Tag name is:', tagName)
    if obj.scheme in ['ss','trojan','vless']:
        result = (obj.scheme, obj.netloc, obj.path, obj.params, obj.query, tagName)
        result = urllib.parse.urlunparse(result)
    elif obj.scheme =='vmess':
        print(obj.netloc,type(obj.netloc))
        result = decode_str(obj.netloc + obj.path)
        try:
            result = json.loads(result)
            result['ps'] = tagName
            result = json.dumps(result,ensure_ascii=False)
            result = bytes(result,'utf-8')
            result = base64.b64encode(result)
            result = str(result, 'utf-8')
            result = urllib.parse.urlunparse((obj.scheme, result, '', obj.params, obj.query,obj.fragment))
        except:
            pl = urllib.parse.parse_qs(obj.query)
            pl['remarks'] = [tagName]
            pl = [(k,','.join(v)) for k,v in pl.items()]
            pl = urllib.parse.urlencode(pl)
            result = urllib.parse.urlunparse((obj.scheme, obj.netloc, obj.path, obj.params, pl, obj.fragment))
    elif obj.scheme =='ssr':
        result = obj.scheme + '://' + decode_str(obj.netloc)
        result = parseUrl(result)
        pl = urllib.parse.parse_qs(result.query)
        tagName = bytes(tagName,'utf-8')
        tagName = base64.b64encode(tagName)
        tagName = str(tagName, 'utf-8')
        pl['remarks'] = [tagName]
        pl = [(k,','.join(v)) for k,v in pl.items()]
        pl = urllib.parse.urlencode(pl)
        result = urllib.parse.urlunparse(('', result.netloc, obj.path, obj.params, pl, obj.fragment))
        if result.startswith('//'):
            result = result[2:]
        result = bytes(result,'utf-8')
        result = base64.b64encode(result)
        result = str(result, 'utf-8')
        result = obj.scheme + '://' + result
    else:
        result = urllib.parse.urlunparse(obj)
    print('New URL is:',result)
    return result

def getCountry(ipStr):
    '''
    geoip2.models.City({'city': {'geoname_id': 5045360, 'names': {'de': 'Saint Paul', 'en': 'Saint Paul', 'es': 'Saint Paul', 'fr': 'Saint Paul', 'ja': 'セントポール', 'pt-BR': 'Saint Paul', 'ru': 'Сент-Пол', 'zh-CN': '圣保罗'}}, 'continent': {'code': 'NA', 'geoname_id': 6255149, 'names': {'de': 'Nordamerika', 'en': 'North America', 'es': 'Norteamérica', 'fr': 'Amérique du Nord', 'ja': '北アメリカ', 'pt-BR': 'América do Norte', 'ru': 'Северная Америка', 'zh-CN': '北美洲'}}, 'country': {'geoname_id': 6252001, 'iso_code': 'US', 'names': {'de': 'USA', 'en': 'United States', 'es': 'Estados Unidos', 'fr': 'États-Unis', 'ja': 'アメリカ合衆国', 'pt-BR': 'Estados Unidos', 'ru': 'США', 'zh-CN': '美国'}}, 'location': {'accuracy_radius': 20, 'latitude': 44.9548, 'longitude': -93.1551, 'metro_code': 613, 'time_zone': 'America/Chicago'}, 'postal': {'code': '55104'}, 'registered_country': {'geoname_id': 6252001, 'iso_code': 'US', 'names': {'de': 'USA', 'en': 'United States', 'es': 'Estados Unidos', 'fr': 'États-Unis', 'ja': 'アメリカ合衆国', 'pt-BR': 'Estados Unidos', 'ru': 'США', 'zh-CN': '美国'}}, 'subdivisions': [{'geoname_id': 5037779, 'iso_code': 'MN', 'names': {'en': 'Minnesota', 'es': 'Minnesota', 'fr': 'Minnesota', 'ja': 'ミネソタ州', 'pt-BR': 'Minesota', 'ru': 'Миннесота', 'zh-CN': '明尼苏达州'}}], 'traits': {'ip_address': '128.101.101.101'}}, ['en'])
    geoip2.models.City({'continent': {'code': 'NA', 'geoname_id': 6255149, 'names': {'de': 'Nordamerika', 'en': 'North America', 'es': 'Norteamérica', 'fr': 'Amérique du Nord', 'ja': '北アメリカ', 'pt-BR': 'América do Norte', 'ru': 'Северная Америка', 'zh-CN': '北美洲'}}, 'country': {'geoname_id': 6252001, 'iso_code': 'US', 'names': {'de': 'USA', 'en': 'United States', 'es': 'EE. UU.', 'fr': 'États Unis', 'ja': 'アメリカ', 'pt-BR': 'EUA', 'ru': 'США', 'zh-CN': '美国'}}, 'location': {'accuracy_radius': 1000, 'latitude': 37.751, 'longitude': -97.822, 'time_zone': 'America/Chicago'}, 'registered_country': {'geoname_id': 6252001, 'iso_code': 'US', 'names': {'de': 'USA', 'en': 'United States', 'es': 'EE. UU.', 'fr': 'États Unis', 'ja': 'アメリカ', 'pt-BR': 'EUA', 'ru': 'США', 'zh-CN': '美国'}}, 'traits': {'ip_address': '172.252.64.49', 'prefix_len': 19}}, ['en'])
    '''
    # ipStr = str(ipStr,encoding='utf-8')
    dbpath = os.path.abspath("./GeoLite2/GeoLite2-City.mmdb")
    client = geoip2.database.Reader(dbpath)
    
    try:
        ipStr = socket.getaddrinfo(ipStr, None)
        ipStr = ipStr[0][4][0]
        response = client.city(ipStr)
        result = response.country.names['zh-CN']
    except:
        result = '未知'
    
    
    

    
    # print(response.country.iso_code)    # 国际标准码中的位置
    # print(response.location.latitude)   # 维度
    # print(response.location.longitude)   # 经度
    # print(response.location.time_zone)   # 时区
    # print(response.city.name)  # 城市 Saint Paul
    # print(response)   # 更多参考 ↓
    # print(result)
    # time.sleep(1/10)
    return result

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

def handleUrl(filename='fly'):
    with open("{}.txt".format(filename),"r") as f:
        urlList = f.readlines()
        
    with open("{}.txt".format(filename),"w") as f:
        f.seek(0)
        f.truncate()
    
    
    urlList = list(set(urlList))
    for url in sorted(urlList):
        print('Current test url is:',url)
        i,p,u = decode_url(url)
        if i is None:
            if i==p==u:
                # 另外处理
                continue
            else:
                print('Address is None')
                continue
        
        r = vaildAddress(i,p)
        print('Test url result is:',r)
        
        if r is False:
            continue
        
        with open("{}.txt".format(filename),'a+') as f:
            f.writelines(u + '\n')
            
def encrypt_base64(filename='fly'):
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
        rsp = requests.get(source, timeout=30)
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

def removeDuplicateData(filename='collection'):
    with open("{}.txt".format(filename),'r') as f:
        sl = f.readlines()
    
    sl = sorted(list(set(sl)))
    
    with open("{}.txt".format(filename),'w+') as f:
        f.write("".join(sl))

if __name__=="__main__":
    # with open('source.txt','r') as f:
    #     sourcelist = f.readlines()
        
    # for source in sourcelist:
    #     parse_from_source(source,'collection.txt')
    
    # removeDuplicateData()
    removeDuplicateData('fly')
        
    fList = walkFile()
    fList.remove('collection')
    fList.remove('source')
    fList.remove('test')
    for f in fList:
        handleUrl(f)
        encrypt_base64(f)
    