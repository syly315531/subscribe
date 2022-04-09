import base64
import json
import os
import re
import socket
import time
import urllib
import pickle

import geoip2.database
import requests

class URLParseHelper():
    
    def __init__(self) -> None:
        self.url = None
        self.geoDBPath = os.path.abspath("./GeoLite2/GeoLite2-City.mmdb")
        self.geoClient = geoip2.database.Reader(self.geoDBPath)
        
    def parse(self, url):
        self.url = urllib.parse.urlparse(url.strip('\n'))
        self.body = self.url.netloc + self.url.path
    
    def decode(self,s:str, isurl=True):
        s = re.sub('=','',s)
        missing_padding = len(s) % 4
        if missing_padding != 0:
            s += '='* (4 - missing_padding)
        
        try:
            if isurl:
                s = base64.urlsafe_b64decode(s)
            else:
                s = bytes(s, 'utf-8')
                s = base64.decodebytes(s)
            s = str(s, encoding='utf-8')
        except Exception as e:
            s = s if type(s)==str else str(s)
            print(e,s)
        
        return s

    def encode(self,s:str, isurl=True):
        try:
            if isurl:
                s = base64.urlsafe_b64encode(bytes(s, 'utf-8'))
            else:
                s = base64.b64encode(bytes(s, 'utf-8'))
            s = str(s, 'utf-8')
        except Exception as e:
            print(e,s)
        return s

    def vaild(self,ipAddr:str,port:int):
        try:
            port = int(str(port).replace("'", ""))
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ipAddr,port))
        except Exception as e:
            result = -1
            print(e,ipAddr,port)
        finally:
            print('Tested',ipAddr,port)
            return True if result == 0 else False
    
    def getCountry(self,ipStr:str):
        '''
        geoip2.models.City({'city': {'geoname_id': 5045360, 'names': {'de': 'Saint Paul', 'en': 'Saint Paul', 'es': 'Saint Paul', 'fr': 'Saint Paul', 'ja': 'セントポール', 'pt-BR': 'Saint Paul', 'ru': 'Сент-Пол', 'zh-CN': '圣保罗'}}, 'continent': {'code': 'NA', 'geoname_id': 6255149, 'names': {'de': 'Nordamerika', 'en': 'North America', 'es': 'Norteamérica', 'fr': 'Amérique du Nord', 'ja': '北アメリカ', 'pt-BR': 'América do Norte', 'ru': 'Северная Америка', 'zh-CN': '北美洲'}}, 'country': {'geoname_id': 6252001, 'iso_code': 'US', 'names': {'de': 'USA', 'en': 'United States', 'es': 'Estados Unidos', 'fr': 'États-Unis', 'ja': 'アメリカ合衆国', 'pt-BR': 'Estados Unidos', 'ru': 'США', 'zh-CN': '美国'}}, 'location': {'accuracy_radius': 20, 'latitude': 44.9548, 'longitude': -93.1551, 'metro_code': 613, 'time_zone': 'America/Chicago'}, 'postal': {'code': '55104'}, 'registered_country': {'geoname_id': 6252001, 'iso_code': 'US', 'names': {'de': 'USA', 'en': 'United States', 'es': 'Estados Unidos', 'fr': 'États-Unis', 'ja': 'アメリカ合衆国', 'pt-BR': 'Estados Unidos', 'ru': 'США', 'zh-CN': '美国'}}, 'subdivisions': [{'geoname_id': 5037779, 'iso_code': 'MN', 'names': {'en': 'Minnesota', 'es': 'Minnesota', 'fr': 'Minnesota', 'ja': 'ミネソタ州', 'pt-BR': 'Minesota', 'ru': 'Миннесота', 'zh-CN': '明尼苏达州'}}], 'traits': {'ip_address': '128.101.101.101'}}, ['en'])
        geoip2.models.City({'continent': {'code': 'NA', 'geoname_id': 6255149, 'names': {'de': 'Nordamerika', 'en': 'North America', 'es': 'Norteamérica', 'fr': 'Amérique du Nord', 'ja': '北アメリカ', 'pt-BR': 'América do Norte', 'ru': 'Северная Америка', 'zh-CN': '北美洲'}}, 'country': {'geoname_id': 6252001, 'iso_code': 'US', 'names': {'de': 'USA', 'en': 'United States', 'es': 'EE. UU.', 'fr': 'États Unis', 'ja': 'アメリカ', 'pt-BR': 'EUA', 'ru': 'США', 'zh-CN': '美国'}}, 'location': {'accuracy_radius': 1000, 'latitude': 37.751, 'longitude': -97.822, 'time_zone': 'America/Chicago'}, 'registered_country': {'geoname_id': 6252001, 'iso_code': 'US', 'names': {'de': 'USA', 'en': 'United States', 'es': 'EE. UU.', 'fr': 'États Unis', 'ja': 'アメリカ', 'pt-BR': 'EUA', 'ru': 'США', 'zh-CN': '美国'}}, 'traits': {'ip_address': '172.252.64.49', 'prefix_len': 19}}, ['en'])
        '''
        try:
            ipStr   = socket.getaddrinfo(ipStr, None)
            ipStr   = ipStr[0][4][0]
            result  = self.geoClient.city(ipStr)
            result  = result.country.names['zh-CN']
        except:
            result = '未知'
        
        # print(response.country.iso_code)    # 国际标准码中的位置
        # print(response.location.latitude)   # 维度
        # print(response.location.longitude)   # 经度
        # print(response.location.time_zone)   # 时区
        # print(response.city.name)  # 城市 Saint Paul
        # print(response)   # 更多参考 ↓
        # print(result)
        return result
    
    def getTagName(self,ipStr,port,quote=False):
        if quote:
            return urllib.parse.quote('[{}{}]{}:{}'.format(self.getCountry(ipStr),self.url.scheme.upper(),ipStr.upper(),port))
        else:
            return '[{}{}]{}:{}'.format(self.getCountry(ipStr),self.url.scheme.upper(),ipStr.upper(),port)
    
    def ssObj(self):
        _s = self.body if self.body.find('@')>0 else self.decode(self.body)
        _s = _s[_s.find('@')+1:]
        _s = _s.split(':')
        _newUrl = (self.url.scheme, self.url.netloc, self.url.path, self.url.params, self.url.query, self.getTagName(_s[0],_s[1],True))
        _newUrl = urllib.parse.urlunparse(_newUrl)
        _s.append(_newUrl)
        return _s
    
    def ssrObj(self):
        _s1 = self.body[0:self.body.find('_')] if self.body.find('_')>0 else self.body
        _s = self.decode(_s1)
        _s = _s.strip().split(':')
        _tagName = self.getTagName(_s[0],_s[1])
        _tagName = 'remarks=' + self.encode(_tagName)
        _tagName = self.encode(_tagName)
        _newUrl  = self.url.scheme + '://' + _s1 + '_' + _tagName
        _s = [_s[0],_s[1],_newUrl]
        return _s
    
    def trojanObj(self):
        return self.ssObj()
    
    def vlessObj(self):
        _s = self.body if self.body.find('@')>0 else self.decode(self.body)
        _s = _s[_s.find('@')+1:]
        _s = _s.split(':')
        _n = self.getTagName(_s[0],_s[1],True)
        _tagname = urllib.parse.parse_qs(self.url.query)
        _tagname['alpn'] = [_n]
        _tagname = [(k,','.join(v)) for k,v in _tagname.items()]
        _tagname = urllib.parse.urlencode(_tagname)
        if self.url.fragment !='':
            _fragment = _n
        else:
            _fragment = ''
        _newUrl  = urllib.parse.urlunparse((self.url.scheme, self.url.netloc, self.url.path, self.url.params, _tagname, _fragment))
        _s.append(_newUrl)
        return _s
    
    def vmessObj(self):
        _s = self.decode(self.body)
        _s = re.sub("\n",'',_s)
        _s = re.sub(' ','',_s)
        try:
            _s = json.loads(_s)
            _ipStr = _s['add']
            _port  = _s['port']
            _s['ps'] = self.getTagName(_s['add'],_s['port'])
            _s = json.dumps(_s,ensure_ascii=False)
            _s = self.encode(_s)
            _newUrl = urllib.parse.urlunparse((self.url.scheme, _s, '', self.url.params, self.url.query, self.url.fragment))
            _s = [_ipStr, _port, _newUrl]
        except:
            try:
                _s = _s[_s.find('@')+1:]
                if _s.find(':')>0:
                    _ipStr, _port = _s.split(':')
                    _queryObj = urllib.parse.parse_qs(self.url.query)
                    _queryObj['remarks'] = [self.getTagName(_ipStr, _port)]
                    _queryObj['title'] = [self.getTagName(_ipStr, _port)]
                    _queryObj = [(k,','.join(v)) for k,v in _queryObj.items()]
                    _queryObj = urllib.parse.urlencode(_queryObj)
                    _newUrl = urllib.parse.urlunparse((self.url.scheme, self.url.netloc, self.url.path, self.url.params, _queryObj, self.url.fragment))
                    _s = [_ipStr, _port, _newUrl]
                else:
                    _s = [None,None, None]
            except:
                print(self.url)
                print('-'*100)
                time.sleep(5)
                _s = [None,None, None]
                
        return _s
    
    def rebuild(self):
        if self.url.scheme == 'ss':
            r = self.ssObj()
        elif self.url.scheme == 'ssr':
            r = self.ssrObj()
        elif self.url.scheme == 'torjan':
            r = self.trojanObj()
        elif self.url.scheme == 'vless':
            r = self.vlessObj()
        elif self.url.scheme == 'vmess':
            r = self.vmessObj()
        else:
            r = [None,None,None]
        return r

    def getSubscribeContent(self,subscribe,filename='collection.txt'):
        try:
            subscribe = re.sub('\n','',subscribe)
            print('='*50)
            print('source is: {}'.format(subscribe))
            print('='*50)
            rsp = requests.get(subscribe, timeout=30)
            if rsp.status_code==200:
                rsp = rsp.text
                rsp = re.sub('\n','',rsp)
                rsp = self.decode(rsp, False)
                lines = rsp.splitlines()
                time.sleep(3)
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
            print(e,subscribe)


def handleUrl(filename='fly'):
    with open("{}.txt".format(filename),"r") as f:
        urlList = f.readlines()
        
    with open("{}.txt".format(filename),"w") as f:
        f.seek(0)
        f.truncate()
    
    
    urlObj = URLParseHelper()
    urlList = list(set(urlList))
    
    for url in sorted(urlList):
        url = str(url) if type(url)==bytes else url
        print('Current test url is:',url)
        
        urlObj.parse(url)
        i,p,u = urlObj.rebuild()
        
        if i is None:
            if i==p==u:
                # with open("{}.txt".format(filename),'a+') as f:
                #     f.writelines(url + '\n')
                continue
            else:
                print('Address is None')
                continue
        
        r = urlObj.vaild(i,p)
        print('Test url result is:',r)
        
        if r is False:
            continue
        
        with open("{}.txt".format(u.split(':')[0]),'a+') as f:
            f.writelines(u + '\n')
            
def encrypt_base64(filename='fly'):
    removeDuplicateData(filename)
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

def removeDuplicateData(filename='collection'):
    with open("{}.txt".format(filename),'r') as f:
        sl = f.readlines()
    
    sl = sorted(list(set(sl)))
    
    with open("{}.txt".format(filename),'w+') as f:
        f.write("".join(sl))

if __name__=="__main__":
    u = URLParseHelper()
    
    with open('source.txt','r') as f:
        sourcelist = f.readlines()
        
    for source in sourcelist:
        u.getSubscribeContent(source)
    
    removeDuplicateData('collection')
    
        
    # fList = walkFile()
    # fList.remove('collection')
    # fList.remove('source')
    # # fList.remove('test')
    # for f in fList:
        # handleUrl(f)
        # removeDuplicateData('fly')
        
    handleUrl('collection')
    
    encrypt_base64('ss')
    encrypt_base64('ssr')
    # encrypt_base64('torjan')
    encrypt_base64('vmess')
    
    # removeDuplicateData('fly')
    # encrypt_base64()
    
    # with open('collection.txt','r') as f:
    #     urls = f.readlines()
    # for url in urls:
    #     if url.startswith('vmess'):
    #         u.parse(url)
    #         print(u.rebuild())
    #     else:
    #         continue