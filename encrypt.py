from ast import keyword
import base64
import json
import os
import pickle
import string
from unicodedata import name
import yaml
import re
import shutil
import socket
import time
import urllib
from xmlrpc.client import boolean

import geoip2.database
import requests

schemaList = ['ss','ssr','trojan','vless','vmess']

class URLParseHelper():
    
    def __init__(self,url=None) -> None:
        self.url = url
        self.geoDBPath = os.path.abspath("./GeoLite2/GeoLite2-City.mmdb")
        self.geoClient = geoip2.database.Reader(self.geoDBPath)
    
    def get_filepath(self,filename):
        return os.path.join(os.path.dirname(os.path.abspath(__file__)),filename)
      
    def parse(self, url=None):
        if url:
            self.url = urllib.parse.urlparse(url.strip('\n'))
        else:
            self.url = urllib.parse.urlparse(self.url.strip('\n'))
        
        self.body = self.url.netloc + self.url.path
        # print(self.url)
    
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
                
            if type(s)==bytes:
                # s = str(s, encoding='UTF-8')
                s = s.decode('UTF-8')
        except Exception as e:
            # s = s if type(s)==str else str(s)
            print(e,s)
        
        return s

    def encode(self,s:str, isurl=True):
        try:
            if isurl:
                s = base64.urlsafe_b64encode(bytes(s, 'utf-8'))
            else:
                s = base64.b64encode(bytes(s, 'utf-8'))
                
            if type(s)==bytes:
                # s = str(s, 'utf-8')
                s = s.decode('UTF-8')
        except Exception as e:
            print(e,s)
        return s

    def splitURL(self):
        _url = self.body if self.body.find('@')>0 else self.decode(self.body)
        ip_and_port = _url[::-1]
        ip_and_port = ip_and_port[:ip_and_port.find('@')]
        ip_and_port = ip_and_port[::-1]
        ip_and_port = ip_and_port.split(':')
        
        return ip_and_port[0],ip_and_port[1].replace("/", ""),_url
    
    def build_query(self,data):
        try:
            qList = []
            for k,v in data.items():
                v = v if v is not None else ''
                
                if k == '':
                    continue
                if k == 'tls':
                    if v=='tls':
                        v = '1'
                    elif v==False:
                        v = 'none'
                    elif v is None:
                        v = 'none'
                
                if v == True:
                    v = 'true'
                else:
                    v = 'false'
                
                if type(v) == list:
                    v = ','.join(v)
                elif type(v) == int:
                    v = str(v)
                elif type(v) == bool:
                    v = str(v)
                
                qList.append((k,v.strip().lower()))
            _query = urllib.parse.urlencode(qList)
            # _query = "&".join([ "{}={}".format(t[0],t[1]) for t in qList])
            # _query = "&".join([ "{}={}".format(k,str(v).lower()) for k,v in data.items() if v is not None])
        except Exception as e:
            print(data)
            with open('error.txt','a+') as f:
                f.write("build_query error: {},{}\n".format(e,data))
            raise(e)
        return _query
    
    def build_queryObj(self,querys=None,key=None,value=None):
        if querys:
            querys = urllib.parse.parse_qs(querys)
        else:
            querys = urllib.parse.parse_qs(self.url.query)
            
        if key and value:
            querys[key] = [value,]
            
        return querys


    def vaild(self,ipAddr:str,port:int):
        try:
            port = int(str(port).replace("'", ""))
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ipAddr,port))
        except Exception as e:
            result = -1
            with open('error.txt','a+') as f:
                f.write("URL Test Error,{},{},{}\n".format(e,ipAddr,port))
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
    
    def build_trojan(self,data):
        _scheme,_password,_ip,_port,_name = data.pop('type'),data.pop('password'),data.pop('server'),data.pop('port'),data.pop('name')
        url = "{}@{}:{}".format(_password,_ip,_port)
        
        # print(data)
        
        query = "&".join(["{}={}".format(k,str(v).lower()) for k,v in data.items()])

        url = (_scheme, url,'','',query,urllib.parse.quote(_name))
        url = urllib.parse.urlunparse(url)
        return url
    
    def build_vmess(self,data):
        """
        name: '🇯🇵 日本 ➤ 01'
        type: vmess
        server: jp01.startmy.cc
        port: 80
        uuid: b254acd1-b7ee-36d6-a0d7-718d5c079f1e
        alterId: 0
        cipher: auto
        udp: true
        servername: a.189.cn
        network: ws
        ws-opts:
            path: /v2ray
            headers: { Host: a.189.cn }
        ws-path: /v2ray
        ws-headers:
            Host: a.189.cn
        {
            "host": "", 
            "path": "/hls/cctv5phd.m3u8", 
            "tls": "", 
            "verify_cert": true, 
            "add": "jp21301.cloudmatrix.xyz", 
            "port": 21301, 
            "aid": 2, 
            "net": "ws", 
            "headerType":  "none", 
            "v": "2", 
            "type": "none", 
            "ps": "[中国VMESS]JP21301.CLOUDMATRIX.XYZ:21301", 
            "remark": "日本-东京1【1倍率】", 
            "id": "1469c8ff-4b3a-33fe-ab96-c8c831cacc47", 
            "class": 1
            }
            
        data = {
            "v": "2",
            "ps": data['name'], 
            "remark": data['name'], 
            "add": data['server'], 
            "port": data['port'], 
            "id": data['uuid'], 
            "aid": data['alterId'], 
            "security": "auto", 
            "scy": data['cipher'], 
            "net": data['network'], 
            "type": "none",
            "host": data['ws-headers']['Host'],
            "path": data['ws-path'],
            "tls": "", 
            "sni": ""
        }
        data = json.dumps(data,ensure_ascii=False)
        data = self.encode(data)
        """
        try:
            #=hk21201.cloudmatrix.xyz&path=/hls/cctv5phd.m3u8&obfs=&alterId=2
            _scheme,_security,_uuid,_address,_port,data['remarks'] = data.pop('type'), data.pop('cipher'),data.pop('uuid'),data.pop('server'),data.pop('port'),data.pop('name')
            url = "{}:{}@{}:{}".format(_security,_uuid,_address,_port)
            
            if data['network']=='ws':
                data['obfs'] = 'websocket'
                data.pop('network')
                if 'ws-opts' in data:
                    data['obfsParam'] = data['ws-opts']['headers']['Host']
                    data['path']= data['ws-opts']['path']
                    data.pop('ws-opts')
                    data.pop('ws-headers')
                    data.pop('ws-path')
                if 'servername' in data:    
                    data.pop('servername')
            data['remarks']  = urllib.parse.quote(data['remarks'])
            query = "&".join([ "{}={}".format(k,str(v).lower()) for k,v in data.items() ])
            url = urllib.parse.urlunparse((_scheme, self.encode(url), '','', query, ''))
            return url
        except Exception as e:
            print(e,data)
            raise(e)
    
    def build_ssr(self,data):
        """
        {
            'name': '香港 3', 
            'type': 'ssr', 
            'server': '42.157.196.252', 
            'port': 18584, 
            'cipher': 'rc4-md5', 
            'password': 'CvnbM0', 
            'protocol': 'origin', 
            'protocol-param': '', 
            'obfs': 'http_simple', 
            'obfs-param': 'download.windowsupdate.com'
        }

        """
        try:
            _scheme,_password,_ip,_port,data['remarks'] = data.pop('type'),data.pop('password'),data.pop('server'),data.pop('port'),data.pop('name')
            _protocol,_cipher,_pparam = data.pop('protocol'),data.pop('cipher'),data.pop('protocol-param') if 'protocol-param' in 'data' else ''
            url = "{}:{}:{}:{}:{}".format(_ip,_port,_protocol,_cipher,_pparam)

            data['remarks'] = urllib.parse.quote(data['remarks'])
            query = _password + "/?" + self.build_query(data)
            url += ":" + query
            url = _scheme + "://" + self.encode(url)
            return url
        except Exception as e:
            print(e,data)
            raise(e)
    
    def build_ss(self,data):
        """
        {
            'name': '🇦🇪AE_04', 
            'server': '217.138.193.10', 
            'type': 'ss', 
            'country': '🇦🇪AE', 
            'port': 800, 
            'password': 'G!yBwPWH3Vao', 
            'cipher': 'chacha20-ietf-poly1305'
        }
        """
        try:
            _scheme,_password,_ip,_port = data.pop('type'),data.pop('password'),data.pop('server'),data.pop('port')
            _cipher,_name = data.pop('cipher'),data.pop('name')
            print(_name)
            
            url = "{}://{}@{}:{}".format(_scheme,self.encode("{}:{}".format(_cipher,_password)),_ip,_port)
            
            _query = self.build_query(data)
            if _query:
                url += "?" + _query
            
            _name = _name if _name else 'clash'
            _name = urllib.parse.quote(_name) 
            url += "#" + _name
            
            
            
            return url
        except Exception as e:
            print(e,data)
            raise(e)
    
    def ssObj(self):
        _ip,_port,_url = self.splitURL()
        
        _newUrl = (self.url.scheme, self.url.netloc, self.url.path, self.url.params, self.url.query, self.getTagName(_ip,_port,True))
        _newUrl = urllib.parse.urlunparse(_newUrl)
        
        return _ip,_port,_newUrl
    
    def ssrObj(self):
        def parse_qs_ssr(url):
            _u = urllib.parse.urlparse(url.strip())
            return _u.path, urllib.parse.parse_qs(_u.query)

        _s1 = self.body[0:self.body.find('_')] if self.body.find('_')>0 else self.body
        _s = self.decode(_s1)
        _s = _s.strip().split(':')
        # print(_s)
        _tagName = self.getTagName(_s[0],_s[1])
        
        _url_path,_url_qs = parse_qs_ssr(_s[-1])
        # print(_url_qs)
        isexistRemarks = 'remarks' in _url_qs
        # if isexistRemarks:
        #     print(self.decode(_url_qs['remarks'][0].replace(" ", "+")))
        _url_qs['remarks'] = [self.encode(_tagName),]
        _s[-1] = _url_path + "?" + self.build_query(_url_qs)
        _s1 = _s1 if isexistRemarks else self.encode(":".join(_s))
        
        if self.body.find('_')>0:
            _newUrl = self.url.scheme + '://' + _s1 + '_' + self.encode('remarks={}'.format(_tagName))
        else:
            _newUrl = self.url.scheme + '://' + self.encode(":".join(_s))
        
        print(_newUrl)
        
        return _s[0], _s[1], _newUrl
    
    def trojanObj(self):
        return self.ssObj()
    
    def vlessObj(self):
        _ip,_port,_url = self.splitURL()

        _tagname = self.getTagName(_ip,_port,True)
        _query = self.build_queryObj(key='alpn',value=_tagname)
        _query = self.build_query(_query)
        
        _fragment = _tagname if self.url.fragment !='' else ''
            
        _newUrl  = urllib.parse.urlunparse((self.url.scheme, self.url.netloc, self.url.path, self.url.params, _query, _fragment))
        
        return _ip,_port,_newUrl
    
    def vmess2link(self,data):
        """
        {"add":"cc.hciahciphcie.club",
        "aid":0,
        "host":"cc.hciahciphcie.club",
        "id":"9a297bb1-06e3-4e6f-97fa-3d3202d46596",
        "net":"ws",
        "path":"/84c3f/",
        "port":443,
        "ps":"Relay_🇺🇸US-🇺🇸US_2225",
        "scy":"aes-128-gcm",
        "sni":"cc.hciahciphcie.club",
        "tls":"tls",
        "type":"none",
        "v":2
        }
        """
        # print(data)
        # data = {k:v for k,v in data.items() if k != ""}
        # data = {k:v for k,v in data.items() if v != ""}
        _security = data.pop('scy') if 'scy' in data else 'none'
        _uuid,_address,_port = data.pop('id'),data.pop('add'),data.pop('port')
        url = "{}:{}@{}:{}".format(_security,_uuid,_address,_port)

        data['remark'] = data.pop('ps')
        # data['remark']  = urllib.parse.quote(data['remark'])
        if 'alterId' not in data:
            data['alterId'] = data.pop('aid') if 'aid' in data else ''
        
        data['obfs']= data.pop('net')
        if data['obfs']=='ws':
            data['obfs']= 'websocket' 
            data['obfsParam'] = data.pop('host') if 'host' in data else ''
        
        if 'url_group' in data:
            data.pop('url_group')
        
        # url += "#" + self.build_query(data)
        url = urllib.parse.urlunparse(('vmess', self.encode(url), '','', self.build_query(data), ''))
        return url
    
    def vmessObj(self):
        try:
            _s = self.decode(self.body)
            _s = re.sub("\n",'',_s) or _s.strip()
            _s = re.sub(' ','',_s)
            
            if _s.find('{')==0:
                _s = json.loads(_s)
                _ipStr,_port = _s['add'],_s['port']
                _s['ps'] = self.getTagName(_ipStr,_port)
                _s = [_ipStr, _port, self.vmess2link(_s)]
            else:
                _ipStr,_port,_url = self.splitURL()
                
                query = self.build_queryObj(key='remark',value=self.getTagName(_ipStr, _port))
                query = self.build_query(query)
                
                print(query)
                
                _newUrl = urllib.parse.urlunparse((self.url.scheme, self.url.netloc, self.url.path, self.url.params, query, self.url.fragment))
                _s = [_ipStr, _port, _newUrl]
            
        except Exception as e:
            print('-'*50,'vmessObj Error:','-'*50)
            print(self.url,e)
            time.sleep(1)
            _s = [None,None, None]
                
        return _s
    
    def rebuild(self):
        try:
            if self.url.scheme == 'ss':
                r = self.ssObj()
            elif self.url.scheme == 'ssr':
                r = self.ssrObj()
            elif self.url.scheme == 'trojan':
                r = self.trojanObj()
            elif self.url.scheme == 'vless':
                r = self.vlessObj()
            elif self.url.scheme == 'vmess':
                r = self.vmessObj()
            else:
                r = [None,None,None]
        except Exception as e:
            print(e, self.url)
        return r

    def getSubscribeContent(self,subscribe,filename='collection.txt',outfile='fly.txt'):
        try:
            subscribe = re.sub('\n','',subscribe)
            print('='*50)
            print('source is: {}'.format(subscribe))
            print('='*50)
            
            rsp = requests.get(subscribe, timeout=5)
            if rsp.status_code==200:
                rsp = rsp.text
                rsp = re.sub('\n','',rsp)

                rsp = self.decode(rsp, False)
                lines = rsp.splitlines()
                time.sleep(3)
                
                with open(outfile,'r') as f:
                    existList = f.readlines()
                    
                for line in lines:
                    if line.startswith(tuple(['{}://'.format(s) for s in schemaList])):
                        if (line + '\n') not in existList:
                            print('Add URL is:',line)
                            with open(filename,"a+") as f2:
                                f2.write(line + '\n')
                            with open(outfile,"a+") as f3:
                                f3.write(line + '\n')
                        else:
                            print('Ignore the URL',line)
                    else:
                        continue
            else:
                print(rsp.status_code,rsp.url)
            
        except Exception as e:
            print(e,subscribe)

    def get_from_clash(self,subscribe,filename='collection.txt',outfile='fly.txt'):
        try:
            subscribe = re.sub('\n','',subscribe)
            print('='*50)
            print('source is: {}'.format(subscribe))
            print('='*50)
            content = requests.get(subscribe,timeout=5)
            if content.status_code==200:
                content = content.text
            else:
                return
                
            if len(content)<=0:
                return
            
            content = yaml.load(content, Loader=yaml.FullLoader)
            content = content['proxies']
            # print(content,type(content))
            
            with open(filename,'r') as f:
                existList = f.readlines()
            
            for data in content:
                if data['type']=='trojan':
                    url = self.build_trojan(data)
                elif data['type']=='vmess':
                    url = self.build_vmess(data)
                elif data['type']=='ssr':
                    url = self.build_ssr(data)
                elif data['type']=='ss':
                    url = self.build_ss(data)
                else:
                    url = ""
                    print("?"*50)
                    print(data)
                    print("?"*50)
                    time.sleep(3)
                
                if (url + '\n') not in existList:
                    print('Add URL is:',url)
                    with open(filename,"a+") as f2:
                        f2.write(url + '\n')
                    with open(outfile,"a+") as f3:
                        f3.write(url + '\n')
                else:
                    print('Ignore the URL',url)
        except Exception as e:
            raise(e)

        
def handleUrl(filename='fly.txt'):
    # filename = os.path.join(os.path.dirname(os.path.abspath(__file__)),filename)
    with open(filename,"r") as f:
        urlList = f.readlines()
        
    with open(filename,"w") as f:
        f.seek(0)
        f.truncate()
    
    
    urlObj = URLParseHelper()
    urlList = list(set(urlList))
    urlList = sorted(urlList)
    
    for index,url in enumerate(urlList):
        url = str(url) if type(url)==bytes else url
        print('Current url is:{}/{} {}'.format(index, len(urlList), url.strip()))
        
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
        print('Test result is:',r)
        
        if r is False:
            continue
        
        with open(filename,'a+') as f:
            f.writelines(u + '\n')
            
def splitFiles(filename="fly.txt"):
    filename = os.path.join(os.path.dirname(os.path.abspath(__file__)),filename)
    
    with open(filename,'r') as f:
        resultList = f.readlines()
          
    for sch in schemaList:
        sList = [u.strip() for u in resultList if u.startswith("{}://".format(sch))]
        
        with open('{}.txt'.format(sch),"w") as f:
            f.seek(0)
            f.truncate()
        
        for u in sList:
            if len(u)<=0:
                continue
            with open("{}.txt".format(u.split(':')[0]),'a+') as f:
                f.writelines(u + '\n')


def encrypt_base64(filename='fly.txt'):
    _file = os.path.join(os.path.dirname(os.path.abspath(__file__)),filename)
    print(_file.split('.')[:-1])
    
    if os.path.exists(_file)==False:
        return False
    
    removeDuplicateData(filename)
    with open(filename,"r+") as f:
        encodeStr = f.read()
        encodeStr = bytes(encodeStr,'utf-8')
        encodeStr = base64.b64encode(encodeStr)
        encodeStr = str(encodeStr, 'utf-8')
    
    with open(filename.split('.')[0],"w") as f:
        f.write(encodeStr)

def walkFile(file="."):
    fileList = []
    for root, dirs, files in os.walk(file):
        # for f in files:
        #     print(os.path.join(root, f))
            
        # for d in dirs:
        #     print(os.path.join(root, d))
        fileList += [f for f in files if f.endswith('txt')]
    return fileList

def removeDuplicateData(filename='collection.txt'):
    with open(filename,'r') as f:
        sl = f.readlines()
    
    sl = sorted(list(set(sl)))
    
    with open(filename,'w+') as f:
        f.write("".join(sl))

def run():
    u = URLParseHelper()
    
    with open('source.txt','r') as f:
        sourcelist = f.readlines()
        
    for index,source in enumerate(sourcelist) :
        print("********** Get Subscribe {}/{} **********".format(index+1,len(sourcelist)))
        time.sleep(1)
        u.getSubscribeContent(source)
    
    removeDuplicateData('collection.txt')
    
        
    # fList = walkFile()
    # fList.remove('collection')
    # fList.remove('source')
    # fList.remove('test')
    
    # for f in fList:
        # handleUrl(f)
        # removeDuplicateData('fly')
        
    handleUrl('fly.txt')
    encrypt_base64('fly.txt')
    
    splitFiles('fly.txt')
    for s in schemaList:
        encrypt_base64('{}.txt'.format(s))


def repair():
    aList = []
    filename = 'fly.txt'
            
    for s in schemaList:
        with open('{}.txt'.format(s)) as f:
            aList += f.readlines()
    
    with open(filename,"w") as f:
        f.seek(0)
        f.truncate()
        
    for u in aList:
        u = u.strip()
        if len(u)<=0:
            continue
        
        with open(filename,'a+') as f:
            f.writelines(u + '\n')
    
    if os.stat(filename).st_size==0:
        os.remove(filename)
        shutil.copy('collection.txt', filename)

def run_with_args():
    import argparse
    parser = argparse.ArgumentParser()

    parser.add_argument('--normal', type=int, required=False, default=0, help='normal')
    parser.add_argument('--repair', type=bool, required=False, default=False, help='repair')
    parser.add_argument('--encode', type=bool, required=False, default=False, help='encode')
    parser.add_argument('--debug', type=bool, required=False, default=False, help='debug')
    parser.add_argument('--str', type=str, required=False, default='', help='custom shop id')
    parser.add_argument('--need_more', type=bool, required=False, default=False, help='need detail')
    args = parser.parse_args()

    print(args)
    if args.repair == 1:
        print("1")
    if args.repair:
        print("2")
    if args.debug==True:
        print("3")
    else:
        print("4")


if __name__=="__main__":
    import sys
    u = URLParseHelper()
    args = sys.argv[1] if len(sys.argv)>=2 else '_'
    match args:
        case 'run':
            run()
        
        case 'source':
            with open('source.txt','r') as f:
                sourcelist = f.readlines()
                
            for source in sourcelist:
                u.getSubscribeContent(source)
            
            removeDuplicateData('collection.txt')
        
        case 'fly':
            handleUrl('fly.txt')
            encrypt_base64('fly.txt')
        
        case 'split':
            splitFiles('fly.txt')
        
        case 'encode':
            encrypt_base64('fly.txt')
            
            for s in schemaList:
                encrypt_base64('{}.txt'.format(s))
        
        case 'repair':
            repair()
            
        case 'clash':
            
            with open('clash.txt','r') as f:
                urlList = f.readlines()
            
            for url in urlList:
                u.get_from_clash(url)
                
        case 'clash2':
            with open('clash2.txt','r') as f:
                urlList = f.readlines()
            
            for url in urlList:
                if url.startswith("#"):
                    continue
                
                _params = "speed=30&type=ss,ssr,trojan,vless,vmess" #"speed=30&c=HK,TW,KR,JP,US&type=ss,ssr,vless,trojan,vmess"
                if url.find('?')>=0:
                    url += '&' + _params
                else: 
                    url += '?'  + _params
                    
                u.get_from_clash(url)
        case 'find':
            keyword = sys.argv[2]
            
            with open('collection.txt','r') as f:
                urlList = f.readlines()
                
            for url in urlList:
                u.parse(url)
                if url.find(keyword)>=0:
                    rst = u.rebuild()
                    print(url,rst)
                else:
                    if url.startswith("vmess"):
                        _s = u.decode(u.body)
                        if _s.find(keyword)>=0:
                            rst = u.rebuild()
                            print(url,_s,rst)
                    else:
                        continue
                
        case 'debug':
            # print(os.stat('fly2.txt').st_size)
            # vmess://YXV0bzphYmE1MGRkNC01NDg0LTNiMDUtYjE0YS00NjYxY2FmODYyZDVAMTkyLjk2LjIwNC4yNTA6NDQz?country=🇺🇸us&alterId=4&ws-path=/ws&ws-headers={'host': 'usa-washington.lvuft.com'}&http-opts={}&h2-opts={}&tls=true&skip-cert-verify=true&remarks=relay_%f0%9f%87%ba%f0%9f%87%b8us-%f0%9f%87%ba%f0%9f%87%b8us_2115&obfs=websocket

            # url = "YWVzLTI1Ni1jZmI6cnBnYk5uVTlyRERVNGFXWg"
            # u.parse(url)
            # rst = u.decode(url)
            # print(rst)
            removeDuplicateData()
            
        case _:
            print('Usage: %s [run | source | fly | split | encode | repair | debug | clash | clash2 | find ]' % sys.argv[0])
