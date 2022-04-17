import base64
import json
import os
import pickle
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
        # print(_url_qs)
        _s[-1] = _url_path + "?" + "&".join(['{}={}'.format(k,','.join(v)) for k,v in _url_qs.items()])
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
        _s = re.sub("\n",'',_s) or _s.strip()
        _s = re.sub(' ','',_s)
        # print(_s)
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
            
            rsp = requests.get(subscribe, timeout=30)
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
        print('Current url is:{}/{} {}'.format(index, len(urlList), url))
        
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
    
    args = sys.argv[1] if len(sys.argv)>=2 else '_'
    match args:
        case 'run':
            run()
        
        case 'source':
            u = URLParseHelper()
    
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
            
        case 'debug':
            # print(os.stat('fly2.txt').st_size)
            url ='ssr://c2hjbjJ0b2hrdDY2LmdnYm95bmV4dGRvb3IuYmVzdDo0OTA0MTphdXRoX2FlczEyOF9tZDU6cmM0LW1kNTp0bHMxLjJfdGlja2V0X2F1dGg6YkVkQ1RVNVAvP29iZnNwYXJhbT1PV1kzWXpRME1UY3pMbVJ2ZDI1c2IyRmtMbmRwYm1SdmQzTjFjR1JoZEdVdVkyOXQmcHJvdG9wYXJhbT1OREUzTXpwUGNsVmlaMEkmcmVtYXJrcz1RMDVmNUxxTTU0aTM1Nys3NWFLWjU3MlJhSFIwY0hNNkx5OHhPREE0TG1kaFh6RXpPQT09Jmdyb3VwPTZidVk2SzZrNVlpRzU3dUU=_cmVtYXJrcz1b5Lit5Zu9U1NSXVNIQ04yVE9IS1Q2Ni5HR0JPWU5FWFRET09SLkJFU1Q6NDkwNDE='
            
            
            urlHelper = URLParseHelper()
            
            with open('ssr.txt','r') as f:
                urlList = f.readlines()
                
            for url in urlList:
                print(url)
                urlHelper.parse(url)
                res = urlHelper.rebuild()
            
        case _:
            print('Usage: %s [run | source | fly | split | encode | repair | debug ]' % sys.argv[0])
