from ast import keyword
import base64
import json
import os
import re
import shutil
import socket
import sys
import time
import urllib

import geoip2.database
import requests
import yaml

from geoip import getCountry

schemaList = ['ss', 'ssr', 'trojan', 'vless', 'vmess','http2']

def get_filepath(filename):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)

def splitFiles(filename="fly.txt"):
    filename = os.path.join(os.path.dirname(
        os.path.abspath(__file__)), filename)

    with open(filename, 'r', encoding='utf8') as f:
        resultList = [h.strip() for h in f.readlines()
                      if h.strip().startswith("#") == False]

    for sch in schemaList:
        sList = [u.strip()
                 for u in resultList if u.startswith("{}://".format(sch))]

        with open('{}.txt'.format(sch), "w", encoding='utf8') as f:
            f.seek(0)
            f.truncate()

        for u in sList:
            if len(u) <= 0:
                continue
            with open("{}.txt".format(u.split(':')[0]), 'a+', encoding='utf8') as f:
                f.writelines(u + '\n')

def encrypt_base64(filename='fly.txt'):
    _file = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    print(_file.split('.')[:-1])

    if os.path.exists(_file) == False:
        return False

    removeDuplicateData(filename)
    with open(filename, "r+", encoding='utf8') as f:
        encodeStr = f.read()
        encodeStr = bytes(encodeStr, 'utf-8')
        encodeStr = base64.b64encode(encodeStr)
        encodeStr = str(encodeStr, 'utf-8')

    with open(filename.split('.')[0], "w", encoding='utf8') as f:
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
    with open(filename, 'r', encoding='utf8') as f:
        sl = f.readlines()

    sl = sorted(list(set(sl)))

    with open(filename, 'w+', encoding='utf8') as f:
        f.write("".join(sl))

class URLParseHelper:
    def __init__(self, url=None, outfile='fly.txt', backupfile='collection.txt') -> None:
        self.url = url.strip() if url else ''
        self.urlObj = None
        self.body = None
        self.host = None
        self.port = None
        
        self.backupfile = get_filepath(backupfile)
        self.outfile = get_filepath(outfile)
        self.errorfile = get_filepath("error.txt")
        
    def parse(self, url=None):
        try:
            self.url = url.strip() if url else self.url
            self.urlObj = urllib.parse.urlparse(self.url.strip())
            self.body = self.urlObj.netloc + self.urlObj.path
            _url = self.body if self.body.find('@') > 0 else self.strDecode(self.body)
            
            host_and_port = _url[::-1]
            host_and_port = host_and_port[:host_and_port.find('@')]
            host_and_port = host_and_port[::-1]
            host_and_port = re.sub('\/|\'','',host_and_port)
            host_and_port = host_and_port.split(':')
            
            self.host = host_and_port[0]
            self.port = host_and_port[1].replace("/", "")

            return self.host,self.port, _url
        except:
            return None,None,None
    
    def vaild(self, ipAddr: str, port: int):
        try:
            port = int(str(port).replace("'", ""))
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ipAddr, port))
        except Exception as e:
            if str(e).find("nodename nor servname provided") > 0 and ipAddr not in ['使用前记得更新订阅', 'NULL', '8.8.8.8']:
                result = 0
            else:
                result = -1
            with open(self.errorfile , 'a+', encoding="utf8") as f:
                f.write("URL Test Error,{},{},{}\n".format(e, ipAddr, port))
        finally:
            print(f'Vaild Host Finished => [{ipAddr}:{port}] => Result is: {True if result == 0 else False}')
            return True if result == 0 else False
    
    def strDecode(self, s: str, isurl=True):
        s = re.sub('=', '', s)
        missing_padding = len(s) % 4
        if missing_padding != 0:
            s += '=' * (4 - missing_padding)

        try:
            if isurl:
                s = base64.urlsafe_b64decode(s)
            else:
                s = bytes(s, 'utf-8')
                s = base64.decodebytes(s)

            if type(s) == bytes:
                # s = str(s, encoding='UTF-8')
                s = s.decode('UTF-8')
        except Exception as e:
            # s = s if type(s)==str else str(s)
            print(e, s)

        return s

    def strEncode(self, s: str, isurl=True):
        try:
            if isurl:
                s = base64.urlsafe_b64encode(bytes(s, 'utf-8'))
            else:
                s = base64.b64encode(bytes(s, 'utf-8'))

            if type(s) == bytes:
                # s = str(s, 'utf-8')
                s = s.decode('UTF-8')
        except Exception as e:
            print(e, s)
        return s

    def build_query(self, data):
        try:
            if 'remarks' in data:
                data.pop('remarks')
            qList = []
            for k, v in data.items():
                if k == '':
                    continue
                
                v = ','.join(v) if isinstance(v, list) else v
                v = v if v else ''
                v = str(v) if isinstance(v, (bool, int, float))  else v

                if k == 'tls':
                    if v == 'tls':
                        v = '1'
                    elif v in (False,None):
                        v = 'none'
                # elif k == 'remark':
                #     v=self.strEncode(v)

                if v.startswith("{") and v.endswith("}"):
                    v = json.loads(v.replace("'", "\""))
                    v = ','.join([b for a, b in v.items()])

                qList.append((k, v.strip().lower()))
            _query = urllib.parse.urlencode(qList)
            # _query = "&".join([ "{}={}".format(t[0],t[1]) for t in qList])
            # _query = "&".join([ "{}={}".format(k,str(v).lower()) for k,v in data.items() if v is not None])
        except Exception as e:
            print(data)
            with open(self.errorfile , 'a+',encoding="utf8") as f:
                f.write("build_query error: {},{}\n".format(e, data))
            raise(e)
        return _query

    def build_queryObj(self, querys=None, key=None, value=None):
        if querys:
            querys = urllib.parse.parse_qs(querys)
        else:
            querys = urllib.parse.parse_qs(self.urlObj.query)
            
        print(querys)

        if key and value:
            querys[key] = [value, ]

        if 'alterId' in querys and 'aid' not in querys:
            querys['aid'] = querys['alterId']

        return querys

    def getTagName(self, ipStr, port, quote=False):
        if quote:
            return urllib.parse.quote('[{}{}]{}:{}'.format(getCountry(ipStr), self.urlObj.scheme.upper(), ipStr.upper(), port))
        else:
            return '[{}{}]{}:{}'.format(getCountry(ipStr), self.urlObj.scheme.upper(), ipStr.upper(), port)

    def ssObj(self):

        _newUrl = (self.urlObj.scheme, self.urlObj.netloc, self.urlObj.path,
                   self.urlObj.params, self.urlObj.query, self.getTagName(self.host, self.port, True))
        _newUrl = urllib.parse.urlunparse(_newUrl)

        return self.host, self.port, _newUrl
    
    def ssrObj(self):
        def parse_qs_ssr(url):
            _u = urllib.parse.urlparse(url.strip())
            return _u.path, urllib.parse.parse_qs(_u.query)
        
        a = self.body[0:self.body.find('_')] if self.body.find('_') > 0 else self.body
        alist = self.strDecode(a).strip().split(':')
        _tagName = self.getTagName(alist[0], alist[1])
        
        _url_path, _url_qs = parse_qs_ssr(alist[-1])
        if 'remarks' in _url_qs:
            _url_qs.pop('remarks')
        
        blist = alist[:-1]
        blist.append(_url_path + "?" + self.build_query(_url_qs))
        b = self.strEncode(":".join(blist))

        _newUrl = self.urlObj.scheme + '://' + b + '_' + self.strEncode('remarks={}'.format(_tagName))

        return alist[0], alist[1], _newUrl

    def vlessObj(self):
        _tagName = self.getTagName(self.host, self.port, True)
        _query = self.build_queryObj(key='alpn', value=_tagName)
        _query = self.build_query(_query)

        _fragment = _tagName if self.urlObj.fragment != '' else ''

        _newUrl = urllib.parse.urlunparse((self.urlObj.scheme, self.urlObj.netloc, self.urlObj.path, self.urlObj.params, _query, _fragment))

        return self.host, self.port, _newUrl
    
    def vlessObj2(self):
        _tagName = self.getTagName(self.host, self.port, True)
        if self.url.find("#")>0:
            _newUrl = self.url[0:self.url.find('#')] + "#" + _tagName
        else:
            _newUrl = self.url + "#" + _tagName

        return self.host, self.port, _newUrl

    def vmessObj(self):
        try:
            _s = self.strDecode(self.body)
            _s = re.sub("\n", '', _s) or _s.strip()
            _s = re.sub(' ', '', _s)
            
            if _s.find('{') == 0:
                _s = json.loads(_s)
                self.host,self.port = _s['add'], _s['port']
                
                _s['ps'] = self.getTagName(self.host,self.port)
                rst = [self.host, self.port, "vmess://{}".format(self.strEncode(json.dumps(_s),False))]
            else:
                
                try:
                    query = self.build_queryObj(key='remarks', value=self.getTagName(self.host, self.port))
                    query = self.build_query(query) + f'&remarks={self.getTagName(self.host, self.port,True)}'
                    print(query)
                    
                    _newUrl = urllib.parse.urlunparse((self.urlObj.scheme, self.urlObj.netloc, self.urlObj.path, self.urlObj.params, query, self.urlObj.fragment))
                    
                except Exception as e:
                    raise(e)
                
                rst = [self.host, self.port, _newUrl]

        except Exception as e:
            print('vmessObj Error:{}'.format(e).center(100,"-"))
            rst = [self.host, self.port, self.url]

        return rst

    def rebuild(self, url=None):
        try:
            self.url = url.strip() if url else self.url
            self.parse(self.url)

            match self.urlObj.scheme:

                case 'ss':
                    r = self.ssObj()
                case 'ssr':
                    r = self.ssrObj()
                case 'trojan':
                    r = self.ssObj()
                case 'vless':
                    r = self.vlessObj2()
                case 'vmess':
                    r = self.vmessObj()
                case 'http2':
                    r = self.ssObj()
                case _:
                    r = [None, None, None]
                    
        except Exception as e:
            print(e, self.urlObj)
            r = [None, None, None]
        return r
    
    def find(self,keyword):
        
        if self.url.find(keyword):
            return self.url
        if self.scheme in ['vmess','ssr']:
            if self.strDecode(self.body).find(keyword)>=0:
                return self.url

class fileHelper:
    
    def __init__(self,source_file='source.txt',out_file='fly.txt', backup_file='collection.txt',error_file='error.txt') -> None:
        self.source_file = get_filepath(source_file)
        self.out_file = get_filepath(out_file)
        self.backup_file = get_filepath(backup_file)
        self.error_file = get_filepath(error_file)


if __name__ == "__main__":
    uhelper = URLParseHelper()
    match sys.argv[1]:
        case 'debug':
            url = 'vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogIkBTU1JTVUIt5L+E572X5pavVjAxLeS7mOi0ueaOqOiNkDpkbGoudGYvc3Nyc3ViIiwNCiAgImFkZCI6ICJ2MS5zc3JzdWIuY29tIiwNCiAgInBvcnQiOiAiNDQzIiwNCiAgImlkIjogIjYyMGQ4MmE4LTIyYmEtNDk0NS05MGJhLWEyYmVkMWNkZTFkMiIsDQogICJhaWQiOiAiMCIsDQogICJzY3kiOiAiYXV0byIsDQogICJuZXQiOiAid3MiLA0KICAidHlwZSI6ICJub25lIiwNCiAgImhvc3QiOiAidjEuc3Nyc3ViLmNvbSIsDQogICJwYXRoIjogIi9hcGkvdjMvZG93bmxvYWQuZ2V0RmlsZSIsDQogICJ0bHMiOiAidGxzIiwNCiAgInNuaSI6ICIiLA0KICAiYWxwbiI6ICIiDQp9'
            # uhelper.parse(url)
            # rst = uhelper.find("v1.ssrsub.com")
            rst = uhelper.rebuild(url)
            print(rst)
            uhelper.vaild(rst[0],rst[1])

        case _:
            print('Usage: %s [run | source | fly | split | encode | repair | debug | clash | clash2 | find ]' % sys.argv[0])