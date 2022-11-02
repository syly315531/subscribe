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
# import yaml

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
    _file = get_filepath(filename)
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

def strDecode(s: str, isurl=True):
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

def strEncode(s: str, isurl=True):
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

def getResponse(url=None, dec=False,timeout=5):
        headers = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "accept-encoding": "gzip, deflate",
            "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36",
        }
        try:
            rsp = requests.get(url, headers=headers, timeout=timeout)
            if rsp.status_code == 200:
                rsp = rsp.text
                rsp = re.sub('\n', '', rsp)

                rsp = strDecode(rsp, False) if dec else rsp
                # time.sleep(3)
            else:
                print(rsp.status_code, rsp.url)
                raise(rsp.status_code)

        except Exception as e:
            rsp = ''
            # raise(e)

        # return rsp.splitlines()
        return rsp


class URLParseHelper:
    def __init__(self, url=None) -> None:
        self.url = url.strip() if url else ''
        self.urlObj = None
        self.body = None
        self.host = None
        self.port = None
        
    def parse(self, url=None):
        try:
            self.url = url.strip() if url else self.url
            self.urlObj = urllib.parse.urlparse(self.url.strip())
            self.body = self.urlObj.netloc + self.urlObj.path
            _url = self.body if self.body.find('@') > 0 else strDecode(self.body)
            
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
            with open(self.error_file , 'a+', encoding="utf8") as f:
                f.write("URL Test Error,{},{},{}\n".format(e, ipAddr, port))
        finally:
            print(f'Vaild Host Finished => [{ipAddr}:{port}] => Result is: {True if result == 0 else False}')
            return True if result == 0 else False
    
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
                #     v=strEncode(v)

                if v.startswith("{") and v.endswith("}"):
                    v = json.loads(v.replace("'", "\""))
                    v = ','.join([b for a, b in v.items()])

                qList.append((k, v.strip().lower()))
            _query = urllib.parse.urlencode(qList)
            # _query = "&".join([ "{}={}".format(t[0],t[1]) for t in qList])
            # _query = "&".join([ "{}={}".format(k,str(v).lower()) for k,v in data.items() if v is not None])
        except Exception as e:
            print(data)
            with open(self.error_file , 'a+',encoding="utf8") as f:
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
        alist = strDecode(a).strip().split(':')
        _tagName = self.getTagName(alist[0], alist[1])
        
        _url_path, _url_qs = parse_qs_ssr(alist[-1])
        if 'remarks' in _url_qs:
            _url_qs.pop('remarks')
        
        blist = alist[:-1]
        blist.append(_url_path + "?" + self.build_query(_url_qs))
        b = strEncode(":".join(blist))

        _newUrl = self.urlObj.scheme + '://' + b + '_' + strEncode('remarks={}'.format(_tagName))

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
            _s = strDecode(self.body)
            _s = re.sub("\n", '', _s) or _s.strip()
            _s = re.sub(' ', '', _s)
            
            if _s.find('{') == 0:
                _s = json.loads(_s)
                self.host,self.port = _s['add'], _s['port']
                
                _s['ps'] = self.getTagName(self.host,self.port)
                rst = [self.host, self.port, "vmess://{}".format(strEncode(json.dumps(_s),False))]
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
            if strDecode(self.body).find(keyword)>=0:
                return self.url


class fileHelper:
    
    def __init__(self,source_file='source.txt',out_file='fly.txt', backup_file='collection.txt',error_file='error.txt',ignore_file="ignore.txt") -> None:
        self.source_file = get_filepath(source_file)
        self.out_file = get_filepath(out_file)
        self.backup_file = get_filepath(backup_file)
        self.error_file = get_filepath(error_file)

        self.exist_list = self.read(self.backup_file)
        self.ignore_list = self.read(get_filepath(ignore_file))

    def add(self,url,chk=False):
        url = url.strip()
        if chk:
            with open(self.out_file,"r",encoding="utf8") as f:
                _alist= [h.strip() for h in f.readlines()]
            if url in _alist:
                return "This URL is Exist"
            
        with open(self.out_file,"a+",encoding="utf8") as f:
            f.write(url+"\n")

        print("Add a URL:" + url)

    def read(self,file=None):
        file = file if file else self.source_file
        removeDuplicateData(file)
        with open(file, 'r', encoding='utf8') as f:
            sourcelist = [h.strip() for h in f.readlines() if h.strip().startswith("#") == False]
        return sourcelist

    def write(self, url):
        url = url.strip()
        if url not in self.exist_list:
            self.add(url)
            with open(self.backup_file, "a+", encoding='utf8') as f3:
                f3.write(url + '\n')
        else:
            print('Ignore the URL', url)

    def getSubscribeContent(self, subscribe):
        try:
            subscribe = re.sub('\n', '', subscribe)
            print('='*50)
            print('source is: {}'.format(subscribe))
            print('='*50)

            lines = getResponse(subscribe, True)
            lines = lines.splitlines()

            for line in lines:
                if line.startswith(tuple(['{}://'.format(s) for s in schemaList])):
                    self.write(line)
                else:
                    continue

        except Exception as e:
            print(e, subscribe)

            raise(e)

    def getSubscribeContent_all(self):
        sourcelist = self.read(self.source_file)
        for index, source in enumerate(sourcelist):
            print("********** Get Subscribe {}/{} **********".format(index+1, len(sourcelist)))
            if source.startswith("#"):
                continue
            self.getSubscribeContent(source)

        removeDuplicateData(self.backup_file)

    def get_from_clash(self, subscribe):
        try:
            subscribe = re.sub('\n', '', subscribe)
            print('='*50)
            print('source is: {}'.format(subscribe))
            print('='*50)
            content = requests.get(subscribe, timeout=5)
            if content.status_code == 200:
                content = content.text
            else:
                return

            if len(content) <= 0:
                return

            content = yaml.load(content, Loader=yaml.FullLoader)
            content = content['proxies']
            # print(content,type(content))

            for data in content:
                if data['type'] == 'trojan':
                    url = self.build_trojan(data)
                elif data['type'] == 'vmess':
                    url = self.build_vmess(data)
                elif data['type'] == 'ssr':
                    url = self.build_ssr(data)
                elif data['type'] == 'ss':
                    url = self.build_ss(data)
                else:
                    url = ""
                    print("?"*50)
                    print(data)
                    print("?"*50)
                    # time.sleep(3)

                self.write(url)

        except Exception as e:
            return None
            # raise(e)

    def splitFiles(self,filename=None):
        filename = get_filepath(filename) if filename else self.out_file

        resultList = self.read(filename)

        for sch in schemaList:
            sList = [u.strip() for u in resultList if u.startswith("{}://".format(sch))]

            with open('{}.txt'.format(sch), "w", encoding='utf8') as f:
                f.seek(0)
                f.truncate()

            for u in sList:
                if len(u) <= 0:
                    continue
                with open("{}.txt".format(u.split(':')[0]), 'a+', encoding='utf8') as f:
                    f.writelines(u + '\n')
            
            encrypt_base64('{}.txt'.format(sch))
   
    def handleUrl(self, filename=None):
        u = URLParseHelper()
        self.out_file = get_filepath(filename) if filename else self.out_file
        urlList = self.read(self.out_file)
        urlList = list(set(urlList))
        urlList = sorted(urlList)

        with open(self.out_file, "w", encoding='utf8') as f:
            f.seek(0)
            f.truncate()

        for index, url in enumerate(urlList):
            url = str(url) if type(url) == bytes else url
            
            print('Current url is:{}/{} {}'.format(index, len(urlList), url.strip()))

            _host,_port, _i = u.rebuild(url)
            if _host is None:
                print('Address is None')
                continue

            if _host in self.ignore_list:
                continue

            r = u.vaild(_host, _port)
            print('Test result is:', r)

            if r is False:
                continue

            self.add(_i)
            print('-'*100, '\n')

    def run(self):
        self.getSubscribeContent_all()
        self.handleUrl(self.out_file)
        # clean_error()
        removeDuplicateData(self.out_file)
        removeDuplicateData(self.error_file)
        encrypt_base64(self.out_file)

        self.splitFiles(self.out_file)

    def clash(self):
        clashfiles = ['clash.txt', 'clash2.txt']

        for cf in clashfiles:
            urlList = self.read(get_filepath(cf))

            for index, url in enumerate(urlList):
                print(
                    "********** Get Subscribe {}/{} **********".format(index+1, len(urlList)))

                if cf == 'clash2.txt':
                    # "speed=30&c=HK,TW,KR,JP,US&type=ss,ssr,vless,trojan,vmess"
                    _params = "speed=30&type=" + ",".join(schemaList)

                    if url.find('?') >= 0:
                        url += '&' + _params
                    else:
                        url += '?' + _params

                self.get_from_clash(url)


if __name__ == "__main__":
    uhelper = URLParseHelper()
    fhelper = fileHelper()
    match sys.argv[1]:
        case 'run':
            rst = fhelper.run()

        case 'debug':
            fhelper.splitFiles()
            
        case 'debug2':
            url = 'vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogIkBTU1JTVUIt5L+E572X5pavVjAxLeS7mOi0ueaOqOiNkDpkbGoudGYvc3Nyc3ViIiwNCiAgImFkZCI6ICJ2MS5zc3JzdWIuY29tIiwNCiAgInBvcnQiOiAiNDQzIiwNCiAgImlkIjogIjYyMGQ4MmE4LTIyYmEtNDk0NS05MGJhLWEyYmVkMWNkZTFkMiIsDQogICJhaWQiOiAiMCIsDQogICJzY3kiOiAiYXV0byIsDQogICJuZXQiOiAid3MiLA0KICAidHlwZSI6ICJub25lIiwNCiAgImhvc3QiOiAidjEuc3Nyc3ViLmNvbSIsDQogICJwYXRoIjogIi9hcGkvdjMvZG93bmxvYWQuZ2V0RmlsZSIsDQogICJ0bHMiOiAidGxzIiwNCiAgInNuaSI6ICIiLA0KICAiYWxwbiI6ICIiDQp9'
            rst = uhelper.rebuild(url)
            print(rst)
            uhelper.vaild(rst[0],rst[1])

        case _:
            print('Usage: %s [run | source | fly | split | encode | repair | debug | clash | clash2 | find ]' % sys.argv[0])