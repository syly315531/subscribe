import base64
import json
import os
import re
import shutil
import socket
import sys
import time
import urllib

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
    filePath = get_filepath(filename)
    print(filePath.split('.')[:-1])

    if os.path.exists(filePath) == False:
        return False

    removeDuplicateData(filePath)
    with open(filePath, "r+", encoding='utf8') as f:
        encodeStr = f.read()
        encodeStr = bytes(encodeStr, 'utf-8')
        encodeStr = base64.b64encode(encodeStr)
        encodeStr = str(encodeStr, 'utf-8')

    with open(filePath.split('.')[0], "w", encoding='utf8') as f:
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
            s = bytes(s, 'utf-8') if isinstance(s,str) else s
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

def is_base64_code(s):
    '''Check s is Base64.b64encode'''
    if not isinstance(s, str) or not s:
        return "params s not string or None"

    _base64_code = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
                    'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
                    'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a',
                    'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
                    'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
                    't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1',
                    '2', '3', '4', '5', '6', '7', '8', '9', '+',
                    '/', '=']
    _base64_code_set = set(_base64_code)  # 转为set增加in判断时候的效率
    # Check base64 OR codeCheck % 4
    code_fail = [i for i in s if i not in _base64_code_set]
    if code_fail or len(s) % 4 != 0:
        return False
    return True

def isBase64(sb):
    '''Check s is Base64.b64encode'''
    try:
        if isinstance(sb, str):
                # If there's any unicode here, an exception will be thrown and the function will return false
            sb_bytes = bytes(sb, 'ascii')
        elif isinstance(sb, bytes):
            sb_bytes = sb
        else:
            raise ValueError("Argument must be string or bytes")
        return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes
    except Exception as e:
        print(e)
        return False

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
            if self.url.find('_')>0:
                self.urlObj = urllib.parse.urlparse(self.url[0:self.url.find('_')])
            else:
                self.urlObj = urllib.parse.urlparse(self.url)
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
        
        def splitParamsDict(s):
            s= s.strip()
            s = urllib.parse.parse_qs(s)
            s = { k: ",".join(v) if v else v for k,v in s.items()}
            return s
        
        def joinParamsDict(s:dict):
            s = [ f'{k}={v}' for k,v in s.items()]
            s = "&".join(s)
            return s
        
        a = strDecode(self.body).strip()
        alist = a.split(":")
        _tagName = self.getTagName(alist[0], alist[1])


        if self.url.find('_')>0:
            params = strDecode(self.url[self.url.find('_')+1:])
            params = splitParamsDict(params)
            params['remarks'] = strEncode(_tagName)
            params = joinParamsDict(params)

            _newUrl = self.urlObj.scheme + '://' + self.body + '_' + strEncode(params)
        else:
            # params = splitParamsDict(a.split('?')[1]) if a.find('?')>0 else {}
            # for k,v in params.items():
            #     print(strDecode(v))
            # params['remarks'] = _tagName
            # params = joinParamsDict(params)

            # b = a.split('?')[0] if a.find('?')>0 else a
            # b = strEncode(b+"?"+params)

            # _newUrl = self.urlObj.scheme + '://' + b
            _newUrl = self.url

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
        try:
            if self.url.find(keyword)>=0:
                return self.url
            if self.urlObj.scheme in ['vmess','ssr']:
                if strDecode(self.body).find(keyword)>=0:
                    return self.url
        except Exception as e:
            print(e)
            print(self.url)
            print(self.body)
            print("*"*100)

class fileHelper:
    
    def __init__(self,source_file='source.txt',out_file='fly.txt', backup_file='collection.txt',error_file='error.txt',ignore_file="ignore.txt") -> None:
        self.source_file = get_filepath(source_file)
        self.out_file = get_filepath(out_file)
        self.backup_file = get_filepath(backup_file)
        self.error_file = get_filepath(error_file)

        self.exist_list = self.read(self.out_file)
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
            if lines:
                lines = lines.splitlines()
            else:
                return

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

    def find(self, keyword):
        print(keyword)
        u = URLParseHelper()
        rst_list = []
        for url in self.exist_list:
            url = url.strip()
            u.parse(url)
            rst = u.find(keyword)
            if rst:
                rst_list.append(u.url)
            # if url.find(keyword) >= 0:
            #     rst.append((url, self.rebuild(), None))
            # else:
            #     if url.startswith("vmess") or url.startswith("ssr"):
            #         _s = self.strDecode(self.body)
            #         if _s.find(keyword) >= 0:
            #             rst.append((url, self.rebuild(), _s))
            #         else:
            #             continue

        return rst_list


if __name__ == "__main__":
    uhelper = URLParseHelper()
    fhelper = fileHelper()
    match sys.argv[1]:
        case 'subscribe':
            fhelper.clash()
            fhelper.getSubscribeContent_all()

        case 'handle':
            fhelper.handleUrl(fhelper.out_file)
            # clean_error()
            removeDuplicateData(fhelper.out_file)
            removeDuplicateData(fhelper.error_file)
            encrypt_base64(fhelper.out_file)

        case 'split':
            fhelper.splitFiles(fhelper.out_file)

        case 'run':
            fhelper.clash()
            fhelper.run()
            
        case 'clash':
            fhelper.clash()
            
        case 'split':
            fhelper.splitFiles()
            
        case 'debug':
            s ='abcdefgh'
            print(is_base64_code(s))
            print(isBase64(s))
        
        case 'detail':
            url = 'ssr://d3ouc2FmZXRlbGVzY29wZS5jYzo0NjU2MjphdXRoX2FlczEyOF9tZDU6YWVzLTI1Ni1jZmI6dGxzMS4yX3RpY2tldF9hdXRoOmFFZHJVVFk1TVRWMFJBLz9yZW1hcmtzPSZwcm90b3BhcmFtPU1USTBPVEUxT2tsVWVUSkRiSGhSUkZZJm9iZnNwYXJhbT1ZV3BoZUM1dGFXTnliM052Wm5RdVkyOXQ'
            url = 'ssr://d3ouc2FmZXRlbGVzY29wZS5jYzo0NjU2MjphdXRoX2FlczEyOF9tZDU6YWVzLTI1Ni1jZmI6dGxzMS4yX3RpY2tldF9hdXRoOmFFZHJVVFk1TVRWMFJBLz9wcm90b3BhcmFtPU1USTBPVEUxT2tsVWVUSkRiSGhSUkZZJm9iZnNwYXJhbT1ZV3BoZUM1dGFXTnliM052Wm5RdVkyOXQmcmVtYXJrcz1b5Lit5Zu9U1NSXVdaLlNBRkVURUxFU0NPUEUuQ0M6NDY1NjI='
            print(url)
            rst = uhelper.rebuild(url)
            uhelper.vaild(rst[0],rst[1])
            
            print(rst)
            print(strDecode(uhelper.body))
            if url.find('_')>0:
                print(strDecode(url[url.find('_')+1:]))
        
        case 'test':
            s1 = "c3NyOi8vZVdNdWMyRm1aWFJsYkdWelkyOXdaUzVqWXpveU1UY3dNanBoZFhSb1gyRmxjekV5T0Y5dFpEVTZZV1Z6TFRJMU5pMWpabUk2ZEd4ek1TNHlYM1JwWTJ0bGRGOWhkWFJvT21GRlpISlZWRmsxVFZSV01GSkJMejl2WW1aemNHRnlZVzA5V1Zkd2FHVkROWFJoVjA1NVlqTk9kbHB1VVhWWk1qbDBKbkJ5YjNSdmNHRnlZVzA5VFZSSk1FMUVRVEpQYTNCRlQxVXdNMkZ0UmpOYWVtY21jbVZ0WVhKcmN6MDJZV0ZhTlhKcGRsRlRNSGhOWldGamFVUlFiV3cyV0cxdE4xUnRiSEpCSm1keWIzVndQV1JIWm5CdmNFaHdaMXBOTmxGSVNuQmpSMFoyWVcxc2JGcEhiR2hpWncKc3NyOi8vZVhwNVpDMHdNUzVqWTNSbGJHVnpZMjl3WlM1NGVYbzZNakF3TURFNllYVjBhRjloWlhNeE1qaGZiV1ExT21GbGN5MHlOVFl0WTJaaU9uUnNjekV1TWw5MGFXTnJaWFJmWVhWMGFEcGhSV1J5VlZSWk5VMVVWakJTUVM4X2IySm1jM0JoY21GdFBWbFhjR2hsUXpWMFlWZE9lV0l6VG5aYWJsRjFXVEk1ZENad2NtOTBiM0JoY21GdFBVMVVTVEJOUkVFeVQydHdSVTlWTUROaGJVWXpXbnBuSm5KbGJXRnlhM005Tm1GaFdqVnlhWFpSYVRFd1dpMXRhV3RsYlVKcmVuQkJZMjFzZDFsWE9YRmhWMVpyWVZkR2RTWm5jbTkxY0Qxa1IyWndiM0JJY0dkYVRUWlJTRXB3WTBkR2RtRnRiR3hhUjJ4b1ltYwpzc3I6Ly9kM291YzJGbVpYUmxiR1Z6WTI5d1pTNWpZem94TWpBeU1UcGhkWFJvWDJGbGN6RXlPRjl0WkRVNllXVnpMVEkxTmkxalptSTZkR3h6TVM0eVgzUnBZMnRsZEY5aGRYUm9PbUZGWkhKVlZGazFUVlJXTUZKQkx6OXZZbVp6Y0dGeVlXMDlXVmR3YUdWRE5YUmhWMDU1WWpOT2RscHVVWFZaTWpsMEpuQnliM1J2Y0dGeVlXMDlUVlJKTUUxRVFUSlBhM0JGVDFVd00yRnRSak5hZW1jbWNtVnRZWEpyY3owMllXRmFOWEpwZGxGNU1UQmFMVzFwYTJWdFFtdDZjRUZqYld4M1dWYzVjV0ZYVm10aFYwWjFKbWR5YjNWd1BXUkhabkJ2Y0Vod1oxcE5ObEZJU25CalIwWjJZVzFzYkZwSGJHaGladwpzc3I6Ly9lWHA1WkMwd01TNWpZM1JsYkdWelkyOXdaUzU0ZVhvNk16QXdNRE02WVhWMGFGOWhaWE14TWpoZmJXUTFPbUZsY3kweU5UWXRZMlppT25Sc2N6RXVNbDkwYVdOclpYUmZZWFYwYURwaFJXUnlWVlJaTlUxVVZqQlNRUzhfYjJKbWMzQmhjbUZ0UFZsWGNHaGxRelYwWVZkT2VXSXpUblphYmxGMVdUSTVkQ1p3Y205MGIzQmhjbUZ0UFUxVVNUQk5SRUV5VDJ0d1JVOVZNRE5oYlVZelducG5KbkpsYldGeWEzTTlObG90Y0RWYWRUbFJVekV3V2kxdGFXdGxiVUpyZW5CQlkyMXNkMWxYT1hGaFYxWnJZVmRHZFNabmNtOTFjRDFrUjJad2IzQkljR2RhVFRaUlNFcHdZMGRHZG1GdGJHeGFSMnhvWW1jCnNzcjovL2Qzb3VjMkZtWlhSbGJHVnpZMjl3WlM1all6b3lPRE0yT0RwaGRYUm9YMkZsY3pFeU9GOXRaRFU2WVdWekxUSTFOaTFqWm1JNmRHeHpNUzR5WDNScFkydGxkRjloZFhSb09tRkZaSEpWVkZrMVRWUldNRkpCTHo5dlltWnpjR0Z5WVcwOVdWZHdhR1ZETlhSaFYwNTVZak5PZGxwdVVYVlpNamwwSm5CeWIzUnZjR0Z5WVcwOVRWUkpNRTFFUVRKUGEzQkZUMVV3TTJGdFJqTmFlbWNtY21WdFlYSnJjejAyVEdGTE5Wa3lXRkZUTVRCYUxXMXBhMlZ0UW10NmNFRmpiV3gzV1ZjNWNXRlhWbXRoVjBaMUptZHliM1Z3UFdSSFpuQnZjRWh3WjFwTk5sRklTbkJqUjBaMllXMXNiRnBIYkdoaVp3CnNzcjovL2VYcDVaQzB3TVM1alkzUmxiR1Z6WTI5d1pTNTRlWG82TkRrd016WTZZWFYwYUY5aFpYTXhNamhmYldRMU9tRmxjeTB5TlRZdFkyWmlPblJzY3pFdU1sOTBhV05yWlhSZllYVjBhRHBoUldSeVZWUlpOVTFVVmpCU1FTOF9iMkptYzNCaGNtRnRQVmxYY0dobFF6VjBZVmRPZVdJelRuWmFibEYxV1RJNWRDWndjbTkwYjNCaGNtRnRQVTFVU1RCTlJFRXlUMnR3UlU5Vk1ETmhiVVl6V25wbkpuSmxiV0Z5YTNNOU5reGhTelZaTWxoUmFURXdXaTF0YVd0bGJVSnJlbkJCWTIxc2QxbFhPWEZoVjFacllWZEdkU1puY205MWNEMWtSMlp3YjNCSWNHZGFUVFpSU0Vwd1kwZEdkbUZ0Ykd4YVIyeG9ZbWMKc3NyOi8vZDNvdWMyRm1aWFJsYkdWelkyOXdaUzVqWXpveE1EQXdOanBoZFhSb1gyRmxjekV5T0Y5dFpEVTZZV1Z6TFRJMU5pMWpabUk2ZEd4ek1TNHlYM1JwWTJ0bGRGOWhkWFJvT21GRlpISlZWRmsxVFZSV01GSkJMejl2WW1aemNHRnlZVzA5V1Zkd2FHVkROWFJoVjA1NVlqTk9kbHB1VVhWWk1qbDBKbkJ5YjNSdmNHRnlZVzA5VFZSSk1FMUVRVEpQYTNCRlQxVXdNMkZ0UmpOYWVtY21jbVZ0WVhKcmN6MDJTWFY0TlZwMU9WRlllREJhTFcxcGEyVnRRbXQ2Y0VGamJXeDNXVmM1Y1dGWFZtdGhWMFoxSm1keWIzVndQV1JIWm5CdmNFaHdaMXBOTmxGSVNuQmpSMFoyWVcxc2JGcEhiR2hpWncKc3NyOi8vZVdNdWMyRm1aWFJsYkdWelkyOXdaUzVqWXpveU1UWXpNanBoZFhSb1gyRmxjekV5T0Y5dFpEVTZZV1Z6TFRJMU5pMWpabUk2ZEd4ek1TNHlYM1JwWTJ0bGRGOWhkWFJvT21GRlpISlZWRmsxVFZSV01GSkJMejl2WW1aemNHRnlZVzA5V1Zkd2FHVkROWFJoVjA1NVlqTk9kbHB1VVhWWk1qbDBKbkJ5YjNSdmNHRnlZVzA5VFZSSk1FMUVRVEpQYTNCRlQxVXdNMkZ0UmpOYWVtY21jbVZ0WVhKcmN6MDFOelpQTlZwMU9WRlllREJhTFcxcGEyVnRRbXQ2Y0VGamJXeDNXVmM1Y1dGWFZtdGhWMFoxSm1keWIzVndQV1JIWm5CdmNFaHdaMXBOTmxGSVNuQmpSMFoyWVcxc2JGcEhiR2hpWncKc3NyOi8vZVhwNVpDMHdNUzVqWTNSbGJHVnpZMjl3WlM1NGVYbzZOVEEwTURJNllYVjBhRjloWlhNeE1qaGZiV1ExT21GbGN5MHlOVFl0WTJaaU9uUnNjekV1TWw5MGFXTnJaWFJmWVhWMGFEcGhSV1J5VlZSWk5VMVVWakJTUVM4X2IySm1jM0JoY21GdFBWbFhjR2hsUXpWMFlWZE9lV0l6VG5aYWJsRjFXVEk1ZENad2NtOTBiM0JoY21GdFBVMVVTVEJOUkVFeVQydHdSVTlWTUROaGJVWXpXbnBuSm5KbGJXRnlhM005TlhKUGR6VmFkVGxSVXpFd1dpMXRhV3RsYlVKcmVuQkJZMjFzZDFsWE9YRmhWMVpyWVZkR2RTWm5jbTkxY0Qxa1IyWndiM0JJY0dkYVRUWlJTRXB3WTBkR2RtRnRiR3hhUjJ4b1ltYwpzc3I6Ly9lWHA1WkMwd01TNWpZM1JsYkdWelkyOXdaUzU0ZVhvNk1qY3dNek02WVhWMGFGOWhaWE14TWpoZmJXUTFPbUZsY3kweU5UWXRZMlppT25Sc2N6RXVNbDkwYVdOclpYUmZZWFYwYURwaFJXUnlWVlJaTlUxVVZqQlNRUzhfYjJKbWMzQmhjbUZ0UFZsWGNHaGxRelYwWVZkT2VXSXpUblphYmxGMVdUSTVkQ1p3Y205MGIzQmhjbUZ0UFUxVVNUQk5SRUV5VDJ0d1JVOVZNRE5oYlVZelducG5KbkpsYldGeWEzTTlOWEpQVmpWYWRUbG1TRkp1Tm1GTFVqWlpSMVJQYTBKNVlWaENhR0l5Y0hCYVYxSndXVmMwSm1keWIzVndQV1JIWm5CdmNFaHdaMXBOTmxGSVNuQmpSMFoyWVcxc2JGcEhiR2hpWncKc3NyOi8vZVdNdWMyRm1aWFJsYkdWelkyOXdaUzVqWXpveU1UQTNPRHBoZFhSb1gyRmxjekV5T0Y5dFpEVTZZV1Z6TFRJMU5pMWpabUk2ZEd4ek1TNHlYM1JwWTJ0bGRGOWhkWFJvT21GRlpISlZWRmsxVFZSV01GSkJMejl2WW1aemNHRnlZVzA5V1Zkd2FHVkROWFJoVjA1NVlqTk9kbHB1VVhWWk1qbDBKbkJ5YjNSdmNHRnlZVzA5VFZSSk1FMUVRVEpQYTNCRlQxVXdNMkZ0UmpOYWVtY21jbVZ0WVhKcmN6MDFjR1ZzTlhCNWMxRlRNVEJhTFcxcGEyVnRRbXQ2Y0VGamJXeDNXVmM1Y1dGWFZtdGhWMFoxSm1keWIzVndQV1JIWm5CdmNFaHdaMXBOTmxGSVNuQmpSMFoyWVcxc2JGcEhiR2hpWncKc3NyOi8vZDNvdWMyRm1aWFJsYkdWelkyOXdaUzVqWXpvME5qVTJNanBoZFhSb1gyRmxjekV5T0Y5dFpEVTZZV1Z6TFRJMU5pMWpabUk2ZEd4ek1TNHlYM1JwWTJ0bGRGOWhkWFJvT21GRlpISlZWRmsxVFZSV01GSkJMejl2WW1aemNHRnlZVzA5V1Zkd2FHVkROWFJoVjA1NVlqTk9kbHB1VVhWWk1qbDBKbkJ5YjNSdmNHRnlZVzA5VFZSSk1FMUVRVEpQYTNCRlQxVXdNMkZ0UmpOYWVtY21jbVZ0WVhKcmN6MDFjR0YzTlZseFp6VmFNbWhSV0hnd1dpMXRhV3RsYlVKcmVuQkJZMjFzZDFsWE9YRmhWMVpyWVZkR2RTWm5jbTkxY0Qxa1IyWndiM0JJY0dkYVRUWlJTRXB3WTBkR2RtRnRiR3hhUjJ4b1ltYwpzc3I6Ly9lWHA1WkMwd01TNWpZM1JsYkdWelkyOXdaUzU0ZVhvNk5UQTRNREk2WVhWMGFGOWhaWE14TWpoZmJXUTFPbUZsY3kweU5UWXRZMlppT25Sc2N6RXVNbDkwYVdOclpYUmZZWFYwYURwaFJXUnlWVlJaTlUxVVZqQlNRUzhfYjJKbWMzQmhjbUZ0UFZsWGNHaGxRelYwWVZkT2VXSXpUblphYmxGMVdUSTVkQ1p3Y205MGIzQmhjbUZ0UFUxVVNUQk5SRUV5VDJ0d1JVOVZNRE5oYlVZelducG5KbkpsYldGeWEzTTlOVmt0ZHpWeWJTMVJVekV3V2kxdGFXdGxiVUpyZW5CQlkyMXNkMWxYT1hGaFYxWnJZVmRHZFNabmNtOTFjRDFrUjJad2IzQkljR2RhVFRaUlNFcHdZMGRHZG1GdGJHeGFSMnhvWW1jCnNzcjovL2VXTXVjMkZtWlhSbGJHVnpZMjl3WlM1all6b3lNVFl6TnpwaGRYUm9YMkZsY3pFeU9GOXRaRFU2WVdWekxUSTFOaTFqWm1JNmRHeHpNUzR5WDNScFkydGxkRjloZFhSb09tRkZaSEpWVkZrMVRWUldNRkpCTHo5dlltWnpjR0Z5WVcwOVdWZHdhR1ZETlhSaFYwNTVZak5PZGxwdVVYVlpNamwwSm5CeWIzUnZjR0Z5WVcwOVRWUkpNRTFFUVRKUGEzQkZUMVV3TTJGdFJqTmFlbWNtY21WdFlYSnJjejAxV1RKM05XSnhiV1pJVW00MllVdFNObGxIVkU5clFubGhXRUpvWWpKd2NGcFhVbkJaVnpRbVozSnZkWEE5WkVkbWNHOXdTSEJuV2swMlVVaEtjR05IUm5aaGJXeHNXa2RzYUdKbgpzc3I6Ly9lWHA1WkMwd01TNWpZM1JsYkdWelkyOXdaUzU0ZVhvNk1qWXdPVFk2WVhWMGFGOWhaWE14TWpoZmJXUTFPbUZsY3kweU5UWXRZMlppT25Sc2N6RXVNbDkwYVdOclpYUmZZWFYwYURwaFJXUnlWVlJaTlUxVVZqQlNRUzhfYjJKbWMzQmhjbUZ0UFZsWGNHaGxRelYwWVZkT2VXSXpUblphYmxGMVdUSTVkQ1p3Y205MGIzQmhjbUZ0UFUxVVNUQk5SRUV5VDJ0d1JVOVZNRE5oYlVZelducG5KbkpsYldGeWEzTTlOVXd0UlRVM01sZzFjR0YyWmtoU2JqWmhTMUkyV1VkVVQydENlV0ZZUW1oaU1uQndXbGRTY0ZsWE5DWm5jbTkxY0Qxa1IyWndiM0JJY0dkYVRUWlJTRXB3WTBkR2RtRnRiR3hhUjJ4b1ltYwpzc3I6Ly9lWHA1WkMwd01TNWpZM1JsYkdWelkyOXdaUzU0ZVhvNk5UQTRNRFE2WVhWMGFGOWhaWE14TWpoZmJXUTFPbUZsY3kweU5UWXRZMlppT25Sc2N6RXVNbDkwYVdOclpYUmZZWFYwYURwaFJXUnlWVlJaTlUxVVZqQlNRUzhfYjJKbWMzQmhjbUZ0UFZsWGNHaGxRelYwWVZkT2VXSXpUblphYmxGMVdUSTVkQ1p3Y205MGIzQmhjbUZ0UFUxVVNUQk5SRUV5VDJ0d1JVOVZNRE5oYlVZelducG5KbkpsYldGeWEzTTlObUZoV2pWeWFYWlNRekV3V2kxdGFXdGxiVUpyZW5CQlkyMXNkMWxYT1hGaFYxWnJZVmRHZFNabmNtOTFjRDFrUjJad2IzQkljR2RhVFRaUlNFcHdZMGRHZG1GdGJHeGFSMnhvWW1jCnNzcjovL1ozcDVaQzB3TVM1alkzUmxiR1Z6WTI5d1pTNTRlWG82TkRFNU9UZzZZWFYwYUY5aFpYTXhNamhmYldRMU9tRmxjeTB5TlRZdFkyWmlPblJzY3pFdU1sOTBhV05yWlhSZllYVjBhRHBoUldSeVZWUlpOVTFVVmpCU1FTOF9iMkptYzNCaGNtRnRQVmxYY0dobFF6VjBZVmRPZVdJelRuWmFibEYxV1RJNWRDWndjbTkwYjNCaGNtRnRQVTFVU1RCTlJFRXlUMnR3UlU5Vk1ETmhiVVl6V25wbkpuSmxiV0Z5YTNNOU5tRmhXalZ5YVhaU1V6RXdXaTF0YVd0bGJVSnJlbkJCWTIxc2QxbFhPWEZoVjFacllWZEdkU1puY205MWNEMWtSMlp3YjNCSWNHZGFUVFpSU0Vwd1kwZEdkbUZ0Ykd4YVIyeG9ZbWMKc3NyOi8vZDNvdWMyRm1aWFJsYkdWelkyOXdaUzVqWXpveE1EQXlNRHBoZFhSb1gyRmxjekV5T0Y5dFpEVTZZV1Z6TFRJMU5pMWpabUk2ZEd4ek1TNHlYM1JwWTJ0bGRGOWhkWFJvT21GRlpISlZWRmsxVFZSV01GSkJMejl2WW1aemNHRnlZVzA5V1Zkd2FHVkROWFJoVjA1NVlqTk9kbHB1VVhWWk1qbDBKbkJ5YjNSdmNHRnlZVzA5VFZSSk1FMUVRVEpQYTNCRlQxVXdNMkZ0UmpOYWVtY21jbVZ0WVhKcmN6MDJXaTF3TlZwMU9WRnBNVEJhTFcxcGEyVnRRbXQ2Y0VGamJXeDNXVmM1Y1dGWFZtdGhWMFoxSm1keWIzVndQV1JIWm5CdmNFaHdaMXBOTmxGSVNuQmpSMFoyWVcxc2JGcEhiR2hpWncKc3NyOi8vZVdNdWMyRm1aWFJsYkdWelkyOXdaUzVqWXpveU1UVTJNenBoZFhSb1gyRmxjekV5T0Y5dFpEVTZZV1Z6TFRJMU5pMWpabUk2ZEd4ek1TNHlYM1JwWTJ0bGRGOWhkWFJvT21GRlpISlZWRmsxVFZSV01GSkJMejl2WW1aemNHRnlZVzA5V1Zkd2FHVkROWFJoVjA1NVlqTk9kbHB1VVhWWk1qbDBKbkJ5YjNSdmNHRnlZVzA5VFZSSk1FMUVRVEpQYTNCRlQxVXdNMkZ0UmpOYWVtY21jbVZ0WVhKcmN6MDJXbWxmTlhGRE5UVmlkVE5tU0ZKdU5tRkxValpaUjFSUGEwSjVZVmhDYUdJeWNIQmFWMUp3V1ZjMEptZHliM1Z3UFdSSFpuQnZjRWh3WjFwTk5sRklTbkJqUjBaMllXMXNiRnBIYkdoaVp3CnNzcjovL2VXTXVjMkZtWlhSbGJHVnpZMjl3WlM1all6b3lNVEk1TXpwaGRYUm9YMkZsY3pFeU9GOXRaRFU2WVdWekxUSTFOaTFqWm1JNmRHeHpNUzR5WDNScFkydGxkRjloZFhSb09tRkZaSEpWVkZrMVRWUldNRkpCTHo5dlltWnpjR0Z5WVcwOVdWZHdhR1ZETlhSaFYwNTVZak5PZGxwdVVYVlpNamwwSm5CeWIzUnZjR0Z5WVcwOVRWUkpNRTFFUVRKUGEzQkZUMVV3TTJGdFJqTmFlbWNtY21WdFlYSnJjejAyU1MxNU5XSTJURFZoTmkxbVNGSnVObUZMVWpaWlIxUlBhMEo1WVZoQ2FHSXljSEJhVjFKd1dWYzBKbWR5YjNWd1BXUkhabkJ2Y0Vod1oxcE5ObEZJU25CalIwWjJZVzFzYkZwSGJHaGladwpzc3I6Ly9lV011YzJGbVpYUmxiR1Z6WTI5d1pTNWpZem95TVRJMk1UcGhkWFJvWDJGbGN6RXlPRjl0WkRVNllXVnpMVEkxTmkxalptSTZkR3h6TVM0eVgzUnBZMnRsZEY5aGRYUm9PbUZGWkhKVlZGazFUVlJXTUZKQkx6OXZZbVp6Y0dGeVlXMDlXVmR3YUdWRE5YUmhWMDU1WWpOT2RscHVVWFZaTWpsMEpuQnliM1J2Y0dGeVlXMDlUVlJKTUUxRVFUSlBhM0JGVDFVd00yRnRSak5hZW1jbWNtVnRZWEpyY3owMlNYVjROVnAxT1ZGdWVEQmFMVzFwYTJWdFFtdDZjRUZqYld4M1dWYzVjV0ZYVm10aFYwWjFKbWR5YjNWd1BXUkhabkJ2Y0Vod1oxcE5ObEZJU25CalIwWjJZVzFzYkZwSGJHaGladwpzc3I6Ly9kM291YzJGbVpYUmxiR1Z6WTI5d1pTNWpZem94TURBd05UcGhkWFJvWDJGbGN6RXlPRjl0WkRVNllXVnpMVEkxTmkxalptSTZkR3h6TVM0eVgzUnBZMnRsZEY5aGRYUm9PbUZGWkhKVlZGazFUVlJXTUZKQkx6OXZZbVp6Y0dGeVlXMDlXVmR3YUdWRE5YUmhWMDU1WWpOT2RscHVVWFZaTWpsMEpuQnliM1J2Y0dGeVlXMDlUVlJKTUUxRVFUSlBhM0JGVDFVd00yRnRSak5hZW1jbWNtVnRZWEpyY3owMU56WlBOVnAxT1ZGdWVEQmFMVzFwYTJWdFFtdDZjRUZqYld4M1dWYzVjV0ZYVm10aFYwWjFKbWR5YjNWd1BXUkhabkJ2Y0Vod1oxcE5ObEZJU25CalIwWjJZVzFzYkZwSGJHaGladwpzc3I6Ly9lV011YzJGbVpYUmxiR1Z6WTI5d1pTNWpZem95TVRBNU9UcGhkWFJvWDJGbGN6RXlPRjl0WkRVNllXVnpMVEkxTmkxalptSTZkR3h6TVM0eVgzUnBZMnRsZEY5aGRYUm9PbUZGWkhKVlZGazFUVlJXTUZKQkx6OXZZbVp6Y0dGeVlXMDlXVmR3YUdWRE5YUmhWMDU1WWpOT2RscHVVWFZaTWpsMEpuQnliM1J2Y0dGeVlXMDlUVlJKTUUxRVFUSlBhM0JGVDFVd00yRnRSak5hZW1jbWNtVnRZWEpyY3owMU5VZGxOVmxYTkdaSVVtNDJZVXRTTmxsSFZFOXJRbmxoV0VKb1lqSndjRnBYVW5CWlZ6UW1aM0p2ZFhBOVpFZG1jRzl3U0hCbldrMDJVVWhLY0dOSFJuWmhiV3hzV2tkc2FHSm4Kc3NyOi8vZVhwNVpDMHdNUzVqWTNSbGJHVnpZMjl3WlM1NGVYbzZOVEF6TVRJNllYVjBhRjloWlhNeE1qaGZiV1ExT21GbGN5MHlOVFl0WTJaaU9uUnNjekV1TWw5MGFXTnJaWFJmWVhWMGFEcGhSV1J5VlZSWk5VMVVWakJTUVM4X2IySm1jM0JoY21GdFBWbFhjR2hsUXpWMFlWZE9lV0l6VG5aYWJsRjFXVEk1ZENad2NtOTBiM0JoY21GdFBVMVVTVEJOUkVFeVQydHdSVTlWTUROaGJVWXpXbnBuSm5KbGJXRnlhM005TlhCbGJEVndlWE5SV0hnd1dpMXRhV3RsYlVKcmVuQkJZMjFzZDFsWE9YRmhWMVpyWVZkR2RTWm5jbTkxY0Qxa1IyWndiM0JJY0dkYVRUWlJTRXB3WTBkR2RtRnRiR3hhUjJ4b1ltYwpzc3I6Ly9kM291YzJGbVpYUmxiR1Z6WTI5d1pTNWpZem94TURBeE9UcGhkWFJvWDJGbGN6RXlPRjl0WkRVNllXVnpMVEkxTmkxalptSTZkR3h6TVM0eVgzUnBZMnRsZEY5aGRYUm9PbUZGWkhKVlZGazFUVlJXTUZKQkx6OXZZbVp6Y0dGeVlXMDlXVmR3YUdWRE5YUmhWMDU1WWpOT2RscHVVWFZaTWpsMEpuQnliM1J2Y0dGeVlXMDlUVlJKTUUxRVFUSlBhM0JGVDFVd00yRnRSak5hZW1jbWNtVnRZWEpyY3owMWNHVnNOWEI1YzFGdWVEQmFMVzFwYTJWdFFtdDZjRUZqYld4M1dWYzVjV0ZYVm10aFYwWjFKbWR5YjNWd1BXUkhabkJ2Y0Vod1oxcE5ObEZJU25CalIwWjJZVzFzYkZwSGJHaGladwpzc3I6Ly9lWHA1WkMwd01TNWpZM1JsYkdWelkyOXdaUzU0ZVhvNk5UQXpNRFk2WVhWMGFGOWhaWE14TWpoZmJXUTFPbUZsY3kweU5UWXRZMlppT25Sc2N6RXVNbDkwYVdOclpYUmZZWFYwYURwaFJXUnlWVlJaTlUxVVZqQlNRUzhfYjJKbWMzQmhjbUZ0UFZsWGNHaGxRelYwWVZkT2VXSXpUblphYmxGMVdUSTVkQ1p3Y205MGIzQmhjbUZ0UFUxVVNUQk5SRUV5VDJ0d1JVOVZNRE5oYlVZelducG5KbkpsYldGeWEzTTlOWEJoZHpWWmNXYzFXakpvVVc1NE1Gb3RiV2xyWlcxQ2EzcHdRV050YkhkWlZ6bHhZVmRXYTJGWFJuVW1aM0p2ZFhBOVpFZG1jRzl3U0hCbldrMDJVVWhLY0dOSFJuWmhiV3hzV2tkc2FHSm4Kc3NyOi8vZVhwNVpDMHdNUzVqWTNSbGJHVnpZMjl3WlM1NGVYbzZNekF3TURJNllYVjBhRjloWlhNeE1qaGZiV1ExT21GbGN5MHlOVFl0WTJaaU9uUnNjekV1TWw5MGFXTnJaWFJmWVhWMGFEcGhSV1J5VlZSWk5VMVVWakJTUVM4X2IySm1jM0JoY21GdFBWbFhjR2hsUXpWMFlWZE9lV0l6VG5aYWJsRjFXVEk1ZENad2NtOTBiM0JoY21GdFBVMVVTVEJOUkVFeVQydHdSVTlWTUROaGJVWXpXbnBuSm5KbGJXRnlhM005TlZrdGR6VnliUzFSYVRFd1dpMXRhV3RsYlVKcmVuQkJZMjFzZDFsWE9YRmhWMVpyWVZkR2RTWm5jbTkxY0Qxa1IyWndiM0JJY0dkYVRUWlJTRXB3WTBkR2RtRnRiR3hhUjJ4b1ltYwpzc3I6Ly9kM291YzJGbVpYUmxiR1Z6WTI5d1pTNWpZem94TURBd056cGhkWFJvWDJGbGN6RXlPRjl0WkRVNllXVnpMVEkxTmkxalptSTZkR3h6TVM0eVgzUnBZMnRsZEY5aGRYUm9PbUZGWkhKVlZGazFUVlJXTUZKQkx6OXZZbVp6Y0dGeVlXMDlXVmR3YUdWRE5YUmhWMDU1WWpOT2RscHVVWFZaTWpsMEpuQnliM1J2Y0dGeVlXMDlUVlJKTUUxRVFUSlBhM0JGVDFVd00yRnRSak5hZW1jbWNtVnRZWEpyY3owMVdTMTNOWEp0TFZGNU1UQmFMVzFwYTJWdFFtdDZjRUZqYld4M1dWYzVjV0ZYVm10aFYwWjFKbWR5YjNWd1BXUkhabkJ2Y0Vod1oxcE5ObEZJU25CalIwWjJZVzFzYkZwSGJHaGladw=="
            s2 = strDecode(s1)
            print(s2)
        
        case 'get':
            url ='https://raw.githubusercontent.com/satrom/V2SSR/master/SSR/Sub.txt'
            rst = fhelper.getSubscribeContent(url)
            print(rst)
        case 'encode':
            if sys.argv[2]:
                encrypt_base64(sys.argv[2])
            else:
                encrypt_base64('fly.txt')

        case 'find':
            rst = fhelper.find(sys.argv[2])
            print(rst)

        case _:
            print('Usage: %s [run | subscribe | split | encode | repair | debug | clash | clash2 | find ]' % sys.argv[0])
            