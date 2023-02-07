import json
import os
import re
import shutil
import socket
import sys
import time
import urllib

import requests
import yaml
from lxml import etree

from dec_enc import strDecode, strEncode
from geoip import getCountry

from v2ray import V2ray

schemaList = ['ss', 'ssr', 'trojan', 'vless', 'vmess','http2']
existNameList = []

def get_filepath(filename):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)

def splitFiles(filename="fly.txt"):
    filename = get_filepath(filename)

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
        encodeStr = strEncode(encodeStr)
        # encodeStr = bytes(encodeStr, 'utf-8')
        # encodeStr = base64.b64encode(encodeStr)
        # encodeStr = str(encodeStr, 'utf-8')

    with open(filePath.split('.')[0], "w", encoding='utf8') as f:
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

def getResponse(url=None, dec=False,timeout=5):
        headers = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "accept-encoding": "gzip, deflate",
            "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36",
        }
        try:
            rsp = requests.get(url, headers=headers, timeout=timeout)
            print(rsp.status_code, rsp.url)
            
            if rsp.status_code == 200:
                rsp = rsp.text
                rsp = re.sub('\n|\r', '', rsp)

                rsp = strDecode(rsp, False) if dec else rsp
                # time.sleep(3)
            else:
                raise(rsp.status_code)

        except Exception as e:
            print(e)
            rsp = ''
            # raise(e)

        # return rsp.splitlines()
        return rsp

def chkName(n,existNameList):
    if n in existNameList:
        ns = n.split("]") if n.find("]")>0 else [n,""]
        n2 = chkName("{}{}]{}".format(ns[0],"*",ns[1]), existNameList)
    else:
        n2 = n
    return n2

def banyunxiaoxi():
    resultList = []
    index_url = 'https://banyunxiaoxi.icu/'
    
    rst = getResponse(index_url)
    rst = etree.HTML(rst)
    urls = rst.xpath('//*[@class="post-title"]/@href')
    for url in urls:
        print(url)
        ret = getResponse(url)
        ret = etree.HTML(ret)
        ret = ret.xpath('//*[@class="wp-block-quote"]//text()')
        ret = [a for a in ret if a.startswith(tuple(['{}://'.format(s) for s in schemaList]))]
        print(ret)
        resultList += ret
        
    return resultList

def parse_plain_url(s:str):
    _protocol = s.split("://")[0] or None
    s = s.strip().replace("/?","?")
    
    try:
        if s.find("?")>0:
            matcher = re.match(r'(.*://){0,1}(.*?:){0,1}(.*)@(.*):(.*)', s[:s.find("?")])
            params = s[s.find("?")+1:s.find("#")]
            params = {ps.split("=")[0]:ps.split("=")[1] for ps in params.split("&")}
        else:
            matcher = re.match(r'(.*://){0,1}(.*?:){0,1}(.*)@(.*):(.*)', s[:s.find("#")])
            params = {}
        
        _name = s.split("#")[1] or ""
        _name = urllib.parse.unquote(_name)
        obj = {
            'ps': _name,
            'type': _protocol,
            'server': matcher.group(4),
            'port': int(matcher.group(5)),
            'id': matcher.group(3),
            
            'cipher':matcher.group(2)[:-1] if matcher.group(2) else 'auto',
            'aid': params.get('aid') or params.get('alterId') or 0,
            'net': params.get('net',""),
            'host': params.get('host',""),
        }
        
        for key in list(params.keys()):
            if key not in list(obj.keys()):
                obj[key] = params[key]
                
    except Exception as e:
        print(e)
        obj = {}
        
    return obj
    
def parse_vmess_url(s:str):
    _protocol = s.split("://")[0] or None
    s = s.strip().replace("/?","?")
    
    try:
        if s.find("@")>0:
            obj = parse_plain_url(s)
            obj['add'] = obj.pop("server")
            
        elif s.find("?")>0:
            matcher = strDecode(s[len(_protocol)+3:s.find("?")])
            _remarks = [ p.replace("remarks=","") for p in s[s.find("?")+1:].split('&') if "remarks=" in p]
            _remarks = _remarks[0] if _remarks else ""
            # _remarks = urllib.parse.unquote(_remarks)
            obj = parse_plain_url("{}://{}?{}#{}".format(_protocol,matcher,s[s.find("?")+1:],_remarks))
            obj['add'] = obj.pop("server")
            
        else:
            parse_rst = strDecode(s[len(_protocol)+3:])
            obj= json.loads(parse_rst)
            
        obj['type'] = _protocol
        obj['path'] = obj.get('path') or None
        obj['tls']  = obj.get('tls') or None
        obj['host'] = obj.get('host',None)
        obj['path'] = obj.get('path',None)
        obj['aid'] = obj.get('aid',0)
        
    except Exception as e:
        print(e)
        obj = {}
        
    return obj

def parse_ssr_url(s:str):
    _protocol = s.split("://")[0] or None
    s = s.strip().replace("/?","?")
    
    try:
        rst = s[len(_protocol)+3:]
        if rst.find("_")>0:
            s1  = strDecode(rst.split("_")[0])
            s2 = strDecode(rst.split("_")[1])
            if s1.find('?')>0:
                rst = "{}&{}".format(s1,s2)
            else:
                rst = "{}?{}".format(s1,s2)
        else:
            rst = strDecode(rst)
        
        rst = rst.strip().replace("/?","?")
        print(rst)
        # sys.exit()
        
        if rst.find('?')>0:
            alist = rst[:rst.find('?')].split(':')
            
            params = rst[rst.find('?')+1:]
            print(params)
            params = {ps.split("=")[0]:strDecode(ps.split("=")[1]) or ps.split("=")[1] for ps in params.split("&")}
            # if "_cmVtYXJrcz" in s:
            #     params['remarks'] = strDecode(s[s.find('_')+1:]).replace('remarks=','')
        else:
            rst = rst[:-1] if rst.endswith('/') else rst
            alist = rst.split(':')
            params = {}
        obj = {
            'type': _protocol,
            'server': alist[0],
            'port':int(alist[1]),
            '协议':alist[2],
            'method算法':alist[3],
            'obfs':alist[4],
            'password':strDecode(alist[5]),
        }
        obj = dict(obj, **params)
        
    except Exception as e:
        print(e)
        obj = {}
        
    return obj

def parse_ss_url(s:str):
    _protocol = s.split("://")[0] or None
    s = s.strip().replace("/?","?")
    s = s if s.find("#")>0 else s+"#"
    
    try:
        if s.find('@')<=0 or s[len(_protocol)+3:].find(':')<=0:
            s = '{}://{}{}'.format(_protocol,strDecode(s[len(_protocol)+3:s.find("#")]),s[s.find("#"):])
            print("fixed",s)
            s = s if s.find("#")>0 else s+"#"

        if s.find('?')>0:
            matcher = re.match(r'(.*)@(.*):(.*)\?(.*)#(.*){0,1}',s[len(_protocol)+3:])
            _params = urllib.parse.unquote(matcher.group(4)) or None
            _remarks = urllib.parse.unquote(matcher.group(5)) or None
            
        else:
            matcher = re.match(r'(.*)@(.*):(.*)#(.*){0,1}',s[len(_protocol)+3:])
            _params = None
            _remarks = urllib.parse.unquote(matcher.group(4)) or None
        
        s1 = matcher.group(1)
        if s1.find(':')<=0:
            s1 = strDecode(s1) or None
        s1 = s1.split(':') if s1 else [None,None]
        obj = {
            'type': _protocol,
            'method': s1[0],
            'passwd': s1[1],
            'server': matcher.group(2) or None,
            'port':matcher.group(3) or None,
            'params': _params,
            'remarks': _remarks,
        }
        
    except Exception as e:
        print(e,s)
        obj = {}
        sys.exit()
        
    return obj


class URLParseHelper:
    def __init__(self, url=None) -> None:
        self.url = url.strip() if url else ''
        self.urlObj = None
        self.body = None
        self.host = None
        self.port = None
        
    def parse(self, url=None):
        try:
            self.url = url.strip().replace("/?","?") if url else self.url
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
        _name = '[{}{}]{}:{}'.format(getCountry(ipStr), self.urlObj.scheme.upper(), ipStr.upper(), port)
        _name = chkName(_name, existNameList)
        existNameList.append(_name)
        
        _name = urllib.parse.quote(_name) if quote else _name

        return _name

    def ssObj(self):
        try:
            
            _newUrl = (self.urlObj.scheme, self.urlObj.netloc, self.urlObj.path,
                    self.urlObj.params, self.urlObj.query, self.getTagName(self.host, self.port, True))
            _newUrl = urllib.parse.urlunparse(_newUrl)
        except Exception as e:
            print(e,self.url,self.urlObj, urllib.parse.unquote(self.urlObj.fragment))
            sys.exit()

        return self.host, self.port, _newUrl
    
    def ssrObj(self):
        try:
            if self.url[6:].find('_')>0:
                s1 = strDecode(self.url[6:].split('_')[0])
                s2 = strDecode(self.url[6:].split('_')[1])
                if s1.find('?')>0:
                    rst = "{}&{}".format(s1,s2)
                else:
                    rst = "{}?{}".format(s1,s2)
            else:
                rst = strDecode(self.url[6:])
                
            rst = rst.strip().replace("/?","?")
            if rst.find('?')>0:
                alist = rst[:rst.find('?')].split(':')
                params = rst[rst.find('?')+1:].split('&')
                params = [p for p in params if not p.startswith('remarks=')]
            
            else:
                rst = rst[:-1] if rst.endswith('/') else rst
                alist = rst.split(':')
                params = []
                
            params.append("remarks={}".format(strEncode(self.getTagName(alist[0], alist[1]))))
            _newUrl = '{}?{}'.format(rst[:rst.find('?')],"&".join(params))
            _newUrl = '{}://{}'.format('ssr',strEncode(_newUrl))
        except Exception as e:
            print(e,self.url,self.urlObj)
            sys.exit()
            
        return alist[0], alist[1], _newUrl
    
    def ssrObj_bak(self):
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
            obj = parse_vmess_url(self.url)
            _remarks= self.getTagName(obj['add'],obj['port'])
            if self.url.find("@")>0:
                rst = [obj['add'],obj['port'], self.url[:self.url.find("#")] + "#" + urllib.parse.quote(_remarks)]
            elif self.url.find('?')>0:
                params = [ p for p in self.url.split('?')[1].split('&') if not p.startswith('remarks=')]
                params.append('remarks={}'.format(_remarks))
                params = "".join(params)
                rst = [ obj['add'], obj['port'], self.url[:self.url.find('?')+1] + params]
            else:
                obj['ps'] = self.getTagName(obj['add'],obj['port'])
                rst = [obj['add'],obj['port'],"vmess://{}".format(strEncode(json.dumps(obj),False))]
        except Exception as e:
            print('vmessObj Error:{}'.format(e).center(100,"-"))
            rst = [self.host, self.port, self.url]
            sys.exit()
        return rst

    def vmessObj_bak(self):
        try:
            _s = strDecode(self.body)
            _s = re.sub("\n|\S", '', _s.strip())
            
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

class clashHelper:
    
    def __init__(self):
        # 规则策略
        self.config_url = 'https://raw.githubusercontent.com/Celeter/v2toclash/master/config.yaml'
        self.config_path = get_filepath("clash_config.yaml")
    
    def save_config(self, sch, data):
        content = yaml.dump(data, sort_keys=False, default_flow_style=False, encoding='utf-8', allow_unicode=True)
        with open(get_filepath("{}_config.yaml".format(sch)), 'wb') as f:
            f.write(content)
        print('成功更新:{}个节点'.format(len(data['proxies'])))
        
    # 获取本地规则策略的配置文件
    def load_local_config(self,path=None):
        self.config_path = get_filepath(path) if path else self.config_path
        try:
            with open(self.config_path, 'r', encoding="utf-8") as f:
                local_config = yaml.load(f.read(), Loader=yaml.FullLoader)
            return local_config
        except FileNotFoundError:
            print('配置文件加载失败')
            sys.exit()
            
    # 获取规则策略的配置文件
    def get_default_config(self, url=None, path=None):
        self.config_url = url if url else self.config_url
        self.config_path = get_filepath(path) if path else self.config_path
        try:
            raw = getResponse(self.config_url,False,5000) #.content.decode('utf-8')
            template_config = yaml.load(raw, Loader=yaml.FullLoader) if raw else self.load_local_config(self.config_path)
        except requests.exceptions.RequestException:
            print('网络获取规则配置失败,加载本地配置文件')
            template_config = self.load_local_config(self.config_path)
        print('已获取规则配置文件')
        return template_config

    def vmess_to_clash(self,arr):
        proxies={
            'proxy_list':[],
            'proxy_names':[]
        }
        try:
            
            for item in arr:
                if isinstance(item, str):
                    item = json.loads(item)
                    
                if item.get('ps') is None and item.get('add') is None and item.get('port') is None and item.get('id') is None and item.get('aid') is None:
                    continue
                _name = item.get('ps').strip() if item.get('ps') else None
                _name = chkName(_name, existNameList)
                existNameList.append(_name)
                obj = {
                    'name': _name,
                    'type': 'vmess',
                    'server': item.get('add') or item.get('server'),
                    'port': int(item.get('port')),
                    'uuid': item.get('id'),
                    'alterId': item.get('aid') or item.get('alterId'),
                    'cipher':'auto', 
                    'udp': True,
                    # 'network': item['net'] if item['net'] and item['net'] != 'tcp' else None,
                    'network': item.get('net') or item.get('network'),
                    'tls': True if item.get('tls') == 'tls' else None,
                    'ws-path': item.get('path') or item.get('ws-path'),
                    'ws-headers': {'Host': item.get('host')} if item.get('host') else None
                }
                
                for key in list(item.keys()):
                    if key in ['v','path','host','net','aid','id','add','ps']:
                        continue
                    if key not in list(obj.keys()):
                        obj[key] = item[key]
                for key in list(obj.keys()):
                    if obj.get(key) is None or obj.get(key)=='' or obj.get(key)=='none':
                        del obj[key]
                
                proxies['proxy_list'].append(obj)
                proxies['proxy_names'].append(obj['name'])
        
        except Exception as e:
            print(e)
            
        return proxies
    
    def trojan_to_clash(self,arr):
        proxies={
            'proxy_list':[],
            'proxy_names':[]
        }
        try:
            
            for item in arr:
                item = item.replace("/?","?")
                if item.find("?")>0:
                    matcher = re.match(r'(.*)@(.*):(.*)', item[:item.find("?")])
                    params = item[item.find("?")+1:item.find("#")]
                    params = {ps.split("=")[0]:ps.split("=")[1] for ps in params.split("&")}
                else:
                    matcher = re.match(r'(.*)@(.*):(.*)', item[:item.find("#")])
                    params = {}
                
                _name = item.split("#")[1] or ""
                _name = urllib.parse.unquote(_name)
                _name = chkName(_name, existNameList)
                existNameList.append(_name)
                obj = {
                    'name': _name,
                    'type': 'trojan',
                    'server': matcher.group(2),
                    'port': int(matcher.group(3)),
                    'password': matcher.group(1),
                    'skip-cert-verify': True,
                    'udp': True,
                }
                
                for key in list(params.keys()):
                    if key not in list(obj.keys()):
                        obj[key] = params[key]
               
                for key in list(obj.keys()):
                    if obj.get(key) is None or obj.get(key)=='none':
                        del obj[key]
                        
                proxies['proxy_list'].append(obj)
                proxies['proxy_names'].append(obj['name'])
        
        except Exception as e:
            print(e)
            
        return proxies
    
    # 将代理添加到配置文件
    def add_proxies_to_model(self, data, model):
        if model.get('proxies') is None:
            model['proxies'] = data.get('proxy_list')
        else:
            model['proxies'].extend(data.get('proxy_list'))
        for group in model.get('proxy-groups'):
            if group.get('name') in ['Ⓜ️ 微软服务','📲 电报信息','🍎 苹果服务','⛔️ 广告拦截','🎯 全球直连','🛑 全球拦截','🐟 漏网之鱼']:
                continue
            
            if group.get('proxies') is None:
                group['proxies'] = data.get('proxy_names')
            else:
                group['proxies'].extend(data.get('proxy_names'))
        return model
    
class fileHelper:
    
    def __init__(self,source_file='source.txt',out_file='fly.txt', backup_file='collection.txt',error_file='error.txt',ignore_file="ignore.txt") -> None:
        self.source_file = get_filepath(source_file)
        self.out_file = get_filepath(out_file)
        self.backup_file = get_filepath(backup_file)
        self.error_file = get_filepath(error_file)

        # self.exist_list = self.read(self.backup_file)
        self.exist_list = []
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
            with open(self.out_file,"a+",encoding="utf8") as f:
                f.write(url+"\n")
            with open(self.backup_file, "a+", encoding='utf8') as f3:
                f3.write(url + '\n')
            print("Add a URL:" + url)
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
                    for _s in schemaList:
                        if line.find("{}://".format(_s))>0:
                            line = "\n".join(["{}://{}".format(_s, l) for l in line.split("{}://".format(_s))]) + '\n'
                    self.write(line)
                else:
                    continue

        except Exception as e:
            print(e, subscribe)
            raise(e)

    def getSubscribeContent_all(self,skip=None):
        sourcelist = self.read(self.source_file)
        sourcelist = sourcelist[skip:] if skip else sourcelist
        for index, source in enumerate(sourcelist):
            print("********** Get Subscribe {}/{} **********".format(index+1, len(sourcelist)))
            self.getSubscribeContent(source)

        removeDuplicateData(self.backup_file)

    def get_from_clash(self, subscribe):
        try:
            subscribe = re.sub('\n', '', subscribe)
            print('='*50)
            print('source is: {}'.format(subscribe))
            content = requests.get(subscribe, timeout=5)
            print(content.status_code)
            
            if content.status_code == 200:
                content = content.text
            else:
                return

            if len(content) <= 0:
                print("length is null")
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
            
            print('='*50)

        except Exception as e:
            print(e)
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
   
    def handleUrl(self, filename=None,skiplines=0):
        u = URLParseHelper()
        self.out_file = get_filepath(filename) if filename else self.out_file
        urlList = self.read(self.out_file)
        urlList = list(set(urlList))
        urlList = sorted(urlList)
        urlList = urlList[skiplines:] if skiplines else urlList

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

    def make_clash_config(self,shm=None):
        clashH = clashHelper()
        default_config = clashH.get_default_config()
        
        for sch in schemaList:
            if shm is not None and shm != sch:
                continue
                
            with open(get_filepath(sch + ".txt")) as f:
                arr = f.readlines()
                
            clash_node = None
            print(sch,len(arr))
            if sch == "vmess":
                arr_v = [strDecode(item[8:].strip()) for item in arr if item.find('@')<=0]
                clash_node = clashH.vmess_to_clash(arr_v)
            
            # if sch == "trojan":
            #     arr_t = [item[9:].strip() for item in arr]
            #     clash_node = clashH.trojan_to_clash(arr_t)
                
            if clash_node:
                final_config = clashH.add_proxies_to_model(clash_node, default_config)
                clashH.save_config(sch, final_config)
            
            # print(sch,len(arr),clash_node)

if __name__ == "__main__":
    uhelper = URLParseHelper()
    fhelper = fileHelper()
    
    match sys.argv[1]:
        case 'subscribe':
            # alist = banyunxiaoxi()
            # for line in alist:
            #     fhelper.write(line)
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
            fhelper.splitFiles()

        case 'run':
            # alist = banyunxiaoxi()
            # for line in alist:
            #     fhelper.write(line)
            fhelper.clash()
            fhelper.run()
            
        case 'clash':
            fhelper.clash()
            
        case 'spider':
            alist = banyunxiaoxi()
            # for line in alist:
            #     fhelper.write(line)
            print(alist)
            
        case 'debug':
            # s ="vless://1eded6fc-8b28-33df-a93f-6491de5f7a12@www.elkcloud.top:10086?encryption=none&type=tcp&security=&path=%2F&headerType=none#%E8%BF%87%E6%9C%9F%E6%97%B6%E9%97%B4%EF%BC%9A2022-11-29"
            # rst = parse_plain_url(s)
            # print(rst)
            
            with open("collection.txt",'r') as f:
                alist = [u.strip() for u in f.readlines() if u.strip().startswith('trojan://')]
            for index,a in enumerate(alist) :
                rst = parse_plain_url(a.strip())
                print(index,a,rst)
                
                # v2Node = V2ray(rst['add'], int(rst['port']), rst['ps'], 'auto', rst['id'], int(rst['aid']), rst['net'], rst['type'], rst['host'], rst['path'] or None, rst['tls'] or None)
                # print(v2Node.formatConfig())
            
            # s = "vmess://YXV0bzo5YTE4Y2JiMS04MWQyLTQ3MjAtOWYwOS00NmVhMjc2YjZkZGJAemh1eW9uZy5odWNsb3VkLWRucy54eXo6NDQz?remarks=%5B%E7%BE%8E%E5%9B%BDVMESS%5DZHUYONG.HUCLOUD-DNS.XYZ:443&path=/huhublog&obfs=websocket&tls=1&alterId=0"
            # rst = parse_vmess_url(s)
            # print(rst)
            
            # v2Node = V2ray(rst['add'], int(rst['port']), rst['ps'], 'auto', rst['id'], int(rst['aid']), rst['net'], rst['type'], rst['host'], rst['path'] or None, rst['tls'] or None)
            # json.dump(v2Node.formatConfig(), open('v2ray-core-4.31.0/speedtest.json', 'w'), indent=2)
            
            # tmpres = os.popen('nohup ./v2ray-core-4.31.0/v2ray -c ./v2ray-core-4.31.0/speedtest.json &')
            # content = tmpres.read()
            # print(content)
            
            # for c in content.splitlines():
            #     print(c)
            # tmpres.close
                
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

        case 'clashconfig':
            fhelper.make_clash_config()

        case _:
            print('Usage: %s [run | subscribe | split | encode | repair | debug | clash | clash2 | find ]' % sys.argv[0])
            