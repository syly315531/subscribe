import base64
import json
import os
import re
import shutil
import socket
import time
import urllib

import geoip2.database
import requests
import yaml

schemaList = ['ss', 'ssr', 'trojan', 'vless', 'vmess','http2']
with open("ignoreList.txt","r", encoding="utf8") as f:
    ignoreList = [i.strip() for i in f.readlines() if i.strip().startswith("#")==False]
# ignoreList =  ['14.29.124.168','14.29.124.174','af01.uwork.mobi', 'azure-f4s-hk.transfer-xray.tk', 'https://t.me/buyebuye', '使用前记得更新订阅', '柠檬国际机场','0']

class URLParseHelper():

    def __init__(self, url=None, outfile='fly.txt', backupfile='collection.txt') -> None:
        self.geoDBPath = self.get_filepath("./GeoLite2/GeoLite2-City.mmdb")
        self.geoClient = geoip2.database.Reader(self.geoDBPath)

        self.url = url

        self.backupfile = self.get_filepath(backupfile)
        self.outfile = self.get_filepath(outfile)
        self.errorfile = self.get_filepath("error.txt")

        with open(self.backupfile, 'r', encoding='utf8') as f:
            self.existList = [h.strip() for h in f.readlines()
                              if h.strip().startswith("#") == False]

    def get_filepath(self, filename):
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)

    def isEmpty(self, s=None):
        if s == None:
            return True

        if isinstance(s, tuple):
            return len(s) == 0 or s == ()
        if isinstance(s, list):
            return len(s) == 0 or s == []
        if isinstance(s, dict):
            return s == {}
        if isinstance(s, str):
            return s == "" or s.isspace() or len(s) == 0 or s == "None" or s == "null" or s == "{}" or s == "[]"

    def getResponse(self, url=None, dec=False,timeout=5):
        self.url = url.strip() if url else self.url.strip()
        headers = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "accept-encoding": "gzip, deflate",
            "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36",
        }
        try:
            print(self.url)
            rsp = requests.get(self.url, headers=headers, timeout=timeout)
            if rsp.status_code == 200:
                rsp = rsp.text
                rsp = re.sub('\n', '', rsp)

                rsp = self.strDecode(rsp, False) if dec else rsp
                # time.sleep(3)
            else:
                print(rsp.status_code, rsp.url)
                raise(rsp.status_code)

        except Exception as e:
            rsp = ''
            # raise(e)

        # return rsp.splitlines()
        return rsp

    def parse(self, url=None):
        self.url = url.strip() if url else self.url.strip()

        self.urlObj = urllib.parse.urlparse(self.url.strip())

        self.body = self.urlObj.netloc + self.urlObj.path

        return self.urlObj

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

    def splitURL(self, url=None):
        if url:
            self.parse(url)

        _url = self.body if self.body.find(
            '@') > 0 else self.strDecode(self.body)
        ip_and_port = _url[::-1]
        ip_and_port = ip_and_port[:ip_and_port.find('@')]
        ip_and_port = ip_and_port[::-1]
        ip_and_port = re.sub('\/|\'','',ip_and_port)
        ip_and_port = ip_and_port.split(':')

        return ip_and_port[0], ip_and_port[1].replace("/", ""), _url

    def build_query(self, data):
        try:
            if 'remarks' in data:
                data.pop('remarks')
            qList = []
            for k, v in data.items():
                if k == '':
                    continue
                
                v = ','.join(v) if isinstance(v, list) else v
                v = '' if self.isEmpty(v) else v
                v = str(v) if isinstance(v, (bool, int, float))  else v
                
                # print(k, v, type(v))

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

        if key and value:
            querys[key] = [value, ]

        if 'alterId' in querys and 'aid' not in querys:
            querys['aid'] = querys['alterId']

        return querys

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
            print('Tested', ipAddr, port)
            return True if result == 0 else False

    def getCountry(self, ipStr: str):
        '''
        geoip2.models.City({'city': {'geoname_id': 5045360, 'names': {'de': 'Saint Paul', 'en': 'Saint Paul', 'es': 'Saint Paul', 'fr': 'Saint Paul', 'ja': 'セントポール', 'pt-BR': 'Saint Paul', 'ru': 'Сент-Пол', 'zh-CN': '圣保罗'}}, 'continent': {'code': 'NA', 'geoname_id': 6255149, 'names': {'de': 'Nordamerika', 'en': 'North America', 'es': 'Norteamérica', 'fr': 'Amérique du Nord', 'ja': '北アメリカ', 'pt-BR': 'América do Norte', 'ru': 'Северная Америка', 'zh-CN': '北美洲'}}, 'country': {'geoname_id': 6252001, 'iso_code': 'US', 'names': {'de': 'USA', 'en': 'United States', 'es': 'Estados Unidos', 'fr': 'États-Unis', 'ja': 'アメリカ合衆国', 'pt-BR': 'Estados Unidos', 'ru': 'США', 'zh-CN': '美国'}}, 'location': {'accuracy_radius': 20, 'latitude': 44.9548, 'longitude': -93.1551, 'metro_code': 613, 'time_zone': 'America/Chicago'}, 'postal': {'code': '55104'}, 'registered_country': {'geoname_id': 6252001, 'iso_code': 'US', 'names': {'de': 'USA', 'en': 'United States', 'es': 'Estados Unidos', 'fr': 'États-Unis', 'ja': 'アメリカ合衆国', 'pt-BR': 'Estados Unidos', 'ru': 'США', 'zh-CN': '美国'}}, 'subdivisions': [{'geoname_id': 5037779, 'iso_code': 'MN', 'names': {'en': 'Minnesota', 'es': 'Minnesota', 'fr': 'Minnesota', 'ja': 'ミネソタ州', 'pt-BR': 'Minesota', 'ru': 'Миннесота', 'zh-CN': '明尼苏达州'}}], 'traits': {'ip_address': '128.101.101.101'}}, ['en'])
        geoip2.models.City({'continent': {'code': 'NA', 'geoname_id': 6255149, 'names': {'de': 'Nordamerika', 'en': 'North America', 'es': 'Norteamérica', 'fr': 'Amérique du Nord', 'ja': '北アメリカ', 'pt-BR': 'América do Norte', 'ru': 'Северная Америка', 'zh-CN': '北美洲'}}, 'country': {'geoname_id': 6252001, 'iso_code': 'US', 'names': {'de': 'USA', 'en': 'United States', 'es': 'EE. UU.', 'fr': 'États Unis', 'ja': 'アメリカ', 'pt-BR': 'EUA', 'ru': 'США', 'zh-CN': '美国'}}, 'location': {'accuracy_radius': 1000, 'latitude': 37.751, 'longitude': -97.822, 'time_zone': 'America/Chicago'}, 'registered_country': {'geoname_id': 6252001, 'iso_code': 'US', 'names': {'de': 'USA', 'en': 'United States', 'es': 'EE. UU.', 'fr': 'États Unis', 'ja': 'アメリカ', 'pt-BR': 'EUA', 'ru': 'США', 'zh-CN': '美国'}}, 'traits': {'ip_address': '172.252.64.49', 'prefix_len': 19}}, ['en'])
        '''
        try:
            ipStr = socket.getaddrinfo(ipStr, None)
            ipStr = ipStr[0][4][0]
            result = self.geoClient.city(ipStr)
            result = result.country.names['zh-CN']
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

    def getTagName(self, ipStr, port, quote=False):
        if quote:
            return urllib.parse.quote('[{}{}]{}:{}'.format(self.getCountry(ipStr), self.urlObj.scheme.upper(), ipStr.upper(), port))
        else:
            return '[{}{}]{}:{}'.format(self.getCountry(ipStr), self.urlObj.scheme.upper(), ipStr.upper(), port)

    def build_trojan(self, data):
        _scheme, _password, _ip, _port, _name = data.pop('type'), data.pop(
            'password'), data.pop('server'), data.pop('port'), data.pop('name')
        url = "{}@{}:{}".format(_password, _ip, _port)

        # print(data)

        query = "&".join(["{}={}".format(k, str(v).lower())
                         for k, v in data.items()])

        url = (_scheme, url, '', '', query, urllib.parse.quote(_name))
        url = urllib.parse.urlunparse(url)
        return url

    def build_vmess(self, data):
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
        data = self.strEncode(data)
        """
        try:
            # =hk21201.cloudmatrix.xyz&path=/hls/cctv5phd.m3u8&obfs=&alterId=2
            _scheme, _security, _uuid, _address, _port, data['remarks'] = data.pop('type'), data.pop(
                'cipher'), data.pop('uuid'), data.pop('server'), data.pop('port'), data.pop('name')
            url = "{}:{}@{}:{}".format(_security, _uuid, _address, _port)

            if data['network'] == 'ws':
                data['obfs'] = 'websocket'
                if 'ws-opts' in data:
                    data['obfsParam'] = data['ws-opts']['headers']['Host']
                    data['path'] = data['ws-opts']['path']
                    data.pop('ws-opts')
                    data.pop('ws-headers')
                    data.pop('ws-path')
                if 'servername' in data:
                    data.pop('servername')
            data['remarks'] = urllib.parse.quote(data['remarks'])
            query = "&".join(["{}={}".format(k, str(v).lower())
                             for k, v in data.items()])
            url = urllib.parse.urlunparse(
                (_scheme, self.strEncode(url), '', '', query, ''))
            return url
        except Exception as e:
            print(e, data)
            raise(e)

    def build_ssr(self, data):
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
            _scheme, _password, _ip, _port, data['remarks'] = data.pop('type'), data.pop(
                'password'), data.pop('server'), data.pop('port'), data.pop('name')
            _protocol, _cipher, _pparam = data.pop('protocol'), data.pop(
                'cipher'), data.pop('protocol-param') if 'protocol-param' in 'data' else ''
            url = "{}:{}:{}:{}:{}".format(
                _ip, _port, _protocol, _cipher, _pparam)

            data['remarks'] = urllib.parse.quote(data['remarks'])
            query = _password + "/?" + self.build_query(data)
            url += ":" + query
            url = _scheme + "://" + self.strEncode(url)
            return url
        except Exception as e:
            print(e, data)
            raise(e)

    def build_ss(self, data):
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
            _scheme, _password, _ip, _port = data.pop('type'), data.pop(
                'password'), data.pop('server'), data.pop('port')
            _cipher, _name = data.pop('cipher'), data.pop('name')
            print(_name)

            url = "{}://{}@{}:{}".format(_scheme, self.strEncode(
                "{}:{}".format(_cipher, _password)), _ip, _port)

            _query = self.build_query(data)
            if _query:
                url += "?" + _query

            _name = _name if _name else 'clash'
            _name = urllib.parse.quote(_name)
            url += "#" + _name

            return url
        except Exception as e:
            print(e, data)
            raise(e)

    def ssObj(self):
        _ip, _port, _url = self.splitURL()

        _newUrl = (self.urlObj.scheme, self.urlObj.netloc, self.urlObj.path,
                   self.urlObj.params, self.urlObj.query, self.getTagName(_ip, _port, True))
        _newUrl = urllib.parse.urlunparse(_newUrl)

        return _ip, _port, _newUrl

    def ssrObj(self):
        def parse_qs_ssr(url):
            _u = urllib.parse.urlparse(url.strip())
            return _u.path, urllib.parse.parse_qs(_u.query)

        _s1 = self.body[0:self.body.find('_')] if self.body.find(
            '_') > 0 else self.body
        _s = self.strDecode(_s1)
        _s = _s.strip().split(':')
        # print(_s)
        _tagName = self.getTagName(_s[0], _s[1])

        _url_path, _url_qs = parse_qs_ssr(_s[-1])
        # print(_url_qs)
        isexistRemarks = 'remarks' in _url_qs
        # if isexistRemarks:
        #     print(self.strDecode(_url_qs['remarks'][0].replace(" ", "+")))
        _url_qs['remarks'] = [self.strEncode(_tagName), ]
        _s[-1] = _url_path + "?" + self.build_query(_url_qs)
        _s1 = _s1 if isexistRemarks else self.strEncode(":".join(_s))

        if self.body.find('_') > 0:
            _newUrl = self.urlObj.scheme + '://' + _s1 + '_' + \
                self.strEncode('remarks={}'.format(_tagName))
        else:
            _newUrl = self.urlObj.scheme + '://' + self.strEncode(":".join(_s))

        print(_newUrl)

        return _s[0], _s[1], _newUrl

    def trojanObj(self):
        return self.ssObj()

    def vlessObj(self):
        _ip, _port, _url = self.splitURL()

        _tagname = self.getTagName(_ip, _port, True)
        _query = self.build_queryObj(key='alpn', value=_tagname)
        _query = self.build_query(_query)

        _fragment = _tagname if self.urlObj.fragment != '' else ''

        _newUrl = urllib.parse.urlunparse(
            (self.urlObj.scheme, self.urlObj.netloc, self.urlObj.path, self.urlObj.params, _query, _fragment))

        return _ip, _port, _newUrl

    def vmess2link(self, data):
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
        _uuid, _address, _port = data.pop(
            'id'), data.pop('add'), data.pop('port')
        url = "{}:{}@{}:{}".format(_security, _uuid, _address, _port)

        data['remark'] = data.pop('ps')
        # data['remark']  = urllib.parse.quote(data['remark'])
        if 'alterId' not in data:
            data['alterId'] = data['aid'] if 'aid' in data else ''

        data['obfs'] = data.pop('net')
        if data['obfs'] == 'ws':
            data['obfs'] = 'websocket'
            data['obfsParam'] = data.pop('host') if 'host' in data else ''

        if 'url_group' in data:
            data.pop('url_group')
        # url += "#" + self.build_query(data)
        url = urllib.parse.urlunparse(
            ('vmess', self.strEncode(url), '', '', self.build_query(data), ''))
        return url

    def vmessObj(self):
        try:
            _s = self.strDecode(self.body)
            _s = re.sub("\n", '', _s) or _s.strip()
            _s = re.sub(' ', '', _s)

            if _s.find('{') == 0:
                _s = json.loads(_s)
                _ipStr, _port = _s['add'], _s['port']
                _s['ps'] = self.getTagName(_ipStr, _port)
                # _s = [_ipStr, _port, self.vmess2link(_s)]
                _s = [_ipStr, _port, "vmess://{}".format(self.strEncode(json.dumps(_s),False))]
            else:
                _ipStr, _port, _url = self.splitURL()
                
                try:
                    query = self.build_queryObj(
                        key='remark', value=self.getTagName(_ipStr, _port))
                    print(query)
                    query = self.build_query(query)
                    _newUrl = urllib.parse.urlunparse(
                        (self.urlObj.scheme, self.urlObj.netloc, self.urlObj.path, self.urlObj.params, query, self.urlObj.fragment))
                    
                except Exception as e:
                    raise(e)
                
                _s = [_ipStr, _port, _newUrl]

        except Exception as e:
            print('vmessObj Error:{}'.format(e).center(100,"-"))
            _s = [_ipStr, _port, self.url]

        return _s

    def rebuild(self, url=None):
        try:
            if url:
                self.url = url.strip()
                self.parse(self.url)

            if self.urlObj.scheme == 'ss':
                r = self.ssObj()
            elif self.urlObj.scheme == 'ssr':
                r = self.ssrObj()
            elif self.urlObj.scheme == 'trojan':
                r = self.trojanObj()
            elif self.urlObj.scheme == 'vless':
                r = self.vlessObj()
            elif self.urlObj.scheme == 'vmess':
                r = self.vmessObj()
            elif self.urlObj.scheme == 'http2':
                r = self.ssObj()
            else:
                r = [None, None, None]
        except Exception as e:
            print(e, self.urlObj)
            r = [None, None, None]
        return r

    def writeIntoFile(self, url):
        url = url.strip()
        if url not in self.existList:
            print('Add URL is:', url)
            self.add(url)
            with open(self.backupfile, "a+", encoding='utf8') as f3:
                f3.write(url + '\n')
        else:
            print('Ignore the URL', url)

    def getSubscribeContent(self, subscribe):
        try:
            subscribe = re.sub('\n', '', subscribe)
            print('='*50)
            print('source is: {}'.format(subscribe))
            print('='*50)

            lines = self.getResponse(subscribe, True)
            lines = lines.splitlines()

            for line in lines:
                if line.startswith(tuple(['{}://'.format(s) for s in schemaList])):
                    self.writeIntoFile(line)
                else:
                    continue

        except Exception as e:
            print(e, subscribe)

            raise(e)

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

                self.writeIntoFile(url)

        except Exception as e:
            return None
            # raise(e)

    def find(self, keyword):
        rst = []
        for url in self.existList:
            url = url.strip()
            self.parse(url)
            if url.find(keyword) >= 0:
                rst.append((url, self.rebuild(), None))
            else:
                if url.startswith("vmess") or url.startswith("ssr"):
                    _s = self.strDecode(self.body)
                    if _s.find(keyword) >= 0:
                        rst.append((url, self.rebuild(), _s))
                    else:
                        continue

        return rst

    def handleUrl(self, filename=None):

        self.outfile = self.get_filepath(
            filename) if filename else self.outfile

        with open(self.outfile, "r", encoding='utf8') as f:
            urlList = [h.strip() for h in f.readlines()
                       if h.strip().startswith("#") == False]

        with open(self.outfile, "w", encoding='utf8') as f:
            f.seek(0)
            f.truncate()

        urlList = list(set(urlList))
        urlList = sorted(urlList)

        for index, url in enumerate(urlList):
            url = str(url) if type(url) == bytes else url
            
            print('Current url is:{}/{} {}'.format(index, len(urlList), url.strip()))

            self.parse(url)
            i, p, u = self.rebuild()
            
            if i in ignoreList:
                continue

            if i is None:
                print('Address is None')
                continue

            r = self.vaild(i, p)
            print('Test result is:', r)

            if r is False:
                continue

            self.add(u)
            print('-'*100, '\n')

    def add(self,url,chk=False):
        url = url.strip()
        if chk:
            with open(self.outfile,"r",encoding="utf8") as f:
                _alist= [h.strip() for h in f.readlines()]
            if url in _alist:
                return "This URL is Exist"
            
        with open(self.outfile,"a+",encoding="utf8") as f:
            f.write(url+"\n")
        return "Add a URL:" + url

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

def run():
    u = URLParseHelper()

    with open('source.txt', 'r', encoding='utf8') as f:
        sourcelist = [h.strip() for h in f.readlines()
                      if h.strip().startswith("#") == False]

    for index, source in enumerate(sourcelist):
        print("********** Get Subscribe {}/{} **********".format(index+1, len(sourcelist)))
        if source.startswith("#"):
            continue

        # time.sleep(1)
        u.getSubscribeContent(source)

    removeDuplicateData(u.backupfile)

    # fList = walkFile()
    # fList.remove('collection')
    # fList.remove('source')
    # fList.remove('test')

    # for f in fList:
    # u.handleUrl(f)
    # removeDuplicateData('fly')

    u.handleUrl(u.outfile)
    clean_error()
    removeDuplicateData(u.outfile)
    encrypt_base64(u.outfile)

    splitFiles(u.outfile)
    for s in schemaList:
        encrypt_base64('{}.txt'.format(s))

def clash():
    clashfiles = ['clash.txt', 'clash2.txt']
    u = URLParseHelper()

    for cf in clashfiles:
        with open(cf, 'r', encoding='utf8') as f:
            urlList = [h.strip() for h in f.readlines()
                       if h.strip().startswith("#") == False]

        for index, url in enumerate(urlList):
            print(
                "********** Get Subscribe {}/{} **********".format(index+1, len(urlList)))
            if url.startswith("#"):
                continue

            if cf == 'clash2.txt':
                # "speed=30&c=HK,TW,KR,JP,US&type=ss,ssr,vless,trojan,vmess"
                _params = "speed=30&type=ss,ssr,trojan,vless,vmess"

                if url.find('?') >= 0:
                    url += '&' + _params
                else:
                    url += '?' + _params

            u.get_from_clash(url)

def repair():
    aList = []
    filename = 'fly.txt'

    for s in schemaList:
        with open('{}.txt'.format(s), encoding='utf8') as f:
            aList += f.readlines()

    with open(filename, "w", encoding='utf8') as f:
        f.seek(0)
        f.truncate()

    for u in aList:
        u = u.strip()
        if len(u) <= 0:
            continue

        with open(filename, 'a+', encoding="utf8") as f:
            f.writelines(u + '\n')

    if os.stat(filename).st_size == 0:
        os.remove(filename)
        shutil.copy('collection.txt', filename)
        
def clean_error():
    
    with open(u.errorfile , 'r', encoding="utf8") as f:
        aList = [h.strip() for h in f.readlines()]
    bList = []
    for index,line in enumerate(aList):
        print("{}/{}".format(index,len(aList)).center(100,"="))
        print(line)
        if line in bList:
            continue
        
        if line.strip().startswith("URL Test Error,[Errno 8]"):
            _url = line.strip().split(',')[3] 
        elif line.strip().startswith("URL Test Error,[Errno 11001]") or line.strip().startswith("URL Test Error,[Errno 11002]"):
            _url = line.strip().split(',')[2]
        # elif line.strip().startswith("build_query error: sequence item 1: expected str instance, list found"):
        #     if line not in bList:
        #         bList.append(line)
        #     continue
        else:
            if line not in bList:
                bList.append(line)
            continue
        
        if _url in ignoreList:
            continue
        print(_url.center(100,"*"))
        
        rst = u.find(_url)
        for r in rst:
            if isinstance(r[0], list):
                continue
            if r[0].startswith(tuple(schemaList)):
                # with open(u.outfile, "a+", encoding='utf8') as f2:
                #     f2.write(r[0] + '\n')
                u.add(r[0])
                    
                print(r[0].center(200,'='))
            
        # for i in range(aList.count(line)):
        #     aList.remove(line)
            
    with open(u.errorfile ,"w",encoding="utf8") as f:
        for b in bList:
            f.write(b.strip() + "\n")
    removeDuplicateData(u.outfile)

def run_with_args():
    import argparse
    parser = argparse.ArgumentParser()

    parser.add_argument('--normal', type=int,
                        required=False, default=0, help='normal')
    parser.add_argument('--repair', type=bool, required=False,
                        default=False, help='repair')
    parser.add_argument('--encode', type=bool, required=False,
                        default=False, help='encode')
    parser.add_argument('--debug', type=bool, required=False,
                        default=False, help='debug')
    parser.add_argument('--str', type=str, required=False,
                        default='', help='custom shop id')
    parser.add_argument('--need_more', type=bool,
                        required=False, default=False, help='need detail')
    args = parser.parse_args()

    print(args)
    if args.repair == 1:
        print("1")
    if args.repair:
        print("2")
    if args.debug == True:
        print("3")
    else:
        print("4")


if __name__ == "__main__":
    import sys
    u = URLParseHelper()
    args = sys.argv[1] if len(sys.argv) >= 2 else '_'
    match args:
        case 'addsource':
            with open("source.txt",'r', encoding="utf8") as f:
                sourceList = [h.strip() for h in f.readlines() if h.strip().startswith("#")==False]
            if sys.argv[2] not in sourceList:
                with open("source.txt",'a+', encoding="utf8") as f:
                    f.write(sys.argv[2]+"\n")
                print("Source Count:", len(sourceList)+1)
            else:
                print("This URL is Exist!")
                
        case 'run':
            run()
            clash()

        case 'source':
            with open('source.txt', 'r', encoding='utf8') as f:
                sourcelist = [h.strip() for h in f.readlines()
                              if h.strip().startswith("#") == False]

            for source in sourcelist:
                u.getSubscribeContent(source)

            removeDuplicateData(u.backupfile)

        case 'fly':
            u.handleUrl(u.outfile)
            encrypt_base64(u.outfile)

        case 'split':
            splitFiles(u.outfile)

        case 'encode':
            encrypt_base64(u.outfile)

            for s in schemaList:
                encrypt_base64('{}.txt'.format(s))

        case 'repair':
            repair()

        case 'clash':
            clash()

        case 'find':

            rst = u.find(sys.argv[2].lower())

            for r in rst:
                for a in r:
                    print(a)
                print('-'*100)

        case 'bug1':
            # Part 1: handle error.txt
            clean_error()

        case 'bug2':
            # Part 2
            urlList = [
                'vmess://YXV0bzo3OTM4NjY4NS0xNmRhLTMyN2MtOWUxNC1hYTZkNzAyZDg2YmNAaW5ncmVzcy1pMS5vbmVib3g2Lm9yZzozODcwMQ?remarks=github.com/freefq%20-%20%E5%B9%BF%E4%B8%9C%E7%9C%81%E6%B7%B1%E5%9C%B3%E5%B8%82%E8%85%BE%E8%AE%AF%E4%BA%91%2039&obfsParam=ingress-i1.onebox6.org&path=/hls/cctv5phd.m3u8&obfs=websocket&alterId=1',
                'vmess://YXV0bzpiZjY3NDM3ZS02YzkwLTQ1Y2EtYWJjMi1jNzI0MGE1Y2UyYWFAMTA0LjE2LjE2Mi4xNjoyMDUz?remarks=github.com/freefq%20-%20%E7%BE%8E%E5%9B%BDCloudFlare%E5%85%AC%E5%8F%B8CDN%E8%8A%82%E7%82%B9%2025&obfsParam=foxus.fovi.tk&path=/eisasqa&obfs=websocket&tls=1&peer=foxus.fovi.tk&alterId=0',
                'vmess://YXV0bzo3OTM4NjY4NS0xNmRhLTMyN2MtOWUxNC1hYTZkNzAyZDg2YmNAaW5ncmVzcy1pMS5vbmVib3g2Lm9yZzozODEwNg?remarks=github.com/freefq%20-%20%E4%B8%8A%E6%B5%B7%E5%B8%82%E7%94%B5%E4%BF%A1%2038&obfsParam=www.ivpnpro.net&path=/hls/cctv5phd.m3u8&obfs=websocket&alterId=1',
                'vmess://YXV0bzo3OTM4NjY4NS0xNmRhLTMyN2MtOWUxNC1hYTZkNzAyZDg2YmNAaW5ncmVzcy1pMS5vbmVib3g2Lm9yZzozODEwNg?remarks=github.com/freefq%20-%20%E4%B8%8A%E6%B5%B7%E5%B8%82%E7%94%B5%E4%BF%A1%2038&obfsParam=www.ivpnpro.net&path=/hls/cctv5phd.m3u8&obfs=websocket&alterId=1',
                'vmess://YXV0bzo5ZWE3MGQ1Ny05Y2I2LTNiZDAtYWU0MS01NjAxZTUxNmRjYzZAYmdwdjIua3R5anNxLmNvbToxMjIyMw?remarks=%25f0%259f%2587%25a8%25f0%259f%2587%25b3%20cn_77%2520%7C48.41mb&obfs=none&alterId=0',
                'vmess://YXV0bzo5ZWE3MGQ1Ny05Y2I2LTNiZDAtYWU0MS01NjAxZTUxNmRjYzZAYmdwdjIua3R5anNxLmNvbToxMjIyMw?remarks=%5B%E4%B8%AD%E5%9B%BDvmess%5Dbgpv2.ktyjsq.com:12223&obfs=none&alterId=0',
                'ss://YWVzLTI1Ni1jZmI6dkRTOUcycEAxODUuNC42NS42OjIxMjQ3#%5B%E4%BF%84%E7%BD%97%E6%96%AF%E8%81%94%E9%82%A6SS%5D185.4.65.6:21247',
                'trojan://e37c6d7efa845d60@116.129.253.130:3389?allowInsecure=1#CN_116.129.253.130:3389',
                'trojan://5c5ceb40-902b-11eb-945a-1239d0255272@sg1-trojan.bonds.id:443?allowInsecure=1#%5B%E6%96%B0%E5%8A%A0%E5%9D%A1TROJAN%5DSG1-TROJAN.BONDS.ID:443',
                'vmess://YXV0bzo3OTM4NjY4NS0xNmRhLTMyN2MtOWUxNC1hYTZkNzAyZDg2YmNAaW5ncmVzcy1pMS5vbmVib3g2Lm9yZzozODIwMQ?remarks=ingress-i1.onebox6.org&obfsParam=ingress-i1.onebox6.org&path=/hls/cctv5phd.m3u8&obfs=websocket&alterId=1',
                'vmess://YXV0bzpkYjVkMWFhMy05MDhiLTQ0ZDEtYmUwYS00ZTZhOGQ0ZTRjZGFAbHUxLmdvZ29nb28uY3lvdTo0NDM?remarks=lu1.gogogoo.cyou&obfsParam=lu1.gogogoo.cyou&path=/go&obfs=websocket&tls=1&peer=lu1.gogogoo.cyou&alterId=0',
                'vmess://YXV0bzo3OTM4NjY4NS0xNmRhLTMyN2MtOWUxNC1hYTZkNzAyZDg2YmNAaW5ncmVzcy1pMS5vbmVib3g2Lm9yZzozODcwMQ?remarks=ingress-i1.onebox6.org:38701&obfsParam=ingress-i1.onebox6.org&path=/hls/cctv5phd.m3u8&obfs=websocket&alterId=1',
                'ssr://aWVwbHN6aGstc3oucXFnZy53b3JrOjUyMzA2OmF1dGhfYWVzMTI4X21kNTphZXMtMjU2LWNmYjp0bHMxLjJfdGlja2V0X2F1dGg6YUVkclVUWTVNVFYwUkEvP3JlbWFya3M9UTA1ZjVMcU01NGkzNTctNzVhS1pJR2gwZEhCek9pOHZNVGd3T0M1bllTRG9pb0xuZ3JsZk1USXgmcHJvdG9wYXJhbT1NemN6T0RBNmF6UldTamxUZVVGMU13Jm9iZnNwYXJhbT1ZV3BoZUM1dGFXTnliM052Wm5RdVkyOXQ',
                'ss://YWVzLTEyOC1nY206ZGVzcGVyYWRvai5jb21fZnJlZV9wcm94eV9kMzltQDEwMS4xMzIuMTkyLjIxMjozMDAwMw#%5B%E4%B8%AD%E5%9B%BDSS%5D101.132.192.212:30003',
                'ss://YWVzLTI1Ni1jZmI6Y3A4cFJTVUF5TGhUZlZXSEAyMTMuMTgzLjU5LjE5MTo5MDY0#%5B%E8%8D%B7%E5%85%B0SS%5D213.183.59.191:9064',
                'ss://YWVzLTI1Ni1jZmI6VlA4WlB4UXBKdFpSQ2pmWkA2Mi4yMTYuOTEuMjI5OjkwODA#%5B%E7%BE%8E%E5%9B%BDSS%5D62.216.91.229:9080',
                'ss://YWVzLTI1Ni1jZmI6dkRTOUcycEAxODUuNC42NS42OjIxMjQ3#%5B%E4%BF%84%E7%BD%97%E6%96%AF%E8%81%94%E9%82%A6SS%5D185.4.65.6:21247',
            ]
            for url in urlList:
                u.add(url)

        case 'bug3':
            with open(u.errorfile , 'r',encoding="utf8") as f:
                urlList = [h.strip().replace("build_query error: 'NoneType' object has no attribute 'startswith',", '') for h in f.readlines(
                ) if h.strip().startswith("build_query error: 'NoneType' object has no attribute 'startswith',")]
            urlList = sorted(list(set(urlList)))

            # urlList = [ json.loads(h)['remark'] for h in urlList]
            # print(urlList)
            alist = []
            for h in urlList:
                h = re.findall(r"'remark': '(.*),\s'", h)[0].split(',')[0]
                h = re.findall(r"](.*)'", h)[0]
                h = h.split(":")[0]
                alist.append(h.lower())
            # print(alist)
            alist = sorted(list(set(alist)))
            for a in alist:
                print(a)
                if a in ignoreList:
                    continue

                rst = u.find(a)
                for r in rst:
                    if isinstance(r[0], list):
                        continue
                    if r[0].startswith(tuple(schemaList)):
                        # print(r[0])
                        u.add(r[0])
                        print('-'*100)

        case 'debug':
            # print("File Size(B):",os.stat(u.outfile).st_size)

            urlList = u.find("43.155.117.192".lower())
            # rst = u.rebuild(url[0])
            # print(rst[2])
            for index,url in enumerate(urlList):
                print("="*50,index+1,"/",len(urlList),"="*50)
                print(url[0])

        case 'test':
            l = ['a','b','c','d','a','b','c','d']
            for char in l:
                print(char)
                for i in range(l.count("c")):
                    l.remove("c")      
            print(l.count("c"))

        case 'http2':
            url = 'http2://ZGNmMTJjN2U3ZDoyNmJhZTliMDIzQGg5NjEzNTkud2FpaHVpemhpYmlhb3dhbmcuY29tOjExNTQ1?peer=h961359.waihuizhibiaowang.com#CTVIP-HK-3%5Bran-out%5D'
            u.parse(url)
            a = u.ssObj()
            print(a)
        case _:
            print(
                'Usage: %s [run | source | fly | split | encode | repair | debug | clash | clash2 | find ]' % sys.argv[0])
