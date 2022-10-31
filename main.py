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

        _s1 = self.body[0:self.body.find('_')] if self.body.find('_') > 0 else self.body
        _s = self.strDecode(_s1).strip().split(':')
        _tagName = self.getTagName(_s[0], _s[1])
        print(_tagName)
        _url_path, _url_qs = parse_qs_ssr(_s[-1])
        print(_url_qs)
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

    def vlessObj(self):
        _ip, _port, _url = self.splitURL()

        _tagname = self.getTagName(_ip, _port, True)
        _query = self.build_queryObj(key='alpn', value=_tagname)
        _query = self.build_query(_query)

        _fragment = _tagname if self.urlObj.fragment != '' else ''

        _newUrl = urllib.parse.urlunparse(
            (self.urlObj.scheme, self.urlObj.netloc, self.urlObj.path, self.urlObj.params, _query, _fragment))

        return _ip, _port, _newUrl

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
                    r = self.vlessObj()
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
    

if __name__ == "__main__":
    uhelper = URLParseHelper()
    match sys.argv[1]:
        case 'debug':
            url = 'ssr://bms1LmJvb20uc2tpbjoxNTAwMDphdXRoX2FlczEyOF9zaGExOmFlcy0yNTYtY2ZiOmh0dHBfc2ltcGxlOlZXczVNa05ULz9vYmZzcGFyYW09emc5M2JteHZ5d3F1ZDJsdXpnOTNjM3Z3emdmMHpzNWpiMjAmcHJvdG9wYXJhbT1vZHkyb3RhNnZodnRiaHptJmdyb3VwPXUyOWphMGp2YjIw'
            
            rst = uhelper.rebuild(url)
            print(rst)
            print(uhelper.urlObj)
            print(uhelper.body)
            
        
        case _:
            print(
                'Usage: %s [run | source | fly | split | encode | repair | debug | clash | clash2 | find ]' % sys.argv[0])