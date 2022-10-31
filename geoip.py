from urllib import response
import geoip2.database
import os
import socket
import re


def get_filepath(dbfile):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),'GeoLite2',f'GeoLite2-{dbfile}.mmdb')

def get_country(ipaddress):
    with geoip2.database.Reader(get_filepath("Country")) as reader:
        response = reader.country(ipaddress)
    return response

def get_city(ipaddress):
    with geoip2.database.Reader(get_filepath("City")) as reader:
        response = reader.city(ipaddress)
    
    return response

def get_asn(ipaddress):
    with geoip2.database.Reader(get_filepath('ASN')) as reader:
        response = reader.asn(ipaddress)
    
    return response

def is_ip(s):
    # reg = "^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
    reg = "^((\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\.){3}(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])(?::(?:[0-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?$"
    p = re.compile(reg)
    return True if p.match(s) else False

def domain2ip(domain):
    return socket.getaddrinfo(domain, None)[0][4][0]

def getCountry(ipaddress):
    ipaddress = ipaddress if is_ip(ipaddress) else domain2ip(ipaddress)
    return get_country(ipaddress).country.names['zh-CN']

if __name__ == "__main__":
    aList = [
        "www.github.com",
        "139.227.182.41",
        "47.103.74.242",
        "103.156.68.191",
    ]
    try:
        for ipStr in aList:
            ipStr = ipStr if is_ip(ipStr) else domain2ip(ipStr)
        
            print(ipStr)
            print(get_country(ipStr).country.names['zh-CN'])
            print(get_city(ipStr).city.names['zh-CN'])
            print(get_asn(ipStr).autonomous_system_organization)
            # print(res.country.names['zh-CN'])
    except Exception as e:
        print(e)
        
    print(get_city("103.156.68.191"))