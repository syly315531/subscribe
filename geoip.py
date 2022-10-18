from urllib import response
import geoip2.database
import os


def get_filepath():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),'GeoLite2','GeoLite2-City.mmdb')

def get_city(ipaddress):
    with geoip2.database.Reader(get_filepath()) as reader:
        response = reader.city(ipaddress)
    
    return response

if __name__ == "__main__":
    
    res = get_city("139.227.182.41")
    print(res)
    print(res.country.names['zh-CN'])
    print(res.city.names['zh-CN'])