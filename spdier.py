import requests
from lxml import etree

schemaList = ['ss', 'ssr', 'trojan', 'vless', 'vmess','http2']

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
                # rsp = re.sub('\n', '', rsp)

                # rsp = strDecode(rsp, False) if dec else rsp
                # time.sleep(3)
            else:
                print(rsp.status_code, rsp.url)
                raise(rsp.status_code)

        except Exception as e:
            rsp = ''
            # raise(e)

        # return rsp.splitlines()
        return rsp

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

if __name__ == "__main__":
    rst = banyunxiaoxi()
    print(len(rst))
    
    