#!/usr/bin/python3
# -*- coding: UTF-8 -*-

import os
import sys
import urllib
import time

import base64
import json
import subprocess

import requests

from shadowsocks import Shadowsocks
from v2ray import V2ray


def decode(base64Str):
    base64Str = base64Str.replace('\n', '').replace('-', '+').replace('_', '/')
    padding = int(len(base64Str) % 4)
    if padding != 0:
        base64Str += '=' * (4 - padding)
    return str(base64.b64decode(base64Str),  'utf-8')
def askfollowRedirect(json):
    isfollowRedirect = ''
    try:
        isfollowRedirect = input('是否使用透明代理（重启失效）？[y/n/exit]')
    except KeyboardInterrupt:
        exit()
    except BaseException:
        return json
    if isfollowRedirect == 'y':
        # 判断是否开启了ip转发
        ipforward = subprocess.check_output("cat /proc/sys/net/ipv4/ip_forward",  shell=True)
        if ipforward == b'0\n':
            #添加ip转发
            subprocess.call("sysctl -w net.ipv4.ip_forward=1",  shell=True)
            subprocess.call("sysctl -p /etc/sysctl.conf", shell=True)
        ## 修改json的相关参数
        json['inbounds'].append({
           "port": 12345,
           "protocol": "dokodemo-door",
           "settings": {
             "network": "tcp,udp",
             "followRedirect": True
           },
            "tag":"followRedirect",
           "sniffing": {
             "enabled": True,
             "destOverride": ["http", "tls"]
           }
        })
        json['routing']['settings']['rules'].append({
            "type": "field",
            "inboundTag": ["followRedirect"],
            "outboundTag": "out"
        })
        for outbound in json['outbounds']:
            if outbound["protocol"] == 'vmess' or outbound["protocol"] == 'shadowsocks':
                outbound['streamSettings']['sockopt'] = {
                    "mark": 255
                }
        #关闭之前的iptables转发
        closeiptableRedirect()
        #开启iptable转发
        openiptableRedirect()
        return json
    elif isfollowRedirect == 'n':
        ipforward = subprocess.check_output("cat /proc/sys/net/ipv4/ip_forward",  shell=True)
        if ipforward == b'1\n':
            # 添加ip转发
            subprocess.call("sysctl -w net.ipv4.ip_forward=0", shell=True, stdout = subprocess.DEVNULL)
            subprocess.call("sysctl -p /etc/sysctl.conf", shell=True, stdout = subprocess.DEVNULL)
        closeiptableRedirect()
        return json
    else:
        return askfollowRedirect(json)

def openiptableRedirect():
    subprocess.call("iptables -t nat -N V2RAY", shell=True, stdout = subprocess.DEVNULL)
    subprocess.call("iptables -t nat -A V2RAY -d 192.168.0.0/16 -j RETURN", shell=True, stdout = subprocess.DEVNULL)
    subprocess.call("iptables -t nat -A V2RAY -d 172.16.0.0/16 -j RETURN", shell=True, stdout = subprocess.DEVNULL)
    subprocess.call("iptables -t nat -A V2RAY -d 10.0.0.0/16 -j RETURN", shell=True, stdout = subprocess.DEVNULL)
    subprocess.call("iptables -t nat -A V2RAY -p tcp -j RETURN -m mark --mark 0xff", shell=True, stdout = subprocess.DEVNULL)
    subprocess.call("iptables -t nat -A V2RAY -p udp -j RETURN -m mark --mark 0xff", shell=True, stdout = subprocess.DEVNULL)
    try:
        subprocess.call("iptables -t nat -A V2RAY -p tcp --match multiport ! --dports 12345,1080,22 -j REDIRECT --to-ports 12345",shell=True, stdout = subprocess.DEVNULL)
    except BaseException:
        print('以存在相应规则!跳过!')
    subprocess.call("iptables -t nat -A OUTPUT -p tcp -j V2RAY", shell=True, stdout = subprocess.DEVNULL)

def closeiptableRedirect():
    subprocess.call("iptables -t nat -F V2RAY", shell=True, stdout = subprocess.DEVNULL)


mode = 'changeNode'
v2rayConfigLocal='/etc/v2ray/config.json'
testFileUrl="http://cachefly.cachefly.net/10mb.test"
if len(sys.argv) == 2:
    mode = sys.argv[1]

# 鉴权
if os.geteuid() != 0:
    print("您需要切换到 Root 身份才可以使用本脚本。尝试在命令前加上 sudo?\n")
    exit()

#判断v2ray服务是否安装
if subprocess.call("systemctl is-enabled v2ray.service", shell=True, stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL) == 1:
    print('检测到v2ray未安装,将执行官方脚本安装v2ray,如果下载速度缓慢,请考虑手动本地安装v2ray,参考地址：https://www.v2ray.com/chapter_00/install.html')
    print('正在下载官方脚本')
    subprocess.run("wget https://install.direct/go.sh", shell=True, stdout = subprocess.DEVNULL)
    print('正在安装v2ray')
    subprocess.check_call('bash go.sh', shell=True)
    print('执行清理工作')
    subprocess.run('rm -rf go.sh', shell=True)


# 本脚本的配置文件，目前的作用是仅存储用户输入的订阅地址，这样用户再次启动脚本时，就无需再输入订阅地址。
# 预设的存储的路径为存储到用户的 HOME 内。
subFilePath = os.path.expandvars('$HOME') + '/.v2sub.conf'
# 获取订阅地址
if not os.path.exists(subFilePath):
    open(subFilePath, 'w+')

subFile = open(subFilePath, 'r')
subLink = subFile.read().strip()
subFile.close()

if not subLink:
    print('您还没有输入订阅地址，请输入订阅地址。')
    try:
        subLink = input('订阅地址：')
    except KeyboardInterrupt:
        exit()
    subFile = open(subFilePath, 'w+')
    subFile.write(subLink)
    subFile.close()
else:
    print('订阅地址：'+subLink)
print('如果您的订阅地址有误，请删除或编辑 '+subFilePath)

print("\n开始从订阅地址中读取服务器节点… 如等待时间过久，请检查网络。\n")

# 获取订阅信息
urldata = requests.get(subLink).text
serverListLink = decode(urldata).splitlines(False)
for i in range(len(serverListLink)):
    if serverListLink[i].startswith('ss://'):
      # ss node
      base64Str = serverListLink[i].replace('ss://', '')
      base64Str = urllib.parse.unquote(base64Str)
      origin = decode(base64Str[0 : base64Str.index('#')])
      remark = base64Str[base64Str.index('#') + 1 :]
      security = origin[0 : origin.index(':')]
      password = origin[origin.index(':') + 1 : origin.index('@')]
      ipandport = origin[origin.index('@') + 1 : ]
      ip = ipandport[0: ipandport.index(':')]
      port = int(ipandport[ipandport.index(':') + 1:])
      print('【' + str(i) + '】' + remark)
      ssNode = Shadowsocks(ip, port, remark, security, password)
      serverListLink[i] = ssNode
    else:
        # vmess
        base64Str = serverListLink[i].replace('vmess://', '')
        jsonstr = decode(base64Str)
        serverNode = json.loads(jsonstr)
        print('【' + str(i) + '】' + serverNode['ps'])
        v2Node = V2ray(serverNode['add'], int(serverNode['port']), serverNode['ps'], 'auto', serverNode['id'], int(serverNode['aid']), serverNode['net'], serverNode['type'], serverNode['host'], serverNode['path'], serverNode['tls'])
        serverListLink[i] = v2Node

if mode == 'changeNode':
    while True:
        try:
            setServerNodeId = int(input("\n请输入要切换的节点编号："))
        except KeyboardInterrupt:
            break
        except BaseException:
            continue
        subprocess.call('ping ' + serverListLink[setServerNodeId].ip + ' -c 3 -w 10', shell=True)
        inputStr = input('确定要使用该节点吗？[y/n/exit]  ')
        if inputStr == 'y':

            jsonObj = serverListLink[setServerNodeId].formatConfig()
            jsonObj = askfollowRedirect(jsonObj)
            json.dump(jsonObj, open(v2rayConfigLocal, 'w'), indent=2)
            print("\n重启 v2ray 服务……\n")
            subprocess.call('systemctl restart v2ray.service', shell=True)
            print('地址切换完成')
            print('代理端口协议：socks5')
            print('代理地址: 127.0.0.1')
            print('代理端口号：1080')
            exit()
        elif inputStr == 'n':
            continue
        else:
            break
else:
    # copy config.json
    print("\n当前模式为测速模式\n")
    print("\n正在备份现有配置文件 %s\n" % v2rayConfigLocal)
    subprocess.call('cp ' + v2rayConfigLocal + ' ' + v2rayConfigLocal + '.bak', shell=True)
    for i in range(len(serverListLink)):
        json.dump(serverListLink[i].formatConfig(), open(v2rayConfigLocal, 'w'), indent=2)
        subprocess.call('systemctl restart v2ray.service', shell=True)
        try:
            time.sleep(5)
            output = subprocess.check_output('curl -o /dev/null -s -w %{speed_download} -x socks5://127.0.0.1:1080 ' + testFileUrl, shell=True)
        except KeyboardInterrupt:
            break
        except BaseException:
            output = b'0.000'
        print('【%d】%s : %d kb/s' %(i, serverListLink[i].remark, float(output) / 1000))
    print("\n正在恢复现有配置文件 %s\n" % v2rayConfigLocal)
    subprocess.call('mv ' + v2rayConfigLocal + '.bak ' + v2rayConfigLocal , shell=True)
    subprocess.call('systemctl restart v2ray.service', shell=True)




