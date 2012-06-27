#!/usr/bin/env python
try:
    import scapy.all as scapy
except ImportError:
    import scapy

import HTTP

packets = scapy.rdpcap('example_network_traffic.pcap')
for p in packets:
    print '=' * 78
    p.show()
