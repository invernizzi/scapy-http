#!/usr/bin/env python
# -*- coding: UTF-8 -*-
try:
    import scapy.all as scapy
except ImportError:
    import scapy

# If you installed the package, you can skip this import
import scapy_http.http

packets = scapy.rdpcap('example_network_traffic.pcap')
for p in packets:
    print '=' * 78
    p.show()
