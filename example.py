#!/usr/bin/env python
# -*- coding: UTF-8 -*-
try:
    import scapy.all as scapy
except ImportError:
    import scapy

import http

packets = scapy.rdpcap('example_network_traffic.pcap')
for p in packets:
    print '=' * 78
    p.show()
