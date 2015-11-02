#!/usr/bin/env python
# -*- coding: UTF-8 -*-
try:
    import scapy.all as scapy
except ImportError:
    import scapy

try:
    # This import works from the project directory
    import scapy_http.http
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers import http

packets = scapy.rdpcap('example_network_traffic.pcap')
for p in packets:
    print('=' * 78)
    p.show()
