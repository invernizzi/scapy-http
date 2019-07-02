
OBSOLETE!
=========
Scapy 2.4.3+ has [native](https://github.com/secdev/scapy/pull/1925) support for HTTP.  It has the same syntax as this package (isn't that nice), plus it packs more features!

Please consider this package as obsolete - long live Scapy!

__DEPRECATED!__
__DEPRECATED!__
__DEPRECATED!__





Scapy-http
==========
Support for parsing HTTP in [Scapy](http://www.secdev.org/projects/scapy/). Compatible with [Scapy3k](https://github.com/phaethon/scapy).

Collaborator wanted!
--------
Hi there, internet stranger! As time is a scarce resource for me nowadays, I'm looking for a collaborator to handle issues and pull requests in a more timely manner. If you are interested, send me an email at `invernizzi.l@gmail.com`. 

Installation
--------

Execute:

```bash
sudo pip install scapy-http
```

Or, to install from source
```bash
sudo python setup.py install
```


Example
--------

## Code
```python
#!/usr/bin/env python
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
    print '=' * 78
    p.show()
```

## Output

```python
==============================================================================
###[ Ethernet ]###
  dst       = 00:21:29:77:3d:d8
  src       = 64:80:99:63:29:94
  type      = 0x800
###[ IP ]###
     version   = 4L
     ihl       = 5L
     tos       = 0x0
     len       = 154
     id        = 46316
     flags     = DF
     frag      = 0L
     ttl       = 64
     proto     = tcp
     chksum    = 0x100b
     src       = 192.168.1.105
     dst       = 207.97.227.243
     \options   \
###[ TCP ]###
        sport     = 52157
        dport     = http
        seq       = 3687400232
        ack       = 2748912324
        dataofs   = 5L
        reserved  = 0L
        flags     = PA
        window    = 14600
        chksum    = 0xb333
        urgptr    = 0
        options   = []
###[ HTTP ]###
###[ HTTP Request ]###
              Method    = 'GET'
              Path      = '/'
              Http-Version= 'HTTP/1.1'
              Host      = 'www.github.com'
              User-Agent= 'Wget/1.13.4 (linux-gnu)'
              Accept    = '*/*'
              Accept-Language= None
              Accept-Encoding= None
              Accept-Charset= None
              Referer   = None
              Authorization= None
              Expect    = None
              From      = None
              If-Match  = None
              If-Modified-Since= None
              If-None-Match= None
              If-Range  = None
              If-Unmodified-Since= None
              Max-Forwards= None
              Proxy-Authorization= None
              Range     = None
              TE        = None
              Cache-Control= None
              Connection= 'Keep-Alive'
              Date      = None
              Pragma    = None
              Trailer   = None
              Transfer-Encoding= None
              Upgrade   = None
              Via       = None
              Warning   = None
              Keep-Alive= None
              Allow     = None
              Content-Encoding= None
              Content-Language= None
              Content-Length= None
              Content-Location= None
              Content-MD5= None
              Content-Range= None
              Content-Type= None
              Expires   = None
              Last-Modified= None
              Cookie    = None
              Additional-Headers= None
==============================================================================
###[ Ethernet ]###
  dst       = 64:80:99:63:29:94
  src       = 00:21:29:77:3d:d8
  type      = 0x800
###[ IP ]###
     version   = 4L
     ihl       = 5L
     tos       = 0x0
     len       = 418
     id        = 29348
     flags     = DF
     frag      = 0L
     ttl       = 55
     proto     = tcp
     chksum    = 0x5a4b
     src       = 207.97.227.243
     dst       = 192.168.1.105
     \options   \
###[ TCP ]###
        sport     = http
        dport     = 52157
        seq       = 2748912324
        ack       = 3687400346
        dataofs   = 5L
        reserved  = 0L
        flags     = PA
        window    = 5840
        chksum    = 0x78e7
        urgptr    = 0
        options   = []
###[ HTTP ]###
###[ HTTP Response ]###
              Status-Line= 'HTTP/1.1 301 Moved Permanently'
              Accept-Ranges= None
              Age       = None
              E-Tag     = None
              Location  = 'http://github.com/'
              Proxy-Authenticate= None
              Retry-After= None
              Server    = 'nginx/1.0.13'
              Vary      = None
              WWW-Authenticate= None
              Cache-Control= None
              Connection= 'keep-alive'
              Date      = 'Wed, 27 Jun 2012 06:53:41 GMT'
              Pragma    = None
              Trailer   = None
              Transfer-Encoding= None
              Upgrade   = None
              Via       = None
              Warning   = None
              Keep-Alive= None
              Allow     = None
              Content-Encoding= None
              Content-Language= None
              Content-Length= '185'
              Content-Location= None
              Content-MD5= None
              Content-Range= None
              Content-Type= 'text/html'
              Expires   = None
              Last-Modified= None
              Additional-Headers= None
###[ Raw ]###
                 load      = '<html>\r\n<head><title>301 Moved Permanently</title></head>\r\n<body bgcolor="white">\r\n<center><h1>301 Moved Permanently</h1></center>\r\n<hr><center>nginx/1.0.13</center>\r\n</body>\r\n</html>\r\n'

```

## Authors
* Steeve Barbeau  ( http://www.sbarbeau.fr )
* Luca Invernizzi ( http://lucainvernizzi.net )
