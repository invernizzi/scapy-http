#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : Steeve Barbeau, Luca Invernizzi
# This program is published under a GPLv2 license

import re
from scapy.all import TCP, bind_layers, Packet, StrField


def _canonicalize_header(name):
    ''' Takes a header key (i.e., "Host" in "Host: www.google.com",
        and returns a canonical representation of it '''
    return name.strip().lower()


def _parse_headers(s):
    ''' Takes a HTTP packet, and returns a tuple containing:
      - the first line (e.g., "GET ...")
      - the headers in a dictionary
      - the body '''
    try:
        headers, body = s.split("\r\n\r\n", 1)
    except:
        headers = s
        body = ''
    headers = headers.split("\r\n")
    first_line, headers = headers[0].strip(), headers[1:]
    headers_found = {}
    for header_line in headers:
        try:
            key, value = header_line.split(':', 1)
        except:
            continue
        headers_found[_canonicalize_header(key)] = header_line.strip()
    return first_line, headers_found, body


def _dissect_headers(obj, s):
    ''' Takes a HTTP packet as the string s, and populates the scapy layer obj
        (either HTTPResponse or HTTPRequest). Returns the first line of the
        HTTP packet, and the body
    '''
    first_line, headers, body = _parse_headers(s)
    for f in obj.fields_desc:
        canonical_name = _canonicalize_header(f.name)
        try:
            header_line = headers[canonical_name]
        except:
            continue
        key, value = header_line.split(':', 1)
        obj.setfieldval(f.name,  value.strip())
        del headers[canonical_name]
    if headers:
        obj.setfieldval(
            'Additional-Headers', '\r\n'.join(headers.values()) + '\r\n')
    return first_line, body


def _self_build(obj, field_pos_list=None):
    ''' Takse an HTTPRequest or HTTPResponse object, and creates its internal
    scapy representation as a string. That is, generates the HTTP
    packet as a string '''
    p = ""
    for f in obj.fields_desc:
        val = obj.getfieldval(f.name)
        if not val:
            continue
        val += '\r\n'
        if f.name in ['Method', 'Additional-Headers', 'Status-Line']:
            p = f.addfield(obj, p, val)
        else:
            p = f.addfield(obj, p, "%s: %s" % (f.name, val))
    return p


class HTTPRequest(Packet):

    name = "HTTP Request"
    http_methods = "^(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT)"
    fields_desc = [StrField("Method", None, fmt="H"),
                StrField("Path", None, fmt="H"),
                StrField("Http-Version", None, fmt="H"),
                StrField("Host", None, fmt="H"),
                StrField("User-Agent", None, fmt="H"),
                StrField("Accept", None, fmt="H"),
                StrField("Accept-Language", None, fmt="H"),
                StrField("Accept-Encoding", None, fmt="H"),
                StrField("Accept-Charset", None, fmt="H"),
                StrField("Referer", None, fmt="H"),
                StrField("Authorization", None, fmt="H"),
                StrField("Expect", None, fmt="H"),
                StrField("From", None, fmt="H"),
                StrField("If-Match", None, fmt="H"),
                StrField("If-Modified-Since", None, fmt="H"),
                StrField("If-None-Match", None, fmt="H"),
                StrField("If-Range", None, fmt="H"),
                StrField("If-Unmodified-Since", None, fmt="H"),
                StrField("Max-Forwards", None, fmt="H"),
                StrField("Proxy-Authorization", None, fmt="H"),
                StrField("Range", None, fmt="H"),
                StrField("TE", None, fmt="H"),
                StrField("Cache-Control", None, fmt="H"),
                StrField("Connection", None, fmt="H"),
                StrField("Date", None, fmt="H"),
                StrField("Pragma", None, fmt="H"),
                StrField("Trailer", None, fmt="H"),
                StrField("Transfer-Encoding", None, fmt="H"),
                StrField("Upgrade", None, fmt="H"),
                StrField("Via", None, fmt="H"),
                StrField("Warning", None, fmt="H"),
                StrField("Keep-Alive", None, fmt="H"),
                StrField("Allow", None, fmt="H"),
                StrField("Content-Encoding", None, fmt="H"),
                StrField("Content-Language", None, fmt="H"),
                StrField("Content-Length", None, fmt="H"),
                StrField("Content-Location", None, fmt="H"),
                StrField("Content-MD5", None, fmt="H"),
                StrField("Content-Range", None, fmt="H"),
                StrField("Content-Type", None, fmt="H"),
                StrField("Expires", None, fmt="H"),
                StrField("Last-Modified", None, fmt="H"),
                StrField("Cookie", None, fmt="H"),
                StrField("Additional-Headers", None, fmt="H")]

    def do_dissect(self, s):
        ''' From the HTTP packet string, populate the scapy object '''
        first_line, body = _dissect_headers(self, s)
        Method, Path, HTTPVersion = re.split("\s+", first_line)
        
        self.setfieldval('Method', Method)
        self.setfieldval('Path', Path)
        self.setfieldval('Http-Version', HTTPVersion)
        return body

    def self_build(self, field_pos_list=None):
        ''' Generate the HTTP packet string (the oppposite of do_dissect) '''
        return _self_build(self, field_pos_list)


class HTTPResponse(Packet):

    name = "HTTP Response"
    fields_desc = [StrField("Status-Line", None, fmt="H"),
                StrField("Accept-Ranges", None, fmt="H"),
                StrField("Age", None, fmt="H"),
                StrField("E-Tag", None, fmt="H"),
                StrField("Location", None, fmt="H"),
                StrField("Proxy-Authenticate", None, fmt="H"),
                StrField("Retry-After", None, fmt="H"),
                StrField("Server", None, fmt="H"),
                StrField("Vary", None, fmt="H"),
                StrField("WWW-Authenticate", None, fmt="H"),
                StrField("Cache-Control", None, fmt="H"),
                StrField("Connection", None, fmt="H"),
                StrField("Date", None, fmt="H"),
                StrField("Pragma", None, fmt="H"),
                StrField("Trailer", None, fmt="H"),
                StrField("Transfer-Encoding", None, fmt="H"),
                StrField("Upgrade", None, fmt="H"),
                StrField("Via", None, fmt="H"),
                StrField("Warning", None, fmt="H"),
                StrField("Keep-Alive", None, fmt="H"),
                StrField("Allow", None, fmt="H"),
                StrField("Content-Encoding", None, fmt="H"),
                StrField("Content-Language", None, fmt="H"),
                StrField("Content-Length", None, fmt="H"),
                StrField("Content-Location", None, fmt="H"),
                StrField("Content-MD5", None, fmt="H"),
                StrField("Content-Range", None, fmt="H"),
                StrField("Content-Type", None, fmt="H"),
                StrField("Expires", None, fmt="H"),
                StrField("Last-Modified", None, fmt="H"),
                StrField("Additional-Headers", None, fmt="H")]

    def do_dissect(self, s):
        ''' From the HTTP packet string, populate the scapy object '''
        first_line, body = _dissect_headers(self, s)
        self.setfieldval('Status-Line', first_line)
        return body

    def self_build(self, field_pos_list=None):
        ''' From the HTTP packet string, populate the scapy object '''
        return _self_build(self, field_pos_list)


class HTTP(Packet):

    name = "HTTP"

    def do_dissect(self, s):
        return s

    def guess_payload_class(self, payload):
        ''' Decides if the payload is an HTTP Request or Response, or
            something else '''
        try:
            prog = re.compile(
                r"^(?:OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT) "
                r"(?:.+?) "
                r"HTTP/\d\.\d$"
            )
            req = payload[:payload.index("\r\n")]
            result = prog.match(req)
            if result:
                return HTTPRequest
            else:
                prog = re.compile(r"^HTTP/\d\.\d \d\d\d .+?$")
                result = prog.match(req)
                if result:
                    return HTTPResponse
        except:
            pass
        return Packet.guess_payload_class(self, payload)

bind_layers(TCP, HTTP)
