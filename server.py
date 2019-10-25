#!/usr/bin/env python
#-*- coding:utf-8 -*-
import sys

try:
    import gevent, gevent.monkey
    gevent.monkey.patch_all(dns=gevent.version_info[0]>=1)
except ImportError:
    gevent = None
    print >>sys.stderr, 'warning: gevent not found, using threading instead'

import socket
import select
import SocketServer
import struct
import string
import hashlib
import os,sys
import json
import logging
import getopt
from disguise import mysql
def send_all(sock, data):
    bytes_sent = 0
    while True:
        r = sock.send(data[bytes_sent:])
        if r < 0:
            return r
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent
class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True
class Socks5Server(SocketServer.StreamRequestHandler):
    def handle_tcp(self, sock, remote):
        try:
            fdset = [sock, remote]
            while True:
                r, w, e = select.select(fdset, [], [])
                if sock in r:
                    data = sock.recv(4096)
                    if len(data) <= 0:
                        break
                    result = send_all(remote,data)
                    if result < len(data):
                        raise Exception('failed to send all data')
                if remote in r:
                    data = remote.recv(4096)
                    if len(data) <= 0:
                        break
                    result = send_all(sock,data)
                    if result < len(data):
                        raise Exception('failed to send all data')

        finally:
            sock.close()
            remote.close()
    def handle(self):
        try:
            sock = self.connection
            if PROXY_MODE=='mysql':
                status=mysql.disguise_server_mysql(sock)
            else:
                status=0
            if status==1:
                sock.close()
            else:
                addr_len=ord(sock.recv(1))
                addr =sock.recv(addr_len)   # get dst addr
                print addr
                port_len=ord(sock.recv(1))
                port =int(sock.recv(port_len))
                print(port)
                try:
                    logging.info('connecting %s:%d' % (addr, port))
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    remote.connect((addr,port))         # connect to dst
                except socket.error, e:
                    # Connection refused
                    logging.warn(e)
                    return
                self.handle_tcp(sock,remote)
        except socket.error, e:
            logging.warn(e)
if __name__ == '__main__':
    with open('config.json', 'rb') as f:
        config = json.load(f)
    SERVER = config['server']
    PORT = config['server_port']
    KEY = config['password']
    PROXY_PORT=config['proxy_port']
    PROXY_MODE=config['proxy_mode']
    try:
        server = ThreadingTCPServer(('', PROXY_PORT), Socks5Server)
        logging.info("starting server at port %d ..." % PORT)
        server.serve_forever()
    except socket.error, e:
        logging.error(e)
