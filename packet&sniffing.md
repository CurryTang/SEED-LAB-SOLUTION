## Packet & Sniffing

### Task 1.1A

Without sudo, the program can not run properly since creating socket object requires root priviledge. 

### Task 1.1B

For the first task, it's just the source we were given. 

For tcp packets, it will output nothing. However, it we try to send some ICMP packets(using ping command), it will capture them. 

For the code 

``` python
#!/usr/bin/python3

from scapy.all import *

def print_pkt(pkt):
        pkt.show()

pkt = sniff(filter='icmp', prn=print_pkt)
pkt2 = sniff(filter='tcp and src 127.0.0.1 and port 23', prn=print_pkt)
pkt3 = sniff(filter='net 192.168.1.0/24', prn=print_pkt)

```


