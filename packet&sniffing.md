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

### Task 1.3

```
#!/usr/bin/python3

from scapy.all import *

def traceroute(ip):
	ttl_i = 1
	packet_result = sr(IP(dst=ip, ttl = ttl_i)/ICMP())
	server_response = packet_result[0][0][1].sprintf("%ICMP.type%")
	while server_response != 'echo-reply':
		print("Now the ttl of packet should be :{}".format(ttl_i))
		ttl_i += 1
		packet_result, unanswered = sr(IP(dst=ip, ttl = ttl_i)/ICMP(), timeout=1.5)
		if not packet_result:
			continue
		server_response = packet_result[0][1].sprintf("%ICMP.type%")
	return ttl_i


if __name__ == '__main__':
	result = traceroute("220.181.38.148")
	print("The traceroute result should be {}".format(result))

```
It should be mentioned that timeout is necessary here. Some servers will ban ICMP packets so we will never get any responses. 


