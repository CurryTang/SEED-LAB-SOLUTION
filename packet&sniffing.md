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

### Task 1.4 
``` python
from scapy.all import *

def spoof_reply(pkt):
    """
    Craft a valid ICMP echo-reply based on an intercepted
    ICMP echo-request    
    """

    if (pkt[2].type == 8):
    #check if the ICMP is a request

        dst=pkt[1].dst
        #store the original packet's destination

        src=pkt[1].src
        #store the original packet's source

        seq = pkt[2].seq
        #store the original packet's sequence

        id = pkt[2].id
        #store the original packet's id

        load=pkt[3].load
        #store the original packet's load

        reply = IP(src=dst, dst=src)/ICMP(type=0, id=id, seq=seq)/load
        #construct the reply packet based on details derived from the
        #original packet, but make sure to flip dst and src

        send(reply)

if __name__=="__main__":
    """
    Sniff ICMP echo-request from a victim's ip and respond
    with valid ICMP echo-reply  
    """

    iface = "eth13"
    #define network interface
   
    ip = "192.168.0.21"
    #define default ip

    if (len(sys.argv) > 1):
    #check for any arguments

        ip = sys.argv[1]
        #override the default ip to target victim
   
    filter = "icmp and src host " + ip
    #build filter from ip
 
    sniff(iface=iface, prn=spoof_reply, filter=filter)
    #start sniffing
```

### Task 2
Important Notes: You must use protocol number 0x1 instead of protocol name `icmp`
``` C
#include <pcap.h>
#include <stdio.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header,
        const u_char *packet)
{
   printf("Got a packet\n");
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  const char filter_exp[] = "ip proto 0x1";
  bpf_u_int32 net;
  pcap_if_t *device_list;

  // Step 0: find existing device
  int result = pcap_findalldevs(&device_list, errbuf);
  if (result) {
    fprintf(stderr, "Error find devs\n");
  }
  printf("%s\n", device_list->name);
  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live(device_list->name, BUFSIZ, 0, 1000, errbuf); 
  if(!handle) {
    printf("%s\n", errbuf);
    return -1;
  }
  // Step 2: Compile filter_exp into BPF psuedo-code
  int err_result = pcap_compile(handle, &fp, filter_exp, 0, net);
  if(err_result == PCAP_ERROR) {
    pcap_perror(handle, "error:");
    return -1;
  }
  pcap_setfilter(handle, &fp);                                

  // // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);                    

  pcap_close(handle);   //Close the handle
  return 0;
}


```
* System call path Using `strace` will get the detailed path of system call. Rough idea will be 
	* read and open system libraries
	* socket
	* memory stuff
	* poll
* pcap_compile will fail without enough priviledge 
* 

