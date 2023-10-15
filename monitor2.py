import logging
from scapy.all import *

# Configure logging
logging.basicConfig(filename='dns_poisoning.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def dns_poisoning_monitor(pkt):
    """
    Monitor DNS packets and detect DNS poisoning attacks.
    """
    if pkt.haslayer(DNSRR):
        # Check if the DNS response is an authoritative response
        if pkt[DNS].ancount > 0 and pkt[DNS].an[0].type == 1:
            # Check if the DNS response IP address is different from the expected IP address
            if pkt[DNS].an[0].rdata != 'EXPECTED_IP_ADDRESS':
                logging.warning(f'DNS poisoning detected! Domain: {pkt[DNSQR].qname.decode()}')

# Sniff DNS packets and call dns_poisoning_monitor for each packet
sniff(filter='udp port 53', prn=dns_poisoning_monitor)

