import time
from scapy.all import *
import requests
from bs4 import BeautifulSoup

# Defining the URL to test
url = input("input the web app url: ")

# Defining the filename to save the analyzed packets
output_filename = "http_packets.txt"

# Setting the start time
start_time = time.time()

# Initializing a list to store analyzed packets
analyzed_packets = []

print("starting to analyze and capture packets")

# Defining a function to analyze packets
def packet_handler(packet):
    global analyzed_packets

    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        
        # Checking for SQL injection
        if "SELECT" in payload.upper() or "INSERT" in payload.upper() or "UPDATE" in payload.upper():
            analyzed_packets.append((time.time(), "SQL Injection detected:", payload))
        
        # Checking for XSS
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        if payload in soup.get_text():
            analyzed_packets.append((time.time(), "XSS detected:", payload))

# Starting packet capture
sniff(filter="tcp port 443 or 80", prn=packet_handler, store=0, timeout=60)

# Checking if any vulnerabilities were found
if not analyzed_packets:
    print("No SQL Injection or XSS vulnerability found.")

# Saving analyzed packets to a local file
with open(output_filename, "w") as output_file:
    for timestamp, vulnerability, payload in analyzed_packets:
        output_file.write(f"Timestamp: {timestamp}, {vulnerability} Payload: {payload}\n")

print(f"Analyzed packets saved to {output_filename}")

# Checking if 1 minute has passed
elapsed_time = time.time() - start_time
if elapsed_time < 60:
    print("Program stopped before 1 minute.")
else:
    print("web app testing  completed.")

