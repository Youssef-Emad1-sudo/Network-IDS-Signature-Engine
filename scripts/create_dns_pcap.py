from scapy.all import Ether, IP, UDP, DNS, DNSQR, wrpcap

# Create a DNS query packet
packet = (
    Ether()
    / IP(src="10.0.0.10", dst="10.0.0.53")
    / UDP(sport=53000, dport=53)
    / DNS(
        rd=1,
        qd=DNSQR(qname="malware-test.example")
    )
)

# Save the packet as a PCAP file
output_file = "pcaps/malicious/02_suspicious_dns.pcap"

wrpcap(output_file, [packet])

print(f"DNS PCAP created successfully: {output_file}")
