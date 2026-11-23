from scapy.all import IP, UDP, DNS, DNSQR, Ether, wrpcap

packet = (
    Ether() /
    IP(src="10.0.0.10", dst="8.8.8.8") /
    UDP(sport=53000, dport=53) /
    DNS(
        rd=1,
        qd=DNSQR(qname="suspicious-test.xyz")
    )
)

wrpcap(
    "pcaps/malicious/12_dns_suspicious_xyz.pcap",
    [packet]
)

print("PCAP created successfully!")
print("DNS Query: suspicious-test.xyz")
