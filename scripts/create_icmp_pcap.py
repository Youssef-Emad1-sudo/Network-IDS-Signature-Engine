from scapy.all import Ether, IP, ICMP, wrpcap

packet = (
    Ether()
    / IP(src="10.0.0.10", dst="10.0.0.20")
    / ICMP(type=8)
)

output_file = "pcaps/malicious/04_icmp_echo.pcap"

wrpcap(output_file, [packet])

print(f"ICMP PCAP created successfully: {output_file}")
