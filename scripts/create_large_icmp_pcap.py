from scapy.all import IP, ICMP, Raw, wrpcap

packet = (
    IP(src="10.0.0.10", dst="10.0.0.20") /
    ICMP(type=8) /
    Raw(load=b"A" * 1200)
)

wrpcap("pcaps/malicious/17_large_icmp.pcap", [packet])

print("Large ICMP PCAP created successfully!")
