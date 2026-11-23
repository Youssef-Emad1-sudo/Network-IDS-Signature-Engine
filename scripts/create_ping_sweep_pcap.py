from scapy.all import IP, ICMP, Ether, wrpcap

packets = []

source_ip = "10.0.0.10"

target_ips = [
    "10.0.0.20",
    "10.0.0.21",
    "10.0.0.22",
    "10.0.0.23",
    "10.0.0.24"
]

for target in target_ips:
    packet = (
        Ether() /
        IP(src=source_ip, dst=target) /
        ICMP(type=8)
    )
    packets.append(packet)

wrpcap(
    "pcaps/malicious/11_icmp_ping_sweep.pcap",
    packets
)

print("PCAP created successfully!")
print("Total ICMP requests:", len(packets))
