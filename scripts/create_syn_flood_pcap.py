from scapy.all import Ether, IP, TCP, wrpcap

packets = []

source_ip = "10.0.0.10"
target_ip = "10.0.0.20"

for i in range(25):
    packet = (
        Ether() /
        IP(src=source_ip, dst=target_ip) /
        TCP(
            sport=40000 + i,
            dport=80,
            flags="S",
            seq=1000 + i
        )
    )
    packets.append(packet)

wrpcap(
    "pcaps/malicious/13_tcp_syn_flood.pcap",
    packets
)

print("PCAP created successfully!")
print("Total SYN packets:", len(packets))
