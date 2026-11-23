from scapy.all import Ether, IP, TCP, wrpcap

packets = []

for port in range(20, 30):
    packet = (
        Ether()
        / IP(src="10.0.0.10", dst="10.0.0.20")
        / TCP(
            sport=40000 + port,
            dport=port,
            flags="S",
            seq=1000 + port
        )
    )
    packets.append(packet)

output_file = "pcaps/malicious/03_tcp_port_scan.pcap"
wrpcap(output_file, packets)

print(f"Port scan PCAP created: {output_file}")
print(f"Total packets: {len(packets)}")
