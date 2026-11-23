from scapy.all import Ether, IP, TCP, wrpcap

packet = (
    Ether()
    / IP(src="10.0.0.10", dst="10.0.0.20")
    / TCP(
        sport=45000,
        dport=22,
        flags="S",
        seq=1000
    )
)

output_file = "pcaps/malicious/05_ssh_connection.pcap"

wrpcap(output_file, [packet])

print(f"SSH PCAP created successfully: {output_file}")
