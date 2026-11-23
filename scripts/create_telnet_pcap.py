from scapy.all import Ether, IP, TCP, wrpcap

packet = (
    Ether()
    / IP(src="10.0.0.10", dst="10.0.0.20")
    / TCP(
        sport=47000,
        dport=23,
        flags="S",
        seq=1000
    )
)

output_file = "pcaps/malicious/07_telnet_connection.pcap"

wrpcap(output_file, [packet])

print(f"Telnet PCAP created successfully: {output_file}")
