from scapy.all import Ether, IP, TCP, wrpcap

packet = (
    Ether()
    / IP(src="10.0.0.10", dst="10.0.0.20")
    / TCP(
        sport=46000,
        dport=21,
        flags="S",
        seq=1000
    )
)

output_file = "pcaps/malicious/06_ftp_connection.pcap"

wrpcap(output_file, [packet])

print(f"FTP PCAP created successfully: {output_file}")
