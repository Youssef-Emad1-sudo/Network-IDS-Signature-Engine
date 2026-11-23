from scapy.all import IP, TCP, wrpcap

packets = []

for i in range(3):
    packet = (
        IP(src="10.0.0.50", dst="10.0.0.20") /
        TCP(
            sport=46000 + i,
            dport=445,
            flags="S",
            seq=2000 + i
        )
    )
    packets.append(packet)

wrpcap("pcaps/malicious/15_smb_connection.pcap", packets)

print("SMB PCAP created successfully!")
