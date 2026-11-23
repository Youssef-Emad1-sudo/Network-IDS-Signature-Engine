from scapy.all import IP, TCP, wrpcap

packets = []

for i in range(6):
    packet = (
        IP(src="10.0.0.50", dst="10.0.0.20") /
        TCP(
            sport=45000 + i,
            dport=22,
            flags="S",
            seq=1000 + i
        )
    )
    packets.append(packet)

wrpcap("pcaps/malicious/14_ssh_repeated_attempts.pcap", packets)

print("SSH repeated attempts PCAP created successfully!")
