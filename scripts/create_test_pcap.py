from scapy.all import Ether, IP, TCP, Raw, wrpcap

packets = []

# TCP handshake
packets.append(
    Ether()/IP(src="10.0.0.10", dst="10.0.0.20")/
    TCP(sport=12345, dport=80, flags="S", seq=1000)
)

packets.append(
    Ether()/IP(src="10.0.0.20", dst="10.0.0.10")/
    TCP(sport=80, dport=12345, flags="SA", seq=2000, ack=1001)
)

packets.append(
    Ether()/IP(src="10.0.0.10", dst="10.0.0.20")/
    TCP(sport=12345, dport=80, flags="A", seq=1001, ack=2001)
)

# HTTP request with our test User-Agent
http_request = (
    "GET / HTTP/1.1\r\n"
    "Host: test.local\r\n"
    "User-Agent: NIDS-Test-Agent\r\n"
    "Connection: close\r\n\r\n"
)

packets.append(
    Ether()/IP(src="10.0.0.10", dst="10.0.0.20")/
    TCP(sport=12345, dport=80, flags="PA",
        seq=1001, ack=2001)/
    Raw(load=http_request.encode())
)

wrpcap("pcaps/malicious/01_suspicious_user_agent.pcap", packets)

print("PCAP created successfully!")
print("Packets:", len(packets))
