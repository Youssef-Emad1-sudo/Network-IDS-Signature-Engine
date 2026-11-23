from scapy.all import Ether, IP, TCP, Raw, wrpcap

packets = []

# TCP handshake
packets.append(
    Ether()/IP(src="10.0.0.10", dst="10.0.0.20")/
    TCP(sport=12346, dport=80, flags="S", seq=3000)
)

packets.append(
    Ether()/IP(src="10.0.0.20", dst="10.0.0.10")/
    TCP(sport=80, dport=12346, flags="SA", seq=4000, ack=3001)
)

packets.append(
    Ether()/IP(src="10.0.0.10", dst="10.0.0.20")/
    TCP(sport=12346, dport=80, flags="A", seq=3001, ack=4001)
)

# Normal HTTP request
http_request = (
    "GET /home HTTP/1.1\r\n"
    "Host: test.local\r\n"
    "User-Agent: Mozilla/5.0\r\n"
    "Connection: close\r\n\r\n"
)

packets.append(
    Ether()/IP(src="10.0.0.10", dst="10.0.0.20")/
    TCP(sport=12346, dport=80, flags="PA",
        seq=3001, ack=4001)/
    Raw(load=http_request.encode())
)

wrpcap("pcaps/benign/01_normal_http.pcap", packets)

print("Benign PCAP created successfully!")
print("Packets:", len(packets))

