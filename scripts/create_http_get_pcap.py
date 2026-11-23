from scapy.all import Ether, IP, TCP, Raw, wrpcap

packets = []

client_ip = "10.0.0.10"
server_ip = "10.0.0.20"
client_port = 49000

# TCP handshake
packets.append(
    Ether() / IP(src=client_ip, dst=server_ip) /
    TCP(sport=client_port, dport=80, flags="S", seq=1000)
)

packets.append(
    Ether() / IP(src=server_ip, dst=client_ip) /
    TCP(sport=80, dport=client_port, flags="SA", seq=2000, ack=1001)
)

packets.append(
    Ether() / IP(src=client_ip, dst=server_ip) /
    TCP(sport=client_port, dport=80, flags="A", seq=1001, ack=2001)
)

# HTTP GET request
http_request = (
    "GET /index.html HTTP/1.1\r\n"
    "Host: example.test\r\n"
    "User-Agent: Mozilla/5.0\r\n"
    "\r\n"
)

packets.append(
    Ether() / IP(src=client_ip, dst=server_ip) /
    TCP(sport=client_port, dport=80, flags="PA",
        seq=1001, ack=2001) /
    Raw(load=http_request)
)

output_file = "pcaps/benign/02_normal_http_get.pcap"
wrpcap(output_file, packets)

print(f"HTTP GET PCAP created: {output_file}")
print(f"Total packets: {len(packets)}")
