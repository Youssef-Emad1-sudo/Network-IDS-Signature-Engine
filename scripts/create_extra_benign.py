from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, ICMP, wrpcap

BASE = "pcaps/benign/"

# 1. Normal DNS query
dns_packet = (
    Ether() /
    IP(src="10.0.0.10", dst="8.8.8.8") /
    UDP(sport=53000, dport=53) /
    DNS(rd=1, qd=DNSQR(qname="example.com"))
)
wrpcap(BASE + "03_normal_dns.pcap", [dns_packet])

# 2. Normal HTTPS connection attempt (TCP handshake)
https_packets = [
    Ether()/IP(src="10.0.0.10", dst="10.0.0.20")/
    TCP(sport=50001, dport=443, flags="S", seq=1000),

    Ether()/IP(src="10.0.0.20", dst="10.0.0.10")/
    TCP(sport=443, dport=50001, flags="SA", seq=2000, ack=1001),

    Ether()/IP(src="10.0.0.10", dst="10.0.0.20")/
    TCP(sport=50001, dport=443, flags="A", seq=1001, ack=2001)
]
wrpcap(BASE + "04_normal_https_handshake.pcap", https_packets)

# 3. Normal ICMP ping
ping_packet = (
    Ether() /
    IP(src="10.0.0.10", dst="10.0.0.20") /
    ICMP()
)
wrpcap(BASE + "05_normal_ping.pcap", [ping_packet])

# 4. Normal FTP connection attempt (TCP SYN only)
ftp_packet = (
    Ether() /
    IP(src="10.0.0.10", dst="10.0.0.20") /
    TCP(sport=50002, dport=21, flags="S", seq=3000)
)
wrpcap(BASE + "06_normal_ftp_connection.pcap", [ftp_packet])

print("Four additional benign PCAP files created successfully!")
