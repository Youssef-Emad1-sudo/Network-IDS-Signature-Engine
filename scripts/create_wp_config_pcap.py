from scapy.all import IP, TCP, Raw, wrpcap

packets = []

src = "10.0.0.10"
dst = "10.0.0.20"
sport = 50010
dport = 80

# TCP handshake
packets.append(IP(src=src, dst=dst) /
               TCP(sport=sport, dport=dport, flags="S", seq=1000))

packets.append(IP(src=dst, dst=src) /
               TCP(sport=dport, dport=sport, flags="SA",
                   seq=2000, ack=1001))

packets.append(IP(src=src, dst=dst) /
               TCP(sport=sport, dport=dport, flags="A",
                   seq=1001, ack=2001))

# Suspicious HTTP GET request
request = (
    "GET /wp-config.php HTTP/1.1\r\n"
    "Host: test.local\r\n"
    "User-Agent: NIDS-Test\r\n"
    "Connection: close\r\n\r\n"
)

packets.append(
    IP(src=src, dst=dst) /
    TCP(sport=sport, dport=dport, flags="PA",
        seq=1001, ack=2001) /
    Raw(load=request)
)

wrpcap("pcaps/malicious/16_wp_config_access.pcap", packets)

print("WP Config test PCAP created successfully!")
