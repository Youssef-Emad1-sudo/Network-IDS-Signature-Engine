from scapy.all import Ether, IP, TCP, Raw, wrpcap

packets = []

client = "192.168.1.10"
server = "192.168.1.20"
sport = 12345
dport = 21

# TCP handshake
packets.append(Ether()/IP(src=client, dst=server)/
               TCP(sport=sport, dport=dport, flags="S", seq=1000))

packets.append(Ether()/IP(src=server, dst=client)/
               TCP(sport=dport, dport=sport, flags="SA", seq=2000, ack=1001))

packets.append(Ether()/IP(src=client, dst=server)/
               TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=2001))

# FTP commands
packets.append(Ether()/IP(src=client, dst=server)/
               TCP(sport=sport, dport=dport, flags="PA",
                   seq=1001, ack=2001)/
               Raw(load=b"USER test\r\n"))

packets.append(Ether()/IP(src=client, dst=server)/
               TCP(sport=sport, dport=dport, flags="PA",
                   seq=1012, ack=2001)/
               Raw(load=b"PASS test123\r\n"))

wrpcap("pcaps/malicious/18_ftp_pass.pcap", packets)

print("FTP PASS test PCAP created successfully!")
