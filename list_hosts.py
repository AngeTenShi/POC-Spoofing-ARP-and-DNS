from scapy.all import * 
import time
import argparse
import os 

file = open("host.txt", "w")
def get_hosts():
	print("[+] Checking for possible hosts ...\n")
	for ip in range(0,256):
		packet = IP(dst="192.168.1." + str(ip), ttl=20) / ICMP()
		reply= sr1(packet, timeout=2,verbose = False)
		#print("Checking " + "192.168.1."+ str(ip))
		if not(reply is None):
			print("[*] Host discovered : " + str(reply.src))
			file.write(str(reply.src) + "\n")
	print(os.system("arp -a"))
	file.write(os.system("arp -a")) 
try :
	get_hosts()
except KeyboardInterrupt:
	print("Stopping Enumerating hosts")
	file.write(os.system("arp -a")) 


"""
import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)
    
    client_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc }
        client_list.append(client_dict)
    return client_list

print(scan("192.168.1.1/24"))
"""
