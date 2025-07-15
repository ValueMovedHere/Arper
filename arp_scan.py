import argparse
from sys import argv
from scapy.all import ARP, Ether, srp

def arp_scan(ip, timeout=2):
    '''
    :param ip: IPv4 address to scan
    :param timeout: timeout for scan
    :return: MAC address of target host, return None if no respond
    '''
    # ARP request
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    # Send the request and wait for respond
    answered, _ = srp(arp_request_broadcast, timeout=timeout, verbose=False)
    
    for _, rcv in answered:
        if rcv.getlayer(ARP).psrc == ip:  # Check source address
            return rcv.hwsrc  # return MAC address

    # Return None if no respond
    return None

if __name__ == "__main__":
    # parse = argparse.ArgumentParser(description='')
    if len(argv) < 2:
        raise SystemExit('Argument <target_IPv4> required')
    target_ip = argv[1]
    mac_address = arp_scan(target_ip)
    if mac_address:
        print(f"Host {target_ip} is active, MAC address: {mac_address}")
    else:
        print(f"Host {target_ip} did not respond to ARP request.")