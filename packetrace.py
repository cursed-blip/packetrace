import tkinter as tk
from tkinter import scrolledtext
import scapy.all as scapy
import threading
import requests

def get_geolocation(ip):
    try:
        url = f'https://ipinfo.io/{ip}/json'
        response = requests.get(url)
        data = response.json()
        location = data.get('city', 'N/A') + ', ' + data.get('country', 'N/A')
        return location
    except Exception as e:
        return 'Geolocation Unavailable'

class PacketTrace:
    def __init__(self, root):
        self.root = root
        self.root.title("PacketTrace: Network Packet Capture & Analysis")
        self.root.geometry("1000x600")
        
        self.suspicious_ips = set()
        self.protocol_colors = {'TCP': 'red', 'UDP': 'blue', 'ICMP': 'green'}
        
        self.frame = tk.Frame(self.root)
        self.frame.pack(fill=tk.BOTH, expand=True)

        self.line_numbers_canvas = tk.Canvas(self.frame, width=40, bg='#f0f0f0', highlightthickness=0)
        self.line_numbers_canvas.pack(side=tk.LEFT, fill=tk.Y)

        self.packet_output = scrolledtext.ScrolledText(self.frame, wrap=tk.WORD, undo=True, font=("Consolas", 12))
        self.packet_output.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.suspicious_panel = tk.LabelFrame(self.root, text="Suspicious IPs", font=("Consolas", 12))
        self.suspicious_panel.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.suspicious_listbox = tk.Listbox(self.suspicious_panel, font=("Consolas", 12), height=10, selectmode=tk.SINGLE)
        self.suspicious_listbox.pack(fill=tk.BOTH, expand=True)

        self.sniff_thread = threading.Thread(target=self.capture_packets)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

    def capture_packets(self):
        scapy.sniff(prn=self.packet_handler, store=0, filter="ip", count=0)

    def packet_handler(self, packet):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        protocol = packet.proto

        if protocol == 6:
            protocol_name = "TCP"
            color = self.protocol_colors.get('TCP', 'black')
        elif protocol == 17:
            protocol_name = "UDP"
            color = self.protocol_colors.get('UDP', 'black')
        elif protocol == 1:
            protocol_name = "ICMP"
            color = self.protocol_colors.get('ICMP', 'black')
        else:
            protocol_name = "Other"
            color = 'black'
        
        self.packet_output.insert(tk.END, f"Src: {ip_src} -> Dst: {ip_dst} [{protocol_name}]\n", 'color')

        if self.is_suspicious(ip_src):
            self.add_suspicious_ip(ip_src)
        if self.is_suspicious(ip_dst):
            self.add_suspicious_ip(ip_dst)

        self.packet_output.see(tk.END)

    def is_suspicious(self, ip):
        if ip.startswith('192.168'):
            return True
        return False

    def add_suspicious_ip(self, ip):
        if ip not in self.suspicious_ips:
            self.suspicious_ips.add(ip)
            location = get_geolocation(ip)
            self.suspicious_listbox.insert(tk.END, f"IP: {ip} | Location: {location}")

root = tk.Tk()
packet_trace = PacketTrace(root)
root.mainloop()
