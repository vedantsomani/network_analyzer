import scapy.all as scapy
from sklearn.ensemble import IsolationForest
import tkinter as tk
from tkinter import messagebox
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
import logging
import socket
import requests

logging.basicConfig(filename="network_analysis.log", level=logging.INFO)
model = IsolationForest()
captured_packets = []
packet_features = []
def get_device_owner(ip):
    try:
        response = requests.get(f"http://ipinfo.io/{ip}/json")
        data = response.json()
        return data.get('org', 'Unknown')
    except:
        return 'Unknown'
def get_communication_type(packet):
    if packet.haslayer(scapy.IP):
        if packet.haslayer(scapy.TCP) and packet.dport == 80:
            return 'HTTP (GET/POST)'
        elif packet.haslayer(scapy.UDP):
            return 'UDP Communication'
    return 'Unknown'

def packet_callback(packet):
    try:
        packet_size = len(packet)
        timestamp = packet.time
        protocol = packet.proto
        ip_src = packet[scapy.IP].src if packet.haslayer(scapy.IP) else 'Unknown'
        mac_src = packet.src if packet.haslayer(scapy.Ether) else 'Unknown'
        owner = get_device_owner(ip_src)
        comm_type = get_communication_type(packet)

        packet_features.append([packet_size, timestamp, protocol])
        captured_packets.append({'packet': packet, 'owner': owner, 'comm_type': comm_type, 'ip_src': ip_src, 'mac_src': mac_src})

        logging.info(f"Packet captured: {packet.summary()}, Source: {ip_src}, Owner: {owner}, Communication: {comm_type}")

        if len(packet_features) > 10: 
            model.fit(packet_features)
            predictions = model.predict(packet_features)
            
            if predictions[-1] == -1:  
                logging.warning(f"Anomaly detected: {packet.summary()}")

    except Exception as e:
        logging.error(f"Error processing packet: {e}")

def start_sniffing():
    interface = "Wi-Fi"
    scapy.sniff(iface=interface, prn=packet_callback, store=0)

def update_plot(frame):
    if captured_packets:
        sizes = [len(pkt['packet']) for pkt in captured_packets]
        timestamps = [pkt['packet'].time for pkt in captured_packets]
        ax.clear()
        ax.plot(timestamps, sizes, label="Packet Size")
        ax.set_title("Network Traffic")
        ax.set_xlabel("Time")
        ax.set_ylabel("Packet Size")
        ax.legend()
fig, ax = plt.subplots()
ani = FuncAnimation(fig, update_plot, interval=1000, cache_frame_data=False)

def start_gui():
    global owner_label, comm_label

    root = tk.Tk()
    root.title("Network Traffic Analyzer")

    status_label = tk.Label(root, text="Starting packet sniffing...", font=("Helvetica", 12))
    status_label.pack(pady=10)

    start_button = tk.Button(root, text="Start Sniffing", command=start_sniffing, font=("Helvetica", 12))
    start_button.pack(pady=20)

    stop_button = tk.Button(root, text="Stop Sniffing", command=root.quit, font=("Helvetica", 12))
    stop_button.pack(pady=20)

    owner_label = tk.Label(root, text="Owner: Unknown", font=("Helvetica", 12))
    owner_label.pack(pady=5)

    comm_label = tk.Label(root, text="Communication: Unknown", font=("Helvetica", 12))
    comm_label.pack(pady=5)

    root.mainloop()
    
import threading
thread = threading.Thread(target=start_gui)
thread.start()
start_sniffing()
plt.show()
