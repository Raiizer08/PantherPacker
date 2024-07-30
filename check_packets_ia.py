import sys
from scapy.all import sniff, IP
import pandas as pd

packet_data = []

def packet_callback(packet):
    if IP in packet and packet[IP].src == '192.168.195.118':
        packet_info = {
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'src_port': packet.sport if packet.haslayer('TCP') or packet.haslayer('UDP') else None,
            'dst_port': packet.dport if packet.haslayer('TCP') or packet.haslayer('UDP') else None,
            'protocol': packet[IP].protocol,
            'length': len(packet)
        }
        packet_data.append(packet_info)

def start_sniffing():
    sniff(prn=packet_callback, count=100)  # You can adjust the count or make it dynamic
    print(f'Number of packets: {len(packet_data)}')

def save_data(filename='packets.csv'):
    df = pd.DataFrame(packet_data)
    df.to_csv(filename, index=False)
    print(f"Paquets capturés et sauvegardés dans '{filename}'")

if __name__ == '__main__':
    start_sniffing()
    save_data()