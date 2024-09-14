# This file defines functions for packet capture and data saving

import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
import json
import xml.etree.ElementTree as ET
from termcolor import colored

packet_data = []

def packet_callback(packet):
    if IP in packet:
        protocol = packet[IP].proto
        if protocol == 6:
            protocol_name = 'TCP'
        elif protocol == 17:
            protocol_name = 'UDP'
        elif protocol == 1:
            protocol_name = 'ICMP'
        elif protocol == 80:
            protocol_name = 'HTTP'
        elif protocol == 0x0806:
            protocol_name = 'ARP'
        else:
            protocol_name = 'OTHER'

        packet_info = {
            'Source IP': packet[IP].src,
            'Ip Destination': packet[IP].dst,
            'Source Port': packet.sport if packet.haslayer(TCP) or packet.haslayer(UDP) else None,
            'Destination Port': packet.dport if packet.haslayer(TCP) or packet.haslayer(UDP) else None,
            'Protocol': protocol_name,
            'Length': len(packet)
        }

        packet_data.append(packet_info)

        color = {
            'TCP': 'green',
            'UDP': 'blue',
            'ICMP': 'yellow',
            'OTHER': 'red'
        }.get(protocol_name, 'red')

        print(colored(packet_info, color))

def start_sniffing(interface):
    try:
        sniff(iface=interface, prn=packet_callback)
    except Exception as e:
        print(f"Erreur: {e}")

def save_data(filename, data, format_type='CSV'):
    df = pd.DataFrame(data)
    if format_type == 'CSV':
        df.to_csv(filename, index=False)
    elif format_type == 'JSON':
        df.to_json(filename, orient='records', lines=True)
    elif format_type == 'XML':
        root = ET.Element("root")
        for item in data:
            packet_elem = ET.SubElement(root, "packet")
            for key, value in item.items():
                child = ET.SubElement(packet_elem, key)
                child.text = str(value)
        tree = ET.ElementTree(root)
        tree.write(filename)
    else:
        print(f"Format {format_type} non supporté.")
