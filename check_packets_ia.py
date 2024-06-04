import pandas as pd
from scapy.all import sniff, IP
import argparse

# initialise une liste vide packet_data qui sera utilisée pour stocker les informations sur chaque paquet capturé
packet_data = []

def packet_callback(packet):
    if IP in packet and packet[IP].src == '192.168.195.118':
        packet_info = {
            'src_ip': packet[IP].src,  # IP source du paquet
            'dst_ip': packet[IP].dst,  # IP de destination du paquet
            'src_port': packet.sport if packet.haslayer('TCP') or packet.haslayer('UDP') else None,  # port source du paquet
            'dst_port': packet.dport if packet.haslayer('TCP') or packet.haslayer('UDP') else None,  # port de destination du paquet
            'protocol': packet[IP].protocol,  # protocole du paquet
            'length': len(packet)  # longueur totale du paquet
        }
        packet_data.append(packet_info)  # ajoute le dictionnaire packet_info à la liste packet_data

def main():
    parser = argparse.ArgumentParser(description="Capture network packets and save them to a JSON file.")
    # Removed custom -h, --help to avoid conflict with the default help behavior
    parser.add_argument('-c', '--count', type=int, default=100, help='Number of packets to capture')
    parser.add_argument('-f', '--file', type=str, default='packets.json', help='Output file name')
    args = parser.parse_args()
    
    # capture le nombre de paquets demandés
    sniff(prn=packet_callback, count=args.count)
    # convertir en dataframe et sauvegarder en json
    df = pd.DataFrame(packet_data)
    df.to_csv(args.file, index=False)
    print(f"Paquets capturés et sauvegardés dans '{args.file}'")