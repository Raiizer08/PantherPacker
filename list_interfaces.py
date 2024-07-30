from scapy.all import sniff, get_if_list

def find_interface():
    interfaces = get_if_list()
    print("Interfaces disponibles :", interfaces)
    # Essaye de trouver une interface qui semble être une carte réseau physique
    # Exemple: retourne la première interface non 'loopback'
    for iface in interfaces:
        if 'loopback' not in iface.lower():
            return iface
    return None

def start_sniffing(interface, count):
    try:
        sniff(iface=interface, prn=lambda x: x.summary(), count=count)
    except Exception as e:
        print(f"Erreur: {e}")

if __name__ == "__main__":
    interface = find_interface()
    if interface:
        print(f"Utilisation de l'interface : {interface}")
        start_sniffing(interface=interface, count=10)
    else:
        print("Aucune interface réseau valide trouvée.")
