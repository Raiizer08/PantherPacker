from scapy.all import get_if_list, get_if_raw_hwaddr, conf

def print_interface_details():
    interfaces = get_if_list()
    print("Interfaces réseau disponibles :")
    for iface in interfaces:
        try:
            # Affiche le nom de l'interface et son adresse MAC
            hw_addr = get_if_raw_hwaddr(iface)
            print(f"Interface: {iface}, Adresse MAC: {hw_addr}")
        except Exception as e:
            print(f"Erreur pour l'interface {iface}: {str(e)}")

if __name__ == "__main__":
    print_interface_details()
