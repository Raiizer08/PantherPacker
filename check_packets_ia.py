import sys
import pandas as pd
from scapy.all import sniff, IP
import argparse
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QLabel, QLineEdit

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

class PacketSnifferApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Packet Sniffer')
        self.setGeometry(100, 100, 400, 200)
        
        layout = QVBoxLayout()
        
        self.startButton = QPushButton('Start Sniffing', self)
        self.startButton.clicked.connect(self.start_sniffing)
        
        self.saveButton = QPushButton('Save Data', self)
        self.saveButton.clicked.connect(self.save_data)
        
        self.packetCountLabel = QLabel('Number of packets: 0', self)
        
        self.fileLabel = QLabel('Enter filename:', self)
        self.filenameLineEdit = QLineEdit('packets.csv', self)
        
        layout.addWidget(self.startButton)
        layout.addWidget(self.saveButton)
        layout.addWidget(self.packetCountLabel)
        layout.addWidget(self.fileLabel)
        layout.addWidget(self.filenameLineEdit)
        
        centralWidget = QWidget(self)
        centralWidget.setLayout(layout)
        self.setCentralWidget(centralWidget)

    def start_sniffing(self):
        sniff(prn=packet_callback, count=100)  # You can adjust the count or make it dynamic
        self.packetCountLabel.setText(f'Number of packets: {len(packet_data)}')

    def save_data(self):
        filename = self.filenameLineEdit.text()
        df = pd.DataFrame(packet_data)
        df.to_csv(filename, index=False)
        print(f"Paquets capturés et sauvegardés dans '{filename}'")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = PacketSnifferApp()
    ex.show()
    sys.exit(app.exec_())
