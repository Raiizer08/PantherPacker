# This file is the PatnherPacker GUI, it uses packet_sniffer code to sniff
import sys
from PyQt5.QtWidgets import (
    QApplication, QProgressBar, QWidget, QPushButton, QVBoxLayout, QLabel,
    QMenuBar, QAction, QFileDialog, QMessageBox, QComboBox, QTableWidget, QTableWidgetItem
)
from PyQt5.QtGui import QIcon, QDesktopServices, QColor
from PyQt5.QtCore import QFile, QTextStream, QUrl, QTimer, QThread, pyqtSignal
import psutil
from scapy.all import sniff, IP, TCP, UDP, Raw
import xml.etree.ElementTree as ET
import xml.dom.minidom
import datetime

class XMLPacketHandler:
    def __init__(self, filename):
        self.filename = filename
        self.root = ET.Element("packet_capture")
        self.tree = ET.ElementTree(self.root)

    def packet_callback(self, packet):
        if IP in packet:
            packet_elem = ET.SubElement(self.root, "packet")
            ET.SubElement(packet_elem, "timestamp").text = str(datetime.datetime.now())
            ET.SubElement(packet_elem, "source_ip").text = packet[IP].src
            ET.SubElement(packet_elem, "destination_ip").text = packet[IP].dst
            
            if TCP in packet:
                ET.SubElement(packet_elem, "protocol").text = "TCP"
                ET.SubElement(packet_elem, "source_port").text = str(packet[TCP].sport)
                ET.SubElement(packet_elem, "destination_port").text = str(packet[TCP].dport)
            elif UDP in packet:
                ET.SubElement(packet_elem, "protocol").text = "UDP"
                ET.SubElement(packet_elem, "source_port").text = str(packet[UDP].sport)
                ET.SubElement(packet_elem, "destination_port").text = str(packet[UDP].dport)
            elif packet.haslayer(Raw) and b'HTTP' in packet[Raw].load:
                ET.SubElement(packet_elem, "protocol").text = "HTTP"
            if TCP in packet:
                ET.SubElement(packet_elem, "source_port").text = str(packet[TCP].sport)
                ET.SubElement(packet_elem, "destination_port").text = str(packet[TCP].dport)

            else:
                ET.SubElement(packet_elem, "protocol").text = "Other"

            ET.SubElement(packet_elem, "length").text = str(len(packet))

    def save_xml(self, filename=None):
        if filename is None:
            filename = self.filename
            filename = self.filename
        xml_str = ET.tostring(self.root, encoding="unicode")
        dom = xml.dom.minidom.parseString(xml_str)
        pretty_xml = dom.toprettyxml(indent="  ")
        
        with open(filename, "w") as f:
            f.write(pretty_xml)

    def convert_to_html(self, html_filename):
        xslt = ET.parse("packet_to_html.xslt")
        transform = ET.XSLT(xslt)
        
        html_tree = transform(self.tree)
        
        with open(html_filename, "wb") as f:
            f.write(ET.tostring(html_tree, pretty_print=True))

class SnifferThread(QThread):
    packet_captured = pyqtSignal(str, str, int, int, str)

    def __init__(self, interface, xml_handler, parent=None):
        super().__init__(parent)
        self.interface = interface
        self.xml_handler = xml_handler
        self.sniffing = True

    def run(self):
        try:
            sniff(iface=self.interface, prn=self.packet_callback, stop_filter=self.should_stop)
        except Exception as e:
            self.packet_captured.emit('Error', str(e), 0, 0, 'Error')
    
    def packet_callback(self, packet):
        if not self.sniffing:
            return
        
        if IP in packet:
            protocol = packet[IP].proto
            if protocol == 6:
                protocol_name = 'TCP'
            elif protocol == 17:
                protocol_name = 'UDP'
            elif protocol == 1:
                protocol_name = 'ICMP'
            else:
                protocol_name = 'OTHER'

            packet_info = {
                'Source IP': packet[IP].src,
                'Destination IP': packet[IP].dst,
                'Source Port': packet.sport if packet.haslayer(TCP) or packet.haslayer(UDP) else None,
                'Destination Port': packet.dport if packet.haslayer(TCP) or packet.haslayer(UDP) else None,
                'Protocol': protocol_name,
                'Length': len(packet)
            }

            self.xml_handler.packet_callback(packet)
            self.packet_captured.emit(
                packet_info['Source IP'],
                packet_info['Destination IP'],
                packet_info['Source Port'],
                packet_info['Destination Port'],
                packet_info['Protocol'],
            )

    def should_stop(self, packet):
        return not self.sniffing
    
    def stop_sniffing(self):
        self.sniffing = False

class MyApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("PacketWhisper")
        self.setGeometry(100, 100, 800, 600)
        self.loadStyleSheet('chill_theme.css')
        self.createMenuBar()
        self.interface_combo = QComboBox(self)
        self.populate_interface_combo()

        self.label = QLabel('Results of the capture : ', self)
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.hide()
        
        self.start_button = QPushButton('Make the panther sniff', self)
        self.start_button.clicked.connect(self.on_button_click)

        self.stop_button = QPushButton('Stop The Panther')
        self.stop_button.clicked.connect(self.on_stop_button_click)

        self.table = QTableWidget(self)
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(['Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Protocol'])

        layout = QVBoxLayout()
        layout.addWidget(self.menuBar)
        layout.addWidget(self.label)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.interface_combo)
        layout.addWidget(self.start_button)
        layout.addWidget(self.stop_button)
        layout.addWidget(self.table)
        self.setLayout(layout)

        self.apply_theme('dark_theme.css', True)

        self.xml_handler = XMLPacketHandler("packet_capture.xml")

    def on_stop_button_click(self):
        if hasattr(self, 'sniffer_thread') and self.sniffer_thread.isRunning():
            print("Stopping sniffer thread...")
            self.sniffer_thread.stop_sniffing()
            self.sniffer_thread.wait()
            self.label.setText("Sniffer arrêté")
            self.progress_bar.setValue(100)
            self.timer.stop()
            self.ask_save_results()
        else:
            print("No sniffing thread is running.")
            self.label.setText("Aucun sniffing en cours.")

    def ask_save_results(self):
        reply = QMessageBox.question(self, 'Save Results', 
                                     "Do you want to save the sniffing results?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        
        if reply == QMessageBox.Yes:
            self.save_results()

    def save_results(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getSaveFileName(self, "Save Sniffing Results", "", 
                                                  "XML Files (*.xml);;All Files (*)", options=options)
        if fileName:
            if not fileName.endswith('.xml'):
                fileName += '.xml'
            self.xml_handler.save_xml(fileName)
            QMessageBox.information(self, "Save Successful", f"Results saved to {fileName}")

    def loadStyleSheet(self, styleSheetFile):
        styleFile = QFile(styleSheetFile)
        if styleFile.open(QFile.ReadOnly | QFile.Text):
            stream = QTextStream(styleFile)
            stylesheet = stream.readAll()
            self.setStyleSheet(stylesheet)
            styleFile.close()

    def populate_interface_combo(self):
        interfaces = self.get_interface_names()
        self.interface_combo.addItems(interfaces)

    def get_interface_names(self):
        interface_names = psutil.net_if_addrs()
        return list(interface_names.keys())

    def createMenuBar(self):
        self.menuBar = QMenuBar(self)
        fileMenu = self.menuBar.addMenu('File')
        settingsMenu = self.menuBar.addMenu('Settings')
        githubMenu = self.menuBar.addMenu('Github')

        openFileAction = QAction('Open Workspace From File', self)
        openFileAction.triggered.connect(self.open_file_dialog)
        fileMenu.addAction(openFileAction)

        openFolderAction = QAction('Open Folder', self)
        openFolderAction.triggered.connect(self.open_folder_dialog)
        fileMenu.addAction(openFolderAction)

        appearanceMenu = settingsMenu.addMenu('Appearance')

        darkThemeAction = QAction('Dark Theme', self)
        darkThemeAction.triggered.connect(lambda: self.apply_theme('dark_theme.css', True))
        appearanceMenu.addAction(darkThemeAction)

        hackerThemeAction = QAction('Hacker Theme', self)
        hackerThemeAction.triggered.connect(lambda: self.apply_theme('hacker_theme.css', False))
        appearanceMenu.addAction(hackerThemeAction)

        lightThemeAction = QAction('Light Theme', self)
        lightThemeAction.triggered.connect(lambda: self.apply_theme('light_theme.css', False))
        appearanceMenu.addAction(lightThemeAction)

        chillThemeAction = QAction('Chill Theme', self)
        chillThemeAction.triggered.connect(lambda: self.apply_theme('chill_theme.css', False))      
        appearanceMenu.addAction(chillThemeAction)

        pinkThemeAction = QAction('Pink Theme', self)
        pinkThemeAction.triggered.connect(lambda: self.apply_theme('pink_theme.css', False))
        appearanceMenu.addAction(pinkThemeAction)

        outputFormatMenu = settingsMenu.addMenu('Output Format')

        csvFormatAction = QAction('CSV', self)
        csvFormatAction.triggered.connect(lambda: self.on_output_format_selected('CSV'))
        outputFormatMenu.addAction(csvFormatAction)

        jsonFormatAction = QAction('JSON', self)
        jsonFormatAction.triggered.connect(lambda: self.on_output_format_selected('JSON'))
        outputFormatMenu.addAction(jsonFormatAction)

        xmlFormatAction = QAction('XML', self)
        xmlFormatAction.triggered.connect(lambda: self.on_output_format_selected('XML'))
        outputFormatMenu.addAction(xmlFormatAction)

        githubAction = QAction('My GitHub', self)
        githubAction.triggered.connect(self.open_github)
        githubMenu.addAction(githubAction)

    def apply_theme(self, styleSheetFile, is_dark_theme):
        self.loadStyleSheet(styleSheetFile)
        self.update_table_colors(is_dark_theme)

    def open_file_dialog(self):
        fileName, _ = QFileDialog.getOpenFileName(self, 'Open File', '', 'All Files (*)')
        if fileName:
            self.label.setText(f"Selected file: {fileName}")

    def open_folder_dialog(self):
        folderName = QFileDialog.getExistingDirectory(self, 'Open Folder', '', QFileDialog.ShowDirsOnly)
        if folderName:
            self.label.setText(f"Selected folder: {folderName}")

    def on_output_format_selected(self, format_name):
        self.label.setText(f"Output format selected: {format_name}")

    def open_github(self):
        url = QUrl('https://github.com/Raiizer08')
        QDesktopServices.openUrl(url)

    def on_button_click(self):
        self.label.setText("Sniffer Started")
        self.progress_bar.setValue(0)
        self.progress_bar.show()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_progress)
        self.timer.start(100)
        self.start_sniffer_thread()

    def start_sniffer_thread(self):
        selected_interface = self.interface_combo.currentText()
        if selected_interface:
            self.sniffer_thread = SnifferThread(selected_interface, self.xml_handler)
            self.sniffer_thread.packet_captured.connect(self.add_packet_to_table)
            self.sniffer_thread.finished.connect(self.on_sniffer_finished)
            self.sniffer_thread.start()
        else:
            self.label.setText("Aucune Interface sélectionnée")

    def on_sniffer_finished(self):
        self.timer.stop()
        self.progress_bar.setValue(100)
        self.want_to_save_message

    def add_packet_to_table(self, src_ip, dst_ip, src_port, dst_port, protocol):
        row_position = self.table.rowCount()
        self.table.insertRow(row_position)

        self.table.setItem(row_position, 0, QTableWidgetItem(src_ip))
        self.table.setItem(row_position, 1, QTableWidgetItem(dst_ip))
        self.table.setItem(row_position, 2, QTableWidgetItem(str(src_port)))
        self.table.setItem(row_position, 3, QTableWidgetItem(str(dst_port)))

        protocol_item = QTableWidgetItem(protocol)
        if protocol == 'TCP':
            protocol_item.setForeground(QColor(0, 255, 0))  # Green for TCP
        elif protocol == 'UDP':
            protocol_item.setForeground(QColor(0, 0, 255))  # Blue for UDP
        else:
            protocol_item.setForeground(QColor(255, 255, 0))  # Yellow for others
        self.table.setItem(row_position, 4, protocol_item)

    def update_table_colors(self, is_dark_theme):
        row_count = self.table.rowCount()
        for row in range(row_count):
            for column in range(self.table.columnCount()):
                item = self.table.item(row, column)
                if item:
                    if is_dark_theme:
                        item.setForeground(QColor(255, 255, 255))  
                        item.setBackground(QColor(43, 43, 43))  
                    else:
                        item.setForeground(QColor(0, 0, 0))  
                        item.setBackground(QColor(255, 255, 255))  

        # Update headers
        for col in range(self.table.columnCount()):
            item = self.table.horizontalHeaderItem(col)
            if item:
                if is_dark_theme:
                    item.setForeground(QColor(0, 0, 0))  
                    item.setBackground(QColor(43, 43, 43))  
                else:
                    item.setForeground(QColor(0, 0, 0))

    def update_progress(self):
        current_value = self.progress_bar.value()
        if current_value < 100:
            self.progress_bar.setValue(current_value + 1)
        else:
            self.timer.stop()
            self.on_stop_button_click()

    def want_to_save_message(self):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Alert)
        msg.setText("Want to save that ?")
        msg.setInformativeText("The Sniffing is finish, want to save the capture ?")
        msg.setWindowTitle("Reminder")
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()

    def show_completion_message(self):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setText("Sniffing Over !")
        msg.setInformativeText("The Sniffing is over")
        msg.setWindowTitle("Information")
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()

    def closeEvent(self, event):
        if hasattr(self, 'timer'):
            self.timer.stop()
        event.accept()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    myApp = MyApp()
    myApp.show()
    sys.exit(app.exec_())
