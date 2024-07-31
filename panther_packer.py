# This file is the PatnherPacker GUI, it uses packet_sniffer code to sniff

import sys
from PyQt5.QtWidgets import (
    QApplication, QProgressBar, QWidget, QPushButton, QVBoxLayout, QLabel,
    QMenuBar, QAction, QFileDialog, QMessageBox, QComboBox, QTableWidget, QTableWidgetItem
)
from PyQt5.QtGui import QIcon, QDesktopServices, QColor
from PyQt5.QtCore import QFile, QTextStream, QUrl, QTimer, QThread, pyqtSignal
import psutil
from packet_sniffer import packet_data, start_sniffing, save_data  # Import functions and variables

class SnifferThread(QThread):
    packet_captured = pyqtSignal(str, str, int, int, str)

    def __init__(self, interface, parent=None):
        super().__init__(parent)
        self.interface = interface
        self.sniffing = True

    def run(self):
        try:
            start_sniffing(self.interface)
        except Exception as e:
            self.packet_captured.emit('Error', str(e), 0, 0, 'Error')
    
    def packet_callback(self, packet):
        if not self.sniffing:
            return
        
        if IP in packet:
            protocol = packet[IP].proto
            if protocol == 6:
                protocol_name == 'TCP'
            if protocol == 17:
                protocol_name = 'UDP'
            if protocol == 1:
                protocol_name = 'ICMP'
            else:
                protocol_name = 'OTHER'

            packet_info = {
                'Source IP': packet[IP].src,
                'Ip Destination': packet[IP].dst,
                'Source Port': packet.sport if packet.haslayer(TCP) or packet.haslayer(UDP) else None,
                'Destination Port': packet.dport if packet.haslayer or packet.haslayer(UDP) else None,
                'Protocol': protocol_name,
                'Length': len(packet)
            }

            packet_data.append(packet_info)
            self.packet_captured.emit(
                packet_info['Source Ip'],
                packet_info['Ip Destination'],
                packet_info['Source Port'],
                packet_info['Destination Port'],
                packet_info['Protocol'],
            )

    def should_stop(self, packet):
        return not self.sniffing
    
    def stop_sniffing(self):
            self.sniffing = False
            self.quit()  # Exit the QThread loop
            self.wait()  # Wait for the thread to finish
            
        
class MyApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("PacketWhisper")
        self.setGeometry(100, 100, 800, 600)
        self.loadStyleSheet('dark_theme.css')
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

    def on_stop_button_click(self):
        if hasattr(self, 'sniffer_thread') and self.sniffer_thread.isRunning():
            self.sniffer_thread.stop_sniffing()
            self.label.setText("Sniffer arrêté")
            self.progress_bar.setValue(100)
            self.timer.stop()
    
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

        lightThemeAction = QAction('Light Theme', self)
        lightThemeAction.triggered.connect(lambda: self.apply_theme('light_theme.css', False))
        appearanceMenu.addAction(lightThemeAction)

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
        self.save_sniffer_data(format_name)

    def save_sniffer_data(self, format_name):
        filename, _ = QFileDialog.getSaveFileName(self, 'Save File', '', f"{format_name} Files (*.{format_name.lower()})")
        if filename:
            save_data(filename, packet_data, format_name)
            self.label.setText(f"Data saved as {filename}")

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
            self.sniffer_thread = SnifferThread(selected_interface)
            self.sniffer_thread.packet_captured.connect(self.add_packet_to_table)
            self.sniffer_thread.finished.connect(self.on_sniffer_finished)
            self.sniffer_thread.start()
        else:
            self.label.setText("Aucune Interface sélectionnée")

    def on_sniffer_finished(self):
        self.timer.stop()
        self.progress_bar.setValue(100)
        self.show_completion_message()

    def add_packet_to_table(self, source_ip, dest_ip, source_port, dest_port, protocol):
        row_position = self.table.rowCount()
        self.table.insertRow(row_position)
    
        source_ip_item = QTableWidgetItem(source_ip)
        dest_ip_item = QTableWidgetItem(dest_ip)
        source_port_item = QTableWidgetItem(str(source_port))
        dest_port_item = QTableWidgetItem(str(dest_port))
        protocol_item = QTableWidgetItem(protocol)

        if 'dark_theme' in self.styleSheet():
            text_color = QColor(255, 255, 255)
            background_color = QColor(43, 43, 43)
        else:
            text_color = QColor(0, 0, 0)
            background_color = QColor(255, 255, 255)

        source_ip_item.setForeground(text_color)
        dest_ip_item.setForeground(text_color)
        source_port_item.setForeground(text_color)
        dest_port_item.setForeground(text_color)
        protocol_item.setForeground(text_color)

        source_ip_item.setBackground(background_color)
        dest_ip_item.setBackground(background_color)
        source_port_item.setBackground(background_color)
        dest_port_item.setBackground(background_color)
        protocol_item.setBackground(background_color)

        self.table.setItem(row_position, 0, source_ip_item)
        self.table.setItem(row_position, 1, dest_ip_item)
        self.table.setItem(row_position, 2, source_port_item)
        self.table.setItem(row_position, 3, dest_port_item)
        self.table.setItem(row_position, 4, protocol_item)

    def update_table_colors(self, is_dark_theme):
        row_count = self.table.rowCount()
        for row in range(row_count):
            for column in range(self.table.columnCount()):
                item = self.table.item(row, column)
                if item:
                    if is_dark_theme:
                        item.setForeground(QColor(255, 255, 255))  # White text for dark theme
                        item.setBackground(QColor(43, 43, 43))  # Dark background for dark theme
                    else:
                        item.setForeground(QColor(0, 0, 0))  # Black text for light theme
                        item.setBackground(QColor(255, 255, 255))  # White background for light theme

        # Mise à jour des en-têtes
        for col in range(self.table.columnCount()):
            item = self.table.horizontalHeaderItem(col)
            if item:
                if is_dark_theme:
                    item.setForeground(QColor(255, 255, 255))
                    item.setBackground(QColor(43, 43, 43))
                else:
                    item.setForeground(QColor(0, 0, 0))
                    item.setBackground(QColor(255, 255, 255))

    def update_progress(self):
        current_value = self.progress_bar.value()
        if current_value < 100:
            self.progress_bar.setValue(current_value + 1)

    def show_completion_message(self):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setText("Sniffing terminé!")
        msg.setInformativeText("Le sniffing des paquets est terminé.")
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
