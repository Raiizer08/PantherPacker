import sys
from PyQt5.QtWidgets import (
    QApplication, QProgressBar, QWidget, QPushButton, QVBoxLayout, QLabel,
    QMenuBar, QAction, QFileDialog, QMessageBox, QComboBox, QTableWidget, QTableWidgetItem
)
from PyQt5.QtGui import QIcon, QDesktopServices
from PyQt5.QtCore import QFile, QTextStream, QUrl, QTimer, QThread, pyqtSignal
import psutil
from packet_sniffer import packet_data, start_sniffing, save_data  # Import functions and variables

class SnifferThread(QThread):
    packet_captured = pyqtSignal(str, str, int, int, str)

    def __init__(self, interface, parent=None):
        super().__init__(parent)
        self.interface = interface

    def run(self):
        try:
            start_sniffing(self.interface, count=1000)  # Start sniffing with a count of 1000
            for packet_info in packet_data:
                # Emitting signal for each packet captured
                self.packet_captured.emit(
                    packet_info['Source IP'],
                    packet_info['Ip Destination'],
                    packet_info['Source Port'],
                    packet_info['Destination Port'],
                    packet_info['Protocol']
                )
        except Exception as e:
            self.packet_captured.emit('Error', str(e), 0, 0, 'Error')

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

        self.label = QLabel('Résultat de la capture : ', self)
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.hide()

        self.start_button = QPushButton('Démarrer le sniffer', self)
        self.start_button.clicked.connect(self.on_button_click)

        self.table = QTableWidget(self)
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(['Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Protocol'])

        layout = QVBoxLayout()
        layout.addWidget(self.menuBar)
        layout.addWidget(self.label)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.interface_combo)
        layout.addWidget(self.start_button)
        layout.addWidget(self.table)
        self.setLayout(layout)

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
        darkThemeAction.triggered.connect(lambda: self.loadStyleSheet('dark_theme.css'))
        appearanceMenu.addAction(darkThemeAction)

        lightThemeAction = QAction('Light Theme', self)
        lightThemeAction.triggered.connect(lambda: self.loadStyleSheet('light_theme.css'))
        appearanceMenu.addAction(lightThemeAction)

        pinkThemeAction = QAction('Pink Theme', self)
        pinkThemeAction.triggered.connect(lambda: self.loadStyleSheet('pink_theme.css'))
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
        self.table.setItem(row_position, 0, QTableWidgetItem(source_ip))
        self.table.setItem(row_position, 1, QTableWidgetItem(dest_ip))
        self.table.setItem(row_position, 2, QTableWidgetItem(str(source_port)))
        self.table.setItem(row_position, 3, QTableWidgetItem(str(dest_port)))
        self.table.setItem(row_position, 4, QTableWidgetItem(protocol))

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

    
def closeEvent(self, event):
        if hasattr(self, 'timer'):
            self.timer.stop()
        event.accept()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    myApp = MyApp()
    myApp.show()
    sys.exit(app.exec_())        