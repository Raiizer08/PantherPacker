import sys
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QLabel, QMenuBar, QAction

class MyApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("PacketWhisper")
        self.setGeometry(100, 100, 800, 600)

        # barre de menu
        menuBar = QMenuBar(self)
        fileMenu = menuBar.addMenu('File')
        settingsMenu = menuBar.addMenu('Settings')
        githubMenu = menuBar.addMenu('Github')

        # ajout de deux actions dans le menu file
        action1 = QAction('Open Workspace From File', self)
        action1.triggered.connect(self.on_action_triggered)
        fileMenu.addAction(action1)

        action2 = QAction('Open Folder', self)
        action2.triggered.connect(self.on_action_triggered)
        fileMenu.addAction(action2)

        # ajout de deux actions dans le menu settings
        action1 = QAction('Appareance',self)
        action1.triggered.connect(self.on_action_triggered)
        settingsMenu.addAction(action1)

        action2 = QAction('Output Format',self)
        action2.triggered.connect(self.on_action_triggered)
        settingsMenu.addAction(action2)

        # ajout d'une action dans le menu github
        action1 = QAction('My GitHub',self)
        action1.triggered.connect(self.on_action_triggered)
        githubMenu.addAction(action1)        
        # label pour afficher le résultat
        self.label = QLabel('Résultat de la capture : ', self)

        # bouton pour démarrer le sniffer
        button = QPushButton('Démarrer le sniffer', self)
        button.clicked.connect(self.on_button_click)

        layout = QVBoxLayout()
        layout.addWidget(menuBar)
        layout.addWidget(self.label)
        layout.addWidget(button)
        self.setLayout(layout)

    def on_button_click(self):
        self.label.setText("Sniffer Started")

    def on_action_triggered(self):
        self.label.setText("Action triggered !")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    myApp = MyApp()
    myApp.show()
    sys.exit(app.exec_())
