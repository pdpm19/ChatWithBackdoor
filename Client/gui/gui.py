
import os
import sys
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *

# Global Variables
guiPath = None

# GUI
class GUI(QMainWindow):
    def __init__(self, width, heigth, windowTitle):
        super(GUI, self).__init__()
        self.setGeometry(800, 600, width, heigth)
        
        iconPath = os.path.join(guiPath, 'images', 'chat_icon.png')
        self.setWindowIcon(QIcon(iconPath)) 
        
        self.setWindowTitle(windowTitle)

        # Headline font
        self.headline = QFont("Arial", 14, QFont.Bold)


        # As diferentes páginas da aplicação vão estar sobrepostas
        # 0 -> Homepage
        # 1 -> Registo
        # 2 -> Login
        # 3 -> Chat
        self.stacked = QStackedWidget()
        
        self.homepageWidgets = QWidget()
        self.homepageLayout = QVBoxLayout()
        self.HomepageUI()

        self.loginWidgets = QWidget()
        self.loginLayout = QVBoxLayout()
        self.LoginUI()

        self.registerWidgets = QWidget()
        self.registerLayout = QVBoxLayout()
        self.RegisterUI()
        
        self.stacked.addWidget(self.homepageWidgets)
        self.stacked.addWidget(self.loginWidgets)
        self.stacked.addWidget(self.registerWidgets)
        self.setCentralWidget(self.stacked)

    # Homepage
    def HomepageUI(self):
        # Logo
        # Insere o logo
        global guiPath
        logo = QLabel()
        logoPath = os.path.join(guiPath, 'images', 'backdoor-logo.jpg')
        pixmap = QPixmap(logoPath)
        logo.setPixmap(pixmap)
        self.homepageLayout.addWidget(logo)
        self.homepageLayout.setAlignment(logo, Qt.AlignCenter)
        # Buttons
        registerBtn = QPushButton('Register')
        registerBtn.pressed.connect(self.RegisterConnect)
        
        loginBtn = QPushButton('Login')
        loginBtn.pressed.connect(self.LoginConnect)
        
        self.homepageLayout.addWidget(registerBtn)
        self.homepageLayout.addWidget(loginBtn)
        self.homepageWidgets.setLayout(self.homepageLayout)

    # Registo

    # Login
    def LoginUI(self):
        # Falta criar um widget para os campos username e password
        # Falta criar um widget para os campos dos botões Voltar e Confirmar
        
        login = QWidget()
        loginFormLayout = QFormLayout()

        self.usernameLoginField = QLineEdit()
        self.passwordLoginField = QLineEdit()
        self.passwordLoginField.setEchoMode(QLineEdit.Password) # Shows *** insted of characters
        
        loginBtns = QWidget()
        loginBtnsLayout = QHBoxLayout()

        backBtn = QPushButton('Voltar')
        backBtn.pressed.connect(self.HomepageConnect)
        loginBtn = QPushButton('Login')
        loginBtn.pressed.connect(self.LoginPhase)
        
        loginBtnsLayout.addWidget(backBtn)
        loginBtnsLayout.addWidget(loginBtn)
        loginBtns.setLayout(loginBtnsLayout)

        loginFormLayout.addRow(QLabel('Username:'), self.usernameLoginField)
        loginFormLayout.addRow(QLabel('Password:'), self.passwordLoginField)
        
        login.setLayout(loginFormLayout)

        self.loginLayout.addWidget(login)
        self.loginLayout.addWidget(loginBtns)
        self.loginWidgets.setLayout(self.loginLayout)
        
    
    # Register
    def RegisterUI(self):
        register = QWidget()
        registerFormLayout = QFormLayout()

        self.usernameRegisterField = QLineEdit()
        self.passwordRegisterField = QLineEdit()
        self.passwordRegisterField.setEchoMode(QLineEdit.Password)
        self.passwordConfirmationRegisterField = QLineEdit()
        self.passwordConfirmationRegisterField.setEchoMode(QLineEdit.Password)

        registerFormLayout.addRow(QLabel('Username:'), self.usernameRegisterField)
        registerFormLayout.addRow(QLabel('Password:'), self.passwordRegisterField)
        registerFormLayout.addRow(QLabel('Confirm Password:'), self.passwordConfirmationRegisterField) 
        register.setLayout(registerFormLayout)

        registerBtns = QWidget()
        registerBtnsLayout = QHBoxLayout()

        backBtn = QPushButton('Voltar')
        backBtn.pressed.connect(self.HomepageConnect)
        registerBtn = QPushButton('Register')
        registerBtn.pressed.connect(self.RegisterPhase)
        
        registerBtnsLayout.addWidget(backBtn)
        registerBtnsLayout.addWidget(registerBtn)
        registerBtns.setLayout(registerBtnsLayout)

        self.registerLayout.addWidget(register)
        self.registerLayout.addWidget(registerBtns)
        self.registerWidgets.setLayout(self.registerLayout)
   
    # Chat
    
    # Login phase, this part should have security openssl passwd
    def LoginPhase(self):
        # Tries to make login if all fields are filled
        if self.usernameLoginField.text() and self.passwordLoginField.text():
            print('Fase de login!')
            # SOME CODE GOES HERE
            # If login is not possible, Error message....

        # Warns if one or other field are empty
        else:
            warning = QMessageBox()
            warning.setIcon(QMessageBox.Warning)
            warning.setWindowTitle('Warning')
            warning.setText('Failed Login')
            warning.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
            if (not self.usernameLoginField.text() and self.passwordLoginField.text()):
                warning.setInformativeText('Ups! There is no username... :c')
            elif (not self.passwordLoginField.text() and self.usernameLoginField.text()):
                warning.setInformativeText('Ups! There is no password... :/')
            else:
                warning.setInformativeText('Ups! There is nothing... :o')
            
            warning.exec_()
    # Register phase
    def RegisterPhase(self):
        # Password nao coincidem...
        # Falta coisas
        # Registo
        if self.usernameRegisterField.text() and self.passwordRegisterField.text() and self.passwordRegisterField.text() == self.passwordConfirmationRegisterField.text():
            print('Fase de registo!')
        
        else:
            warning = QMessageBox()
            warning.setIcon(QMessageBox.Warning)
            warning.setWindowTitle('Warning')
            warning.setText('Failed Registration')
            # Passwords are different in 1st and 2nd line
            if self.passwordRegisterField.text() and self.passwordRegisterField.text() and self.passwordRegisterField.text() != self.passwordConfirmationRegisterField.text():
                warning.setInformativeText('Ups! Passwords are not the same...')
            if not self.usernameRegisterField.text() or not self.passwordRegisterField.text() or not self.passwordConfirmationRegisterField.text():
                warning.setInformativeText('Ups! Some fields are empty... \nPlease fill them :D')
            warning.exec_()

    # Connects
    def LoginConnect(self):
        self.stacked.setCurrentIndex(1)
    def RegisterConnect(self):
        self.stacked.setCurrentIndex(2)
    def HomepageConnect(self):
        self.LoginFieldsClear()
        self.RegisterFieldsClear()
        self.stacked.setCurrentIndex(0)
    
    # Clear
    def LoginFieldsClear(self):
        self.usernameLoginField.clear()
        self.passwordLoginField.clear()
    
    def RegisterFieldsClear(self):
        self.usernameRegisterField.clear()
        self.passwordRegisterField.clear()
        self.passwordConfirmationRegisterField.clear()
    


# Calls the GUI
def GUILoad(args):
    global guiPath
    guiPath = args

    app = QApplication([])
    window = GUI(600, 400, 'ChatWithBackDoor')
    window.show()
    app.exec()
