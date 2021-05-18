# Main file
# Standard imports
import os
import sys
import threading
#from connect_server import SendMessage

workingDirectory = os.getcwd()
guiPath = os.path.join(workingDirectory, 'gui')
sys.path.append(guiPath)
sys.path.append(workingDirectory)


# My imports
from connect_server import ConServer
from gui import GUILoad
from gui import ChatUI

if __name__ == '__main__':
    # 1. Checks if everything is OK
    #threading_accept = threading.Thread(
    #        target=ConServer, args=[])
    #threading_accept.start()
    # 2. Calls the GUI
    GUILoad(guiPath)