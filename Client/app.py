# Main file
# Standard imports
import os
import sys
import threading

workingDirectory = os.getcwd()
guiPath = os.path.join(workingDirectory, 'gui')
sys.path.append(guiPath)

# My imports
from gui import GUILoad
from backend_process import ConnServer
if __name__ == '__main__':
    # 1st Starts the Backend process a.k. ConServer() (connect_server.py)
    server, secret, server_pk = ConnServer()
    
    # 2nd If connection is established, them Client GUI can load
    paths = [guiPath, server, secret, server_pk]
    GUILoad(paths)
    
sys.exit()