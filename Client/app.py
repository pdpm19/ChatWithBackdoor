# Main file
# Standard imports
import os
import sys

workingDirectory = os.getcwd()
guiPath = os.path.join(workingDirectory, 'gui')
sys.path.append(guiPath)

# My imports
from gui import GUILoad

if __name__ == '__main__':
    # 1. Checks if everything is OK

    # 2. Calls the GUI
    GUILoad(guiPath) 