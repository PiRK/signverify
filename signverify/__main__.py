
from PySide2 import QtWidgets
from .gui import MainWindow


def main():
    """Application's entry point defined in setup.py"""
    app = QtWidgets.QApplication([])
    mw = MainWindow()
    mw.show()
    app.exec_()


# This is reached if the package is executed with `python -m signverify`
if __name__ == '__main__':
    main()
