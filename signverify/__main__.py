
from PySide2 import QtWidgets
from .gui import MainWindow

app = QtWidgets.QApplication([])
mw = MainWindow()
mw.show()
app.exec_()
