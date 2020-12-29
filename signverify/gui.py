from PySide2 import QtWidgets
from PySide2 import QtGui
import base64

from .crypto import (
    compare_pubkeys,
    is_private_key,
    is_address,
    sign_message,
    verify_signature_from_address,
    verify_signature_from_pubkey,
)


class HLine(QtWidgets.QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QtWidgets.QFrame.HLine)
        self.setFrameShadow(QtWidgets.QFrame.Sunken)


class SignWidget(QtWidgets.QWidget):
    """Signature widget. It has an input field for a private key, and
    displays the signature."""

    def __init__(self, parent=None):
        super(SignWidget, self).__init__(parent)

        layout = QtWidgets.QVBoxLayout()
        self.setLayout(layout)

        layout.addWidget(QtWidgets.QLabel("Private key (WIF)"))
        self.privkey_edit = QtWidgets.QLineEdit()
        layout.addWidget(self.privkey_edit)

        layout.addWidget(QtWidgets.QLabel("Signature (Base64)"))
        self.signature_display = QtWidgets.QTextEdit()
        self.signature_display.setReadOnly(True)
        layout.addWidget(self.signature_display)

        self._message: str = ""
        """Message to be signed"""

        self.privkey_edit.textChanged.connect(self._on_key_or_msg_updated)

    def set_message(self, message: str):
        self._message = message
        self._on_key_or_msg_updated()

    def _on_key_or_msg_updated(self, *args):
        self.signature_display.clear()
        key = self.privkey_edit.text()
        if not key:
            return
        if is_private_key(key):
            signature = self.sign_message(self._message, key)
            self.signature_display.setHtml(f'<p style="color:black;">{signature}</p>')
        else:
            self.signature_display.setHtml(
                '<p style="color:red;">Incorrect private key format</p>'
            )

    def sign_message(self, message: str, wif_privkey: str) -> str:
        """
        Sign the message and return the signature as a base64 string.
        """
        sig = sign_message(wif_privkey, message)
        return base64.b64encode(sig).decode("ascii")


class VerifyWidget(QtWidgets.QWidget):
    """Verification widget. It has an input field for a signature, and
    displays the public key."""

    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QtWidgets.QVBoxLayout()
        self.setLayout(layout)

        layout.addWidget(QtWidgets.QLabel("Public key (hex) or bitcoin address"))
        self.pubkey_edit = QtWidgets.QLineEdit()
        layout.addWidget(self.pubkey_edit)

        layout.addWidget(QtWidgets.QLabel("Signature (Base64)"))
        self.signature_edit = QtWidgets.QTextEdit()
        self.signature_edit.setAcceptRichText(False)
        layout.addWidget(self.signature_edit)

        sublayout = QtWidgets.QHBoxLayout()
        layout.addLayout(sublayout)
        sublayout.addWidget(QtWidgets.QLabel("Signature verification: "))
        self.verification_label = QtWidgets.QLabel()
        sublayout.addWidget(self.verification_label)
        sublayout.addStretch(1)

        self._message: str = ""
        """Message to be signed"""
        self._signature: str = ""
        """Base64 representation of the signature"""

        self.signature_edit.textChanged.connect(self._on_signature_updated)
        self.pubkey_edit.textChanged.connect(self._on_input_updated)

    def set_message(self, message: str):
        self._message = message
        self.verify_signature()

    def _on_signature_updated(self):
        self._signature = self.signature_edit.toPlainText()
        self.verify_signature()

    def _on_input_updated(self):
        self.verify_signature()

    def verify_signature(self):
        """Verify that the signature matches the message for the specified public key
        or address.
        Display a green checkmark if it matches or a red X-mark if it doesn't.
        """
        key = self.pubkey_edit.text().strip()
        if not key:
            self.verification_label.clear()
            return

        if is_address(key):
            is_verified = verify_signature_from_address(
                key, self._message, self._signature
            )
        else:
            is_verified = verify_signature_from_pubkey(
                key, self._message, self._signature
            )

        if is_verified:
            self.verification_label.setText('<p style="color:green;">✓ OK</p>')
        else:
            self.verification_label.setText('<p style="color:red;">✗ Bad signature or key</p>')


class MainWidget(QtWidgets.QWidget):
    """Central widget in the main window."""

    def __init__(self, parent=None):
        super(MainWidget, self).__init__(parent)

        layout = QtWidgets.QVBoxLayout()
        self.setLayout(layout)

        layout.addWidget(QtWidgets.QLabel("Message"))
        self.message_edit = QtWidgets.QTextEdit()
        self.message_edit.setAcceptRichText(False)
        layout.addWidget(self.message_edit)

        self.tab_widget = QtWidgets.QTabWidget()
        layout.addWidget(self.tab_widget)

        self.sign_widget = SignWidget()
        self.tab_widget.addTab(self.sign_widget, "Sign message")

        self.verify_widget = VerifyWidget()
        self.tab_widget.addTab(self.verify_widget, "Verify message")

        self.message_edit.textChanged.connect(self._on_message_changed)

    def _on_message_changed(self):
        msg = self.message_edit.toPlainText()
        self.sign_widget.set_message(msg)
        self.verify_widget.set_message(msg)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.setWindowTitle("Sign and verify messages")
        self.setCentralWidget(MainWidget(self))
        self.setMinimumWidth(800)

        main_window_bg_color = (
            self.palette().color(QtGui.QPalette.Window).name(QtGui.QColor.HexRgb)
        )
        self.setStyleSheet(
            """
            QTextEdit[readOnly="true"] {
                background-color: %s
            }
            """
            % main_window_bg_color
        )
