from PySide2 import QtWidgets
from PySide2 import QtGui
import base64
import binascii

from .crypto import (
    compare_pubkeys,
    verify_signature,
    sign_message,
    is_private_key,
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

        layout.addWidget(QtWidgets.QLabel("Secret key (WIF)"))
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

        layout.addWidget(QtWidgets.QLabel("Signature (Base64)"))
        self.signature_edit = QtWidgets.QTextEdit()
        self.signature_edit.setAcceptRichText(False)
        layout.addWidget(self.signature_edit)

        layout.addWidget(QtWidgets.QLabel("Public key (hex)"))
        self.pubkey_edit = QtWidgets.QLineEdit()
        layout.addWidget(self.pubkey_edit)

        layout.addWidget(QtWidgets.QLabel("Public key derived from signature (compressed, hex)"))
        self.pubkey_display = QtWidgets.QTextEdit()
        self.pubkey_display.setReadOnly(True)
        layout.addWidget(self.pubkey_display)

        self._message: str = ""
        """Message to be signed"""

        self.signature_edit.textChanged.connect(self._on_signature_or_message_updated)
        self.pubkey_edit.textChanged.connect(self._on_input_pubkey_updated)

    def set_message(self, message: str):
        self._message = message
        self._on_signature_or_message_updated()

    def _on_input_pubkey_updated(self, pubkey: str):
        self.verify_keys_match(pubkey)

    def _on_signature_or_message_updated(self):
        self.pubkey_display.clear()
        self.verify_signature()

    def verify_keys_match(self, *args):
        """verify that the computed verifying key matches the pubkey
        specified by the user. Adjust the color of the computed
        pubkey accordingly"""
        input_pubkey = self.pubkey_edit.text().strip()
        computed_pubkey = self.pubkey_display.toPlainText()

        if input_pubkey:
            try:
                key1 = bytes.fromhex(input_pubkey)
                key2 = bytes.fromhex(computed_pubkey)
            except ValueError:
                color = "red"
            else:
                if compare_pubkeys(key1, key2):
                    # keys match
                    color = "blue"
                else:
                    # keys don't match
                    color = "red"
        else:
            # no input key
            color = "black"
        self.pubkey_display.setHtml(f'<p style="color:{color};">{computed_pubkey}</p>')

    def verify_signature(self):
        """Verify signature matches the message, compute the
        verifying public key and display it, then call
        :meth:`verify_keys_match`"""
        try:
            # This can throw on invalid base64
            sig = base64.b64decode(self.signature_edit.toPlainText(),
                                   validate=True)
        except binascii.Error:
            self.pubkey_display.setHtml(
                '<p style="color:red;">Invalid base64 signature</p>'
            )
            return

        is_verified, pubkey = verify_signature(self._message, sig)
        self.pubkey_display.setPlainText(pubkey.hex())
        self.verify_keys_match()


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
