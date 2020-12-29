from PySide2 import QtWidgets
from PySide2 import QtGui
import base64
from typing import List, Optional

from .crypto import (
    are_addresses_identical,
    is_private_key,
    is_address,
    pubkeys_to_multisig_p2sh,
    sign_message,
    verify_signature_with_address,
    verify_signature_with_privkey,
    verify_signature_with_pubkey,
    MAX_PUBKEYS_PER_MULTISIG,
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
            is_verified = verify_signature_with_address(
                key, self._message, self._signature
            )
        elif is_private_key(key):
            is_verified = verify_signature_with_privkey(
                key, self._message, self._signature
            )
        else:
            is_verified = verify_signature_with_pubkey(
                key, self._message, self._signature
            )

        if is_verified:
            self.verification_label.setText('<p style="color:green;">✓ OK</p>')
        else:
            self.verification_label.setText(
                '<p style="color:red;">✗ Bad signature or key</p>'
            )


class SignVerifyWidget(QtWidgets.QWidget):
    """Widget handling the signing of message and the verification of signatures"""

    def __init__(self, parent=None):
        super().__init__(parent)

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


class MultisigWidget(QtWidgets.QWidget):
    """Widget handling the verification of multisig redeem scripts"""

    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QtWidgets.QVBoxLayout()
        self.setLayout(layout)

        layout.addWidget(QtWidgets.QLabel("Public keys (one per line)"))
        self.pubkeys_edit = QtWidgets.QTextEdit()
        self.pubkeys_edit.setAcceptRichText(False)
        layout.addWidget(self.pubkeys_edit)

        m_sublayout = QtWidgets.QHBoxLayout()
        layout.addLayout(m_sublayout)
        m_sublayout.addWidget(QtWidgets.QLabel("M: "))
        self.m_edit = QtWidgets.QLineEdit()
        self.m_edit.setValidator(QtGui.QIntValidator(1, MAX_PUBKEYS_PER_MULTISIG))
        m_sublayout.addWidget(self.m_edit)
        m_sublayout.addStretch(1)

        layout.addWidget(QtWidgets.QLabel("Redeem script:"))
        self.redeem_script_display = QtWidgets.QTextEdit()
        self.redeem_script_display.setReadOnly(True)
        layout.addWidget(self.redeem_script_display)

        layout.addWidget(QtWidgets.QLabel("p2sh address"))
        self.p2sh_edit = QtWidgets.QLineEdit()
        layout.addWidget(self.p2sh_edit)

        sublayout = QtWidgets.QHBoxLayout()
        layout.addLayout(sublayout)
        sublayout.addWidget(QtWidgets.QLabel("Script verification: "))
        self.verification_label = QtWidgets.QLabel()
        sublayout.addWidget(self.verification_label)
        sublayout.addStretch(1)

        self._pubkeys: List[str] = []
        """List of hex encoded public keys"""

        self._m: Optional[int] = None
        """Minimal number of signatures required to unlock the script"""

        self._p2sh: str = ""

        self._redeem_script: str = ""
        """Redeem script in a human readable format"""

        self.pubkeys_edit.textChanged.connect(self._on_pubkeys_changed)
        self.p2sh_edit.textChanged.connect(self._on_p2sh_changed)
        self.m_edit.textChanged.connect(self._on_m_changed)

    def _on_pubkeys_changed(self):
        lines = self.pubkeys_edit.toPlainText().split("\n")
        stripped_non_empty_lines = [line.strip() for line in lines if line.strip()]
        try:
            [bytes.fromhex(pubkey) for pubkey in stripped_non_empty_lines]
        except ValueError:
            # if a pubkey cannot be decoded from hex, don't even try
            self._pubkeys = []
        else:
            self._pubkeys = stripped_non_empty_lines
        self.construct_redeem_script()
        self.check_script()

    def _on_m_changed(self, text):
        if not text.strip():
            self._m = None
        else:
            self._m = int(text.strip())
        self.construct_redeem_script()
        self.check_script()

    def _on_p2sh_changed(self, text):
        self._p2sh = text.strip()
        self.check_script()

    def construct_redeem_script(self):
        # construct redeem script
        if not self._pubkeys or self._m is None:
            self.redeem_script_display.clear()
            self._redeem_script = ""
            return

        # TODO: insert the script fragments with different text colors
        self._redeem_script = f"{self._m} "
        for pubkey in sorted(self._pubkeys, key=bytes.fromhex):
            self._redeem_script += f"{pubkey} "
        self._redeem_script += f"{len(self._pubkeys)} OP_CHECKMULTISIG"
        self.redeem_script_display.setPlainText(self._redeem_script)

    def check_script(self):
        # check against p2sh address
        if not self._p2sh or self._m is None:
            self.verification_label.setText("Missing parameters (p2sh or M)")
            return
        if not self._pubkeys:
            self.verification_label.setText("Missing or incorrect public keys")
            return

        derived_p2sh = pubkeys_to_multisig_p2sh(self._pubkeys, self._m)
        if are_addresses_identical(derived_p2sh, self._p2sh):
            self.verification_label.setText('<p style="color:green;">✓ OK</p>')
        else:
            self.verification_label.setText(
                '<p style="color:red;">✗ Scripts do not match</p>'
            )


class MainWidget(QtWidgets.QTabWidget):
    """Central widget in the main window."""

    def __init__(self, parent=None):
        super(MainWidget, self).__init__(parent)

        self.addTab(SignVerifyWidget(), "Sign/verify message")
        self.addTab(MultisigWidget(), "Verify multisig script")


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
