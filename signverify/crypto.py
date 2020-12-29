import base64
import binascii
import ecdsa
from typing import Tuple

from electroncash import bitcoin
from electroncash.address import Address


def is_private_key(wif_privkey: str) -> bool:
    return bitcoin.is_private_key(wif_privkey)


def sign_message(wif_privkey: str, message: str) -> bytes:
    keytype, pk, is_compressed = bitcoin.deserialize_privkey(wif_privkey)
    eck = bitcoin.EC_KEY(pk)
    return eck.sign_message(message, is_compressed)


def derive_pubkey(message: str, signature: bytes) -> Tuple[bool, bytes]:
    """Derive a public key from a message and signature.

    Return a tuple (is_verified, public_key). The public key, is returned
    as a compressed key.

    If public_key is a null bytestring, it means deriving the public
    key from the signature failed. In this case is_verified is expected
    to be always False.

    If is_verified is True, it only means that this function was able to
    derive a public key from the message and signature. This public key
    still needs to be checked against another key or bitcoin address.
    """
    h = bitcoin.Hash(bitcoin.msg_magic(message.encode("utf-8")))
    try:
        public_key_from_sig, compressed = bitcoin.pubkey_from_signature(signature, h)
    except Exception:
        return False, b""

    try:
        is_verified = public_key_from_sig.verify_digest(
            signature[1:], h, sigdecode=ecdsa.util.sigdecode_string
        )
    except Exception:
        is_verified = False
    return is_verified, public_key_from_sig.to_string(encoding="compressed")


def compare_pubkeys(pubkey1: bytes, pubkey2: bytes) -> bool:
    """Compare two public keys on the SECP256k1 curve. Return True
    if they match.

    The function does accept and automatically detect the type of point
    encoding used. It supports the :term:`raw encoding`,
    :term:`uncompressed`, :term:`compressed` and :term:`hybrid` encodings.
    """
    try:
        key1 = ecdsa.keys.VerifyingKey.from_string(
            pubkey1, curve=ecdsa.curves.SECP256k1
        )
        key2 = ecdsa.keys.VerifyingKey.from_string(
            pubkey2, curve=ecdsa.curves.SECP256k1
        )
    except ecdsa.keys.MalformedPointError:
        return False
    return key1 == key2


def is_address(addr: str) -> bool:
    """Test if a string is a valid bitcoin address.
    Supported formats: CashAddr, legacy address.
    """
    return Address.is_valid(addr.strip())


def verify_signature_with_address(address: str, message: str, signature: str) -> bool:
    """Verify a message signature using a bitcoin address.

    :param address: Bitcoin address, either legacy or cashaddr
    :param message: Message to verify against the signature
    :param signature: Base64 encoded signature string.
    """
    try:
        sig = base64.b64decode(signature)
    except binascii.Error:
        return False
    addr = Address.from_string(address)
    message_bytes = message.encode("utf-8")

    return bitcoin.verify_message(addr, sig, message_bytes)


def verify_signature_with_pubkey(pubkey: str, message: str, signature: str) -> bool:
    """Verify a message signature using a public key

    :param pubkey: Bitcoin public key as a hexadecimal string (raw or compressed)
    :param message: Message to verify against the signature
    :param signature: Base64 encoded signature string.
    """
    try:
        sig = base64.b64decode(signature)
    except binascii.Error:
        return False
    try:
        pubkey_bytes = bytes.fromhex(pubkey)
    except ValueError:
        return False

    is_verified, derived_pubkey = derive_pubkey(message, sig)
    if not is_verified or not derived_pubkey:
        return False
    return compare_pubkeys(derived_pubkey, pubkey_bytes)


def verify_signature_with_privkey(
    wif_privkey: str, message: str, signature: str
) -> bool:
    try:
        sig = base64.b64decode(signature)
    except binascii.Error:
        return False
    keytype, pk, is_compressed = bitcoin.deserialize_privkey(wif_privkey)
    eck = bitcoin.EC_KEY(pk)
    try:
        eck.verify_message(sig, message.encode("utf-8"))
    except Exception:
        return False
    return True
