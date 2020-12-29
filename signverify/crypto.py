import base64
import binascii
import ecdsa
from typing import Sequence, Tuple

from electroncash import bitcoin
from electroncash.address import Address, Script


# The node software set this limit to 20, but all electrum forks seem to limit it to 15
MAX_PUBKEYS_PER_MULTISIG = 15


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


def pubkeys_to_multisig_p2sh(pubkeys: Sequence[str], m: int) -> str:
    """

    :param pubkeys: List of publics keys, as hexadecimal strings.
        The keys will be sorted.
    :param m: Minimal number of signatures to unlock the multisig script
        (it is the M in M-of-N)
    :return: p2sh CashAddr
    """
    pubkeys_bytes = [bytes.fromhex(pubkey) for pubkey in pubkeys]
    redeem_script = Script.multisig_script(m, sorted(pubkeys_bytes))
    fmt = Address.FMT_CASHADDR_BCH
    return Address.from_multisig_script(redeem_script).to_full_string(fmt)


def are_addresses_identical(addr1: str, addr2: str) -> bool:
    """Compare 2 addresses. These addresses can be of a different format.

    :param addr1:
    :param addr2:
    :return:
    """
    addr1 = Address.from_string(addr1)
    addr2 = Address.from_string(addr2)
    fmt = Address.FMT_LEGACY
    return addr1.to_string(fmt) == addr2.to_string(fmt)
