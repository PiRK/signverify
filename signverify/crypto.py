from typing import Tuple

from electroncash import bitcoin
import ecdsa


def is_private_key(wif_privkey: str) -> bool:
    return bitcoin.is_private_key(wif_privkey)


def sign_message(wif_privkey: str, message: str) -> bytes:
    keytype, pk, is_compressed = bitcoin.deserialize_privkey(wif_privkey)
    eck = bitcoin.EC_KEY(pk)
    return eck.sign_message(message, is_compressed)


def verify_signature_with_privkey(
    signature: bytes, message: str, wif_privkey: str
) -> bool:
    keytype, pk, is_compressed = bitcoin.deserialize_privkey(wif_privkey)
    eck = bitcoin.EC_KEY(pk)
    try:
        eck.verify_message(signature, message.encode("utf-8"))
    except Exception:
        return False
    return True


def verify_signature(
    message: str, signature: bytes) -> Tuple[bool, bytes]:
    """Verify a signed message.

    Return a tuple (is_verified, public_key)

    If public_key is a null bytestring, it means deriving the public
    key from the signature failed. In this case is_verified is expected
    to be always False.
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
    try:
        key1 = ecdsa.keys.VerifyingKey.from_string(pubkey1, curve=ecdsa.curves.SECP256k1)
        key2 = ecdsa.keys.VerifyingKey.from_string(pubkey2, curve=ecdsa.curves.SECP256k1)
    except ecdsa.keys.MalformedPointError:
        print("malformed point")
        return False
    return key1 == key2