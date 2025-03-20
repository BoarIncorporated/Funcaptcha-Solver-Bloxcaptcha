from json import loads, dumps
from base64 import b64decode, b64encode
from hashlib import md5
from string import ascii_lowercase
from random import choice
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from typing import Dict, Any


__all__ = ("decrypt_data", "encrypt_data")


def _generate_salted_key(key: str, salt: str) -> str:
    salted = ""
    dx = b""

    for _ in range(3):
        dx = md5(dx + key.encode("utf-8") + salt.encode("utf-8")).digest()
        salted += dx.hex()

    return salted


def decrypt_data(raw_data: str, key: str) -> str:
    data: Dict[str, str] = loads(raw_data)

    salt: bytes = bytes.fromhex(data["s"])
    salted_key: str = _generate_salted_key(key, salt.decode("utf-8"))

    aes_key: bytes = bytes.fromhex(salted_key[:64])
    iv: bytes = bytes.fromhex(data["iv"])

    aes = AES.new(aes_key, AES.MODE_CBC, iv)

    cipher_text: bytes = b64decode(data["ct"])
    decrypted_data: bytes = unpad(aes.decrypt(cipher_text), AES.block_size)

    return decrypted_data.decode("utf-8")


def encrypt_data(data: str, key: str, switch_order: bool = False) -> str:
    salt: str = "".join(choice(ascii_lowercase) for _ in range(8))
    salted_key: str = _generate_salted_key(key, salt)

    aes_key: bytes = bytes.fromhex(salted_key[:64])
    iv: bytes = bytes.fromhex(salted_key[64:96])

    aes = AES.new(aes_key, AES.MODE_CBC, iv)

    padded_data: bytes = pad(data.encode("utf-8"), AES.block_size)
    cipher_text: bytes = aes.encrypt(padded_data)

    encrypted_data: Dict[str, Any] = {
        "ct": b64encode(cipher_text).decode("utf-8"),
        "iv": iv.hex(),
        "s": salt.encode("utf-8").hex(),
    }

    if switch_order:
        encrypted_data = {
            "ct": b64encode(cipher_text).decode("utf-8"),
            "s": salt.encode("utf-8").hex(),
            "iv": iv.hex(),
        }

    return dumps(encrypted_data, separators=(",", ":"))
