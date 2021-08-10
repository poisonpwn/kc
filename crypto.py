from nacl.secret import SecretBox
from nacl.utils import random
from pyargon2 import hash


class Crypto:
    KDF_SALT_BYTES = 32

    def __gen_secret_box_from_pass(passwd, salt=None):
        # perform key derivation from password passed in by user
        if salt is None:
            salt = random(Crypto.KDF_SALT_BYTES).hex()
        derived_symmetric_key = hash(
            passwd,
            salt,
            hash_len=SecretBox.KEY_SIZE,
            encoding="raw",
        )

        # encrypt the secret key with password passed in by user
        return SecretBox(derived_symmetric_key), salt

    def encrypt(message, passwd, salt=None):
        secret_box, salt = Crypto.__gen_secret_box_from_pass(passwd, salt)
        return secret_box.encrypt(message), salt

    def decrypt(cipher, passwd, salt):
        secret_box, _ = Crypto.__gen_secret_box_from_pass(passwd, salt)
        return secret_box.decrypt(cipher)
