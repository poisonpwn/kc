from nacl.secret import SecretBox
from nacl.utils import random
from pyargon2 import hash


class SymmetricCrypto:
    KDF_SALT_BYTES = 32

    def gen_secret_box_from_pass(passwd, salt=None):
        """
        performs a key derivation from given password
        if salt is not specified a random salt is generated and used
        to create an NaCl SecretBox instance with the credentials
        which is returned along with the salt used
        """
        # perform key derivation from password passed in by user
        if salt is None:
            salt = random(SymmetricCrypto.KDF_SALT_BYTES).hex()
        derived_symmetric_key = hash(
            passwd,
            salt,
            hash_len=SecretBox.KEY_SIZE,
            encoding="raw",
        )

        # encrypt the secret key with password passed in by user
        return SecretBox(derived_symmetric_key), salt

    def encrypt(message, passwd, salt=None):
        """
        encrypt with NaCl secretbox
        if salt is not provided a random salt is generated
        returns a tuple of the hex of the encrypted message and the salt used
        """
        secret_box, salt = SymmetricCrypto.gen_secret_box_from_pass(passwd, salt)
        return secret_box.encrypt(message).hex(), salt

    def decrypt(cipher, passwd, salt):
        """
        decrypts cipher text with SecretBox
        returns hex of decryption
        """
        secret_box, _ = SymmetricCrypto.gen_secret_box_from_pass(passwd, salt)
        return secret_box.decrypt(cipher).hex()
