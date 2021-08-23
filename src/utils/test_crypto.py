import unittest
import crypto


class TestCrypto(unittest.TestCase):
    def test_crypto(self):
        password = "this is a bad password"
        secret_box = crypto.KeySecretBox(password)
        salt = secret_box.salt
        plain_text = b"lorem ipsum dolor sit amet"
        cipher_text = secret_box.encrypt(plain_text)
        confirm_secret_box = crypto.KeySecretBox(password, salt)
        decrypted_plain_text = confirm_secret_box.decrypt(cipher_text)
        self.assertEqual(plain_text, decrypted_plain_text)
