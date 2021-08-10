from pathlib import Path
from crypto import SymmetricCrypto
from pass_input import PassInput
from nacl.public import PrivateKey
from nacl.exceptions import CryptoError
from sys import exit
import os


class MasterKeyPair:
    KEYPAIR_DIR_ENV_VAR = "NACL_KEYPAIR_DIR"

    def __init__(
        # all of these defaults to None because
        # argparse returns None when option is not specified
        self,
        keypair_dir=None,
        skey_filename=None,
        pubkey_filename=None,
    ):
        if keypair_dir is None:
            env_key_dir = os.environ.get(MasterKeyPair.KEYPAIR_DIR_ENV_VAR)
            self.keypair_dir = (
                Path.home() / ".keys" if env_key_dir is None else env_key_dir
            )  # directory where keypair is contained

        self.public_key_file = self.keypair_dir / (
            "nacl_pubkey.pub" if pubkey_filename is None else pubkey_filename
        )
        self.secret_key_file = self.keypair_dir / (
            "nacl_seckey.enc" if skey_filename is None else skey_filename
        )

    def generate(self, passwd=None):
        """
        generates an NaCL keypair and written to disk at self.keypair_dir location
        the secret key is symmetrically encrypted with master password provided by the user
        """
        # check if a secret already exists in the keystore directory
        if self.secret_key_file.exists():
            prompt = f"file {self.secret_key_file.name} ALREADY Exists in {self.keypair_dir}! Overwrite? (y/N): "
            while (should_overwrite := input(prompt).casefold()) not in ["y", "n", ""]:
                print(f"Invalid Input! expected 'y' or 'n' given {should_overwrite}.")
            should_overwrite = should_overwrite == "y"

            if not should_overwrite:
                print("operation cancelled! Aborting!")
                exit()

        # get master password from user
        passwd = (
            PassInput.prompt_password_and_confirm("Enter master Password: ")
            if passwd is None
            else passwd
        )

        # generate the keypair
        secret_key = PrivateKey.generate()
        public_key = secret_key.public_key

        encrypted_secret_key, salt = SymmetricCrypto.encrypt(
            secret_key.encode(), passwd
        )

        # if keystore directory doesn't exist, create it.
        if not self.keypair_dir.exists():
            os.makedirs(self.keypair_dir)

        # write key pair into their files in the key pair directory
        with open(self.secret_key_file, "w") as secret_key_file:
            # key derivation salt is appended to the user's secret key after the '|' symbol
            secret_key_file.write("|".join([encrypted_secret_key, salt]))
        with open(self.public_key_file, "w") as public_key_file:
            public_key_file.write(public_key.encode().hex())

    def get_secret(self, passwd=None):
        """
        decrypt and return the secret key from disk using provided password
        """
        with open(self.secret_key_file, "r") as secret_key_file:
            encrypted_secret_key, _, salt = secret_key_file.read().partition("|")

        if passwd is not None:
            return bytes.fromhex(
                SymmetricCrypto.decrypt(encrypted_secret_key, passwd, salt)
            )

        def check_if_right_passwd(inputted_passwd, pyentry_instance, attempts_left):
            try:
                secret = SymmetricCrypto.decrypt(
                    bytes.fromhex(encrypted_secret_key), inputted_passwd, salt
                )
                return bytes.fromhex(secret)
            except CryptoError:
                pyentry_instance.description = (
                    f"Wrong Password! Try Again {attempts_left} tries left"
                )
                return False

        def ran_out_of_attempts():
            print("Wrong Password!")
            exit()

        return PassInput.prompt_password_until(
            "Enter master password: ", check_if_right_passwd, ran_out_of_attempts
        )

    def change_passwd(self, new_passwd=None):
        """
        change the master password using the secret key is encrypted on disk
        """
        secret_key = self.get_secret()
        new_passwd = (
            PassInput.prompt_password_and_confirm("Enter new master password: ")
            if new_passwd is None
            else new_passwd
        )
        with open(self.secret_key_file, "w") as secret_key_file:
            secret_key = secret_key_file.write(
                "|".join(SymmetricCrypto.encrypt(secret_key, new_passwd))
            )


if __name__ == "__main__":
    key_pair = MasterKeyPair()
    key_pair.change_passwd()
