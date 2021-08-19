from pathlib import Path
from sys import stderr
from crypto import KeySecretBox
from pass_input import AskUser
from nacl.public import PrivateKey
from pynentry import PynEntry
from nacl.exceptions import CryptoError
from sys import exit
from typing import Final, Optional
import os


class MasterKeyPair:
    KEYPAIR_DIR_ENV_VAR = "NACL_KEYPAIR_DIR"
    DEFAULT_SECRET_KEY_FILENAME = "nacl_seckey.enc"
    DEFAULT_PUBLIC_KEY_FILENAME = "nacl_pubkey.pub"
    DEFAULT_KEYPAIR_DIR_PATH: Final[Path] = Path.home() / ".keys"

    def __init__(
        # all of these defaults to None because
        # argparse returns None when option is not specified
        self,
        keypair_dir: Optional[Path] = None,
        skey_filename: Optional[str] = None,
        pubkey_filename: Optional[str] = None,
    ):
        self.keypair_dir = keypair_dir
        if keypair_dir is None:
            # key_pair_dir was not specified so check the environment
            env_key_dir = os.environ.get(MasterKeyPair.KEYPAIR_DIR_ENV_VAR)
            self.keypair_dir = (
                # if keypair_dir was not specified in the environment either
                MasterKeyPair.DEFAULT_KEYPAIR_DIR_PATH
                if env_key_dir is None
                else Path(env_key_dir)
            )  # directory where keypair is contained:

        if not self.keypair_dir.exists():
            os.makedirs(self.keypair_dir)

        self.public_key_file = self.keypair_dir / (
            MasterKeyPair.DEFAULT_PUBLIC_KEY_FILENAME
            if pubkey_filename is None
            else pubkey_filename
        )
        self.secret_key_file = self.keypair_dir / (
            MasterKeyPair.DEFAULT_SECRET_KEY_FILENAME
            if skey_filename is None
            else skey_filename
        )

    def generate(self, passwd: Optional[str] = None):
        """
        generates an NaCL keypair and writes to disk at self.keypair_dir location
        the secret key is symmetrically encrypted with master password provided by the user
        """
        if self.secret_key_file.exists():
            prompt = f"file {self.secret_key_file.name} ALREADY Exists in {self.keypair_dir}! Overwrite? (y/N): "
            while (should_overwrite := input(prompt).casefold()) not in ["y", "n", ""]:
                print(f"Invalid Input! expected 'y' or 'n' given {should_overwrite}.")
            should_overwrite = should_overwrite == "y"

            if not should_overwrite:
                print("operation cancelled! Aborting!")
                exit()

        passwd = (
            AskUser.and_confirm("Enter master Password: ") if passwd is None else passwd
        )

        secret_key = PrivateKey.generate()
        public_key = secret_key.public_key

        # create a secret box with the password and use that to encrypt the secret key
        secret_box = KeySecretBox(passwd)
        encrypted_secret_key = secret_box.encrypt(secret_key.encode())

        with open(self.secret_key_file, "w") as secret_key_file:
            # key derivation salt is appended to the user's secret key after the '|' symbol
            secret_key_file.write(
                "|".join([encrypted_secret_key.hex(), secret_box.salt])
            )

        with open(self.public_key_file, "w") as public_key_file:
            public_key_file.write(public_key.hex())

    def get_secret(self, passwd: Optional[str] = None):
        """
        decrypt and return the secret key from disk using provided password
        """
        if not self.secret_key_file.exists():
            print(f"secret key does not exist in {self.keypair_dir}")

        with open(self.secret_key_file, "r") as secret_key_file:
            # the secret and the salt are seperated by a pipe i.e '|'
            # so partition to retrieve them
            encrypted_secret_key_bytes, _, salt = secret_key_file.read().partition("|")

        if passwd is not None:
            secret_box = KeySecretBox(passwd, salt)
            return secret_box.decrypt(encrypted_secret_key_bytes)

        ### else: prompt for password from user###

        # executes this function while there are attempts left
        def check_if_right_passwd(
            inputted_passwd: str, pyentry_instance: PynEntry, attempts_left: int
        ):
            """
            check if the password provided is correct to decrypt the secret key
            """
            secret_box = KeySecretBox(inputted_passwd, salt)
            try:
                return secret_box.decrypt(bytes.fromhex(encrypted_secret_key_bytes))
                #                 ^^^^^^^ will fail if user enters wrong password
            except CryptoError:
                # user entered wrong password and decryption failed,
                # update the descsription with the number of attempts and try again
                pyentry_instance.description = (
                    f"Wrong Password! Try Again {attempts_left} tries left"
                )
                return False

        # executes this when the user runs out of attempts
        def ran_out_of_attempts():
            stderr.write("Wrong Password!")
            exit()

        return AskUser.until(
            "Enter master password: ", check_if_right_passwd, ran_out_of_attempts
        )

    def get_public_key(self):
        """
        retrieves the public key from disk at the `self.pubkey_file` location
        """
        with open(self.public_key_file) as public_key_file:
            return bytes.fromhex(public_key_file.read())

    def change_passwd(
        self, new_passwd: Optional[str] = None, old_passwd: Optional[str] = None
    ):
        """
        change the master password using the secret key,
        and store it back in disk at `self.skey_key_file` location

        user will be prompted for value if new or old passwords are not specfied
        """
        # NOTE: this will ask for the password from user if the password was `None`
        secret_key_bytes = self.get_secret(old_passwd)
        new_passwd = (
            AskUser.and_confirm("Enter new master password: ")
            if new_passwd is None
            else new_passwd
        )

        secret_box = KeySecretBox(new_passwd)
        with open(self.secret_key_file, "w") as secret_key_file:
            secret_key_bytes = secret_key_file.write(
                # write the salt and encrypted secret key bytes seperated by a pipe symbol
                "|".join([secret_box.encrypt(secret_key_bytes).hex(), secret_box.salt])
            )


if __name__ == "__main__":
    key_pair = MasterKeyPair()
    key_pair.generate()
    key_pair.change_passwd()
