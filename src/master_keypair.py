from utils.crypto import KeySecretBox, PassEncryptedMessage
from utils.user_prompt import AskUser
from utils.exceptions import InvalidFilenameErr, SameKeyFileError, EmptyError
from nacl.public import PrivateKey, PublicKey
from nacl.exceptions import CryptoError
from pynentry import PynEntry
from pathlib import Path
from typing import Optional
from sys import exit
import click


class MasterKeyPair:
    SECKEY_FILE_EXT = ".enc"
    PUBKEY_FILE_EXT = ".pub"

    def __init__(
        # all of these defaults to None because
        # argparse returns None when option is not specified
        self,
        secret_key_file: Path,
        public_key_file: Path,
    ):
        self.secret_key_file = secret_key_file.absolute()
        self.public_key_file = public_key_file.absolute()

        if self.secret_key_file.parent != self.public_key_file.parent:
            raise InvalidFilenameErr("keyfiles must be under the same directory.")

        if secret_key_file.name == "" or public_key_file.name == "":
            raise EmptyError("keyfile name's can't be empty!.")

        if secret_key_file.suffix != MasterKeyPair.SECKEY_FILE_EXT:
            raise InvalidFilenameErr(
                f"secret key file name has to have extension {MasterKeyPair.SECKEY_FILE_EXT}"
            )

        if public_key_file.suffix != MasterKeyPair.PUBKEY_FILE_EXT:
            raise InvalidFilenameErr(
                f"secret key file name has to have extension {MasterKeyPair.PUBKEY_FILE_EXT}"
            )

        if self.secret_key_file == self.public_key_file:
            raise SameKeyFileError(
                self.secret_key_file,
                "public key and secret key files can't be the same.",
            )

        if not self.keypair_dir.exists():
            self.keypair_dir.mkdir()

    @property
    def keypair_dir(self):
        return self.secret_key_file.parent

    def generate_keypair(self, master_passwd: Optional[str] = None):
        """
        generates an NaCL keypair and writes to disk at self.keypair_dir location
        the secret key is symmetrically encrypted with master password provided by the user
        """

        if self.secret_key_file.exists():
            prompt_message = f"file {self.secret_key_file.name} ALREADY Exists in {self.keypair_dir}! Overwrite?"

            try:
                click.confirm(
                    prompt_message, default=False, show_default=True, abort=True
                )
            except click.exceptions.Abort:
                print("operation cancelled! Aborting!")
                exit()

        if master_passwd is None:
            master_passwd = AskUser.and_confirm(
                "Enter a master password: ", allow_empty=False
            )

        assert master_passwd != ""

        secret_key = PrivateKey.generate()
        public_key = secret_key.public_key

        # create a secret box with the password and use that to encrypt the secret key
        secret_box = KeySecretBox(master_passwd)
        encrypted_secret_key = secret_box.encrypt(secret_key.encode())

        with open(self.secret_key_file, "wb") as secret_key_file:
            # key derivation salt is appended to the user's secret key after the '|' symbol
            secret_key_file.write(bytes(encrypted_secret_key))

        try:
            ## this should never run, this is just in case python's file equality
            # checking messes up earlier which it shouldn't
            if self.secret_key_file.samefile(self.public_key_file):
                self.public_key_file = self.public_key_file.with_name(
                    self.public_key_file.name + "__PUBLIC_KEY"
                )
                raise SameKeyFileError(
                    self.secret_key_file,
                    "public and private keyfiles can't be the same",
                )
        finally:
            with open(self.public_key_file, "w") as public_key_file:
                public_key_file.write(public_key.encode().hex())

    def get_secret_key(self, passwd: Optional[str] = None):
        """
        decrypt and return the secret key from disk using provided password

        Args:
            passwd (str): master password to be used for decrypting the secret key
        """
        if not self.secret_key_file.exists():
            click.echo(f"secret key does not exist in {self.keypair_dir}!", err=True)
            exit()

        with open(self.secret_key_file, "rb") as secret_key_file:
            # the secret and the salt are seperated by a pipe i.e '|'
            # so partition to retrieve them
            encrypted_secret_key = PassEncryptedMessage.from_bytes(
                secret_key_file.read()
            )

        if passwd is not None:
            return PrivateKey(
                KeySecretBox.decrypt_message(encrypted_secret_key, passwd)
            )

        ### else: prompt for password from user###

        # executes this function while there are attempts left
        def check_if_right_passwd(
            inputted_passwd: str, pyentry_instance: PynEntry, attempts_left: int
        ):
            """
            check if password provided was right, if yes then return the decypted secret key bytes
            else return False, so that this function runs again, when passed as a closure
            """
            try:
                # if successful return the master secret key bytes
                return KeySecretBox.decrypt_message(
                    encrypted_secret_key, inputted_passwd
                )
                #                 ^^^^^^^ will fail if user enters wrong password
            except CryptoError:
                # user entered wrong password and decryption failed,
                # update the descsription with the number of attempts and try again
                pyentry_instance.description = (
                    f"Wrong Password! Try Again {attempts_left} tries left"
                )
                # return False to run this function again on next attempt
                return False

        # executes this when the user runs out of attempts
        def ran_out_of_attempts():
            click.echo("Wrong Password!", err=True)
            exit()

        return PrivateKey(
            ## this returns the secret key bytes if the user provides the right password
            ## else it will abort
            AskUser.until(
                "Enter master password: ",
                check_if_right_passwd,
                ran_out_of_attempts,
            )
        )

    def get_public_key(self):
        """
        retrieves the public key from disk at the `self.pubkey_file` location
        """
        if not self.public_key_file.exists():
            click.echo(f"can't find public key in {self.keypair_dir}")
            exit()

        with open(self.public_key_file) as public_key_file:
            return PublicKey(bytes.fromhex(public_key_file.read()))

    def change_master_password(
        self, new_passwd: Optional[str] = None, old_passwd: Optional[str] = None
    ):
        """
        change the master password used to encrypt the secret key,
        and store it back in disk at `self.skey_key_file` location

        user will be prompted for value if new or old passwords are not specfied
        """
        assert new_passwd != ""
        secret_key = self.get_secret_key(old_passwd)
        if new_passwd is None:
            new_passwd = AskUser.and_confirm(
                "Enter new master password: ", allow_empty=False
            )

        secret_box = KeySecretBox(new_passwd)
        with open(self.secret_key_file, "w") as secret_key_file:
            secret_key = secret_key_file.write(
                # write the salt and encrypted secret key bytes seperated by a pipe symbol
                "|".join(
                    [secret_box.encrypt(secret_key.encode()).hex(), secret_box.salt]
                )
            )


# if __name__ == "__main__":
# key_pair = MasterKeyPair()
# key_pair.generate_keypair()
# key_pair.change_master_password()
