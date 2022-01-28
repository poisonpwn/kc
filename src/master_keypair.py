from utils.user_prompt import AskPasswd
from utils.keyfiles import PublicKeyFile, SecretKeyFile
from nacl.public import PrivateKey
from nacl.exceptions import CryptoError
from pynentry import PynEntry
from utils.exceptions import EmptyError
from pathlib import Path
from typing import Optional
from sys import exit
import click


class MasterKeyPair:
    DECRYPTION_FAILED_MESG = "Wrong Password! Decryption Failed"
    MASTER_PASSWD_PROMPT = "Enter master password: "
    NEW_MASTER_PASSWD_PROMPT = "Enter new master password: "
    PASSWD_CHANGED_MESG = "Password Changed"

    def __init__(
        self,
        secret_keyfile: SecretKeyFile,
        public_keyfile: PublicKeyFile,
    ):
        self.secret_keyfile = secret_keyfile
        self.public_keyfile = public_keyfile

    def generate_keypair(
        self,
        master_passwd: Optional[str] = None,
        *,
        should_confirm_overwrite: bool = True,
    ):
        """generates an NaCl keypair and writes to disk at self.keypair_dir location
        the secret key is symmetrically encrypted with master password provided by the user
        """

        if master_passwd == "":
            raise EmptyError("master password can't be empty!")

        if master_passwd is None:
            master_passwd = AskPasswd.and_confirm(
                "Enter a master password: ", allow_empty=False
            )

        secret_key = PrivateKey.generate()
        public_key = secret_key.public_key

        self.secret_keyfile.write_encrypted(
            secret_key, master_passwd, should_confirm_overwrite=should_confirm_overwrite
        )
        self.public_keyfile.write(
            public_key, should_confirm_overwrite=should_confirm_overwrite
        )

    def get_secret_key(self, passwd: Optional[str] = None):
        """
        decrypt and return the secret key from disk using provided password

        Args:
            passwd (str): master password to be used for decrypting the secret key
        """

        if passwd is not None:
            try:
                return self.secret_keyfile.retrieve(passwd)
            except CryptoError:
                click.echo(self.DECRYPTION_FAILED_MESG, err=True)
                exit(1)

        ## this returns the secret key bytes if the user provides the right password
        ## else it will abort
        return AskPasswd.until(
            self.MASTER_PASSWD_PROMPT,
            self.__check_if_right_passwd,  # will return bytes if successful
            self.__ran_out_of_attempts,
        )

    # executes this callback while there are attempts left
    def __check_if_right_passwd(
        self,
        inputted_passwd: str,
        attempts_left: int,  # not including current attempt
        pyentry_instance: Optional[PynEntry],
    ):
        """check if password provided was right, if yes then return the decypted secret key bytes
        else return False, so that this function runs again, when passed as a closure
        """
        try:
            # if successful return the master secret key bytes out of all enclosing functions
            return self.secret_keyfile.retrieve(inputted_passwd)

        except CryptoError:
            # user entered wrong password and decryption failed,
            if attempts_left != 0:
                # current was not the last attempt, there are still attempts left.
                # so inform them of how many.
                wrong_passwd_mesg = (
                    f"Wrong Password! Try Again, {attempts_left} tries left"
                )

                if pyentry_instance is not None:
                    # update the descsription and try again
                    pyentry_instance.description = wrong_passwd_mesg
                else:
                    # if pynentry instance was none because user does not have pinentry
                    # just echo the message and try again.
                    click.echo(wrong_passwd_mesg, err=True)

            # return False to run this function again on next attempt
            return False

    # execute this callback when attemtps are exhausted
    def __ran_out_of_attempts(self):
        click.echo(self.DECRYPTION_FAILED_MESG, err=True)
        exit()

    def change_master_password(
        self, new_passwd: Optional[str] = None, old_passwd: Optional[str] = None
    ):
        """
        change the master password used to encrypt the secret key,
        and store it back in disk at the same location

        user will be prompted for value if new or old passwords are not specfied
        """

        assert new_passwd != ""

        plaintext_secret_key = self.get_secret_key(old_passwd)
        if new_passwd is None:
            new_passwd = AskPasswd.and_confirm(
                self.NEW_MASTER_PASSWD_PROMPT, allow_empty=False
            )

        self.secret_keyfile.write_encrypted(
            plaintext_secret_key,
            new_passwd,
            should_confirm_overwrite=False,
            should_print_write_mesg=False,
        )
        click.echo(self.PASSWD_CHANGED_MESG)

    def get_public_key(self):
        return self.public_keyfile.retrieve()


if __name__ == "__main__":
    key_pair = MasterKeyPair(
        SecretKeyFile(Path.home() / ".keys/nacl_seckey.enc"),
        PublicKeyFile(Path.home() / ".keys/nacl_pubkey.pub"),
    )
    key_pair.generate_keypair()
    key_pair.change_master_password()
