import logging
from typing import Callable, Optional, Union

import click
from pynentry import PynEntry

from utils.keyfiles import PublicKeyFile, SecretKeyFile
from utils.crypto import SymmetricEncryptionBox, PublicKey, SecretKey
from utils.crypto import generate_keypair as nacl_generate_keypair
from utils.exceptions import Exit, DecryptionError
from utils.user_prompt import AskPasswd


logger = logging.getLogger(__name__)


class MasterKeyPair:
    DECRYPTION_FAILED_MESG = "fatal: Wrong Password! Decryption Failed"
    MASTER_PASSWD_PROMPT = "Enter master password: "
    NEW_MASTER_PASSWD_PROMPT = "Enter new master password: "
    PASSWD_CHANGED_MESG = "Password Changed"
    symmetric_encryptor = SymmetricEncryptionBox
    secret_key_cls = SecretKey
    public_key_cls = PublicKey
    keypair_generator = nacl_generate_keypair

    def __init__(self, secret_key_path: SecretKeyFile, public_key_path: PublicKeyFile):
        self.public_key_file = public_key_path
        self.secret_key_file = secret_key_path

    def generate_keypair(self, master_passwd: Union[str, Callable[..., str]], **kwargs):
        """generates an NaCl keypair and writes to disk at self.keypair_dir location
        the secret key is symmetrically encrypted with master password provided by the user.
        **kwargs are same as `SecretKeyFile.write_encrypted` or `PrivateKeyFile.write` in
        utils.keyfiles
        """

        if master_passwd == "":
            logger.debug("empty master password tried")
            raise Exit("fatal: master password can't be empty!")

        if callable(master_passwd):
            master_passwd = master_passwd()

        if not isinstance(master_passwd, str):
            raise TypeError(
                "master_passwd must be a str or a callable that returns a str"
            )

        if self.secret_key_file.path.exists() or self.public_key_file.path.exists():
            logger.warn(
                "KEYFILE EXISTS!, if keyfiles all the password in current pass store will be INVALIDATED!"
            )

        secret_key, public_key = MasterKeyPair.keypair_generator()

        encryption_box = MasterKeyPair.symmetric_encryptor(master_passwd)
        encrypted_secret_key = encryption_box.encrypt(bytes(secret_key))

        self.secret_key_file.write(encrypted_secret_key, **kwargs)
        self.public_key_file.write(public_key, **kwargs)

    def get_secret_key(self, master_passwd: Optional[str] = None):
        """
        decrypt and return the secret key from disk using provided password

        Args:
            passwd (str): master password to be used for decrypting the secret key
        """

        if master_passwd is not None:
            try:
                return self._try_decrypt_secret_key(master_passwd)
            except DecryptionError as e:
                logger.debug("decryption failed!", exc_info=e)
                raise Exit(self.DECRYPTION_FAILED_MESG)

        # this returns the secret key bytes if the user provides the right password
        # else it will abort
        return AskPasswd.until(
            self.MASTER_PASSWD_PROMPT,
            self._check_if_right_passwd,  # will return bytes if successful
            self.__ran_out_of_attempts,
        )

    def _try_decrypt_secret_key(self, passwd: str):
        """tries to decrypt the password otherwise CryptoError is raised"""
        try:
            encrypted_mesg = self.secret_key_file.read()
        except FileNotFoundError:
            raise Exit("fatal: secret key file not found")
        decrypted_bytes = MasterKeyPair.symmetric_encryptor.decrypt_message(
            passwd, encrypted_mesg
        )
        return MasterKeyPair.secret_key_cls(decrypted_bytes)

    # executes this callback while there are attempts left
    def _check_if_right_passwd(
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
            secret_key = self._try_decrypt_secret_key(inputted_passwd)
        except DecryptionError:
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
        else:
            logger.debug("password decrypt successful")
        return secret_key

    # execute this callback when attemtps are exhausted
    def __ran_out_of_attempts(self):
        logger.debug("decryption failed!, user ran out of attempts")
        raise Exit(self.DECRYPTION_FAILED_MESG)

    def change_master_password(
        self, new_passwd: Optional[str] = None, old_passwd: Optional[str] = None
    ):
        """
        change the master password used to encrypt the secret key,
        and store it back in disk at the same location

        user will be prompted for value if new or old passwords are not specfied
        """

        assert new_passwd != ""

        secret_key = self.get_secret_key(old_passwd)
        if new_passwd is None:
            new_passwd = AskPasswd.and_confirm(self.NEW_MASTER_PASSWD_PROMPT)

        symmetric_encryptor = self.symmetric_encryptor(new_passwd)
        encrypted_secret_key = symmetric_encryptor.encrypt(bytes(secret_key))

        self.secret_key_file.write(
            encrypted_secret_key,
            should_confirm_overwrite=False,
        )
        logger.info("password changed")

    def get_public_key(self):
        try:
            public_key_bytes = self.public_key_file.read()
        except FileNotFoundError:
            raise Exit("fatal: public key file not found")
        return MasterKeyPair.public_key_cls(public_key_bytes)
