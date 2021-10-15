from master_keypair import MasterKeyPair
from pass_store import PassStore
from utils.user_prompt import AskUser
from pathlib import Path
import click

key_store_dir = Path.home() / ".password-store"
master_key_pair = MasterKeyPair(
    Path.home() / ".keys/nacl_seckey.enc",
    Path.home() / ".keys/nacl_pubkey.pub",
)
keystore = PassStore(key_store_dir)


@click.command()
@click.argument("service_name", required=True)
@click.argument("--allow-empty", is_flag=True)
@click.argument("--stdin", "from_stdin", is_flag=True)
def insert_passwd(service_name: str, allow_empty: bool, from_stdin: bool):
    public_key = master_key_pair.get_public_key()
    if from_stdin:
        # TODO implement piping password from stdin
        raise NotImplementedError
    else:
        passwd = AskUser("Enter Password: ", allow_empty=allow_empty)  # type: ignore

    keystore.insert_passwd(service_name, passwd, public_key)  # type: ignore


@click.command()
@click.argument("service_name", required=True)
@click.option("--stdin", "master_password_from_stdin", is_flag=True)
def retrieve_password(service_name, master_passwd_from_stdin: bool = False):
    if master_passwd_from_stdin:
        # TODO implement passing master password from stdin
        raise NotImplementedError

    secret_key = master_key_pair.get_secret_key()
    return keystore.retrieve_passwd(service_name, secret_key)


@click.command("--stdin", "from_stdin", is_flag=True)
def generate_keypair(from_stdin: bool):
    master_passwd = None
    if from_stdin:
        # TODO implement passing password through stdin
        ## master_passwd = password from stdin
        pass
    master_key_pair.generate_keypair(master_passwd)


@click.command(name="list")
def list_keystore():
    PassStore.KEY_FILE_EXT = "gpg"
    keystore.print_tree()
