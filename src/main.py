from dataclasses import dataclass
from functools import partial
from time import sleep

import click

import utils.misc as misc
from master_keypair import MasterKeyPair
from pass_store import PasswdStore
from utils.keyfiles import PublicKeyFile, SecretKeyFile
from utils.user_prompt import AskPasswd


@dataclass
class KcStateObj:
    master_keypair: MasterKeyPair
    passwd_store: PasswdStore


@click.group()
@click.option(
    "--password-store",
    "passwd_store_path",
    type=click.Path(dir_okay=True, readable=True, writable=True),
    default=partial(
        misc.get_default_value_from_env,
        env_var=PasswdStore.PASSWD_STORE_DIR_ENV_VAR,
        default=PasswdStore.DEFAULT_LOCATION,
    ),
)
@click.option(
    "--secret-key",
    "secret_key_path",
    type=click.Path(file_okay=True, readable=True),
    default=SecretKeyFile.DEFAULT_LOCATION,
)
@click.option(
    "--public_key",
    "public_key_path",
    type=click.Path(file_okay=True, readable=True),
    default=PublicKeyFile.DEFAULT_LOCATION,
)
@click.pass_context
@misc.exit_if_raised
def cli(
    ctx,
    passwd_store_path,
    public_key_path,
    secret_key_path,
):
    ctx.obj = KcStateObj(
        master_keypair=MasterKeyPair(
            SecretKeyFile(secret_key_path),
            PublicKeyFile(public_key_path),
        ),
        passwd_store=PasswdStore(passwd_store_path),
    )


@cli.command()
@click.argument("service_name")
@click.option("--allow-empty", is_flag=True, help="allow the password to be empty")
@click.option("-p", "--password", "passwd", required=False)
@click.pass_obj
@misc.exit_if_raised
def add(obj: KcStateObj, service_name: str, allow_empty: bool, passwd: str):
    public_key = obj.master_keypair.get_public_key()
    if passwd is None:
        passwd = AskPasswd("Enter Password: ", allow_empty=allow_empty)  # type: ignore
    elif passwd == "-":
        passwd = click.get_text_stream("stdin").readline().rstrip()
    obj.passwd_store.insert_passwd(service_name, passwd, public_key)  # type: ignore


@cli.command(name="get")
@click.argument("service_name", required=True)
@click.option(
    "-p",
    "--print/--no-print",
    "should_print",
    is_flag=True,
    help="print the result to console",
    default=False,
)
@click.option(
    "-c",
    "--copy/--no-copy",
    "should_copy",
    default=True,
    is_flag=True,
    help="copy the password to clipboard",
)
@click.pass_obj
@misc.exit_if_raised
def retrieve_password(
    obj: KcStateObj, service_name: str, should_print: bool, should_copy: bool
):
    get_secret_key_callback = obj.master_keypair.get_secret_key
    passwd = obj.passwd_store.retrieve_passwd(service_name, get_secret_key_callback)
    if should_print:
        click.echo(passwd)
    if not should_copy:
        return

    import pyperclip
    from daemon import DaemonContext

    clipboard_contents = pyperclip.paste()
    daemon_ctx = DaemonContext(detach_process=True)
    daemon_ctx.passwd = passwd
    daemon_ctx.clipboard_contents = (
        clipboard_contents if clipboard_contents is not None else ""
    )
    with daemon_ctx as ctx:
        pyperclip.copy(ctx.passwd)
        sleep(21)
        pyperclip.copy(ctx.clipboard_contents)


@cli.command(name="generate")
@click.pass_obj
@misc.exit_if_raised
def generate_keypair(obj: KcStateObj):
    obj.master_keypair.generate_keypair()


@cli.command()
@click.argument("service_name")
@click.confirmation_option(prompt="Are you sure you want to remove the password?")
@click.pass_obj
@misc.exit_if_raised
def remove(obj: KcStateObj, service_name: str):
    obj.passwd_store.remove_passwd(service_name)


@cli.command(name="list")
@click.pass_obj
@misc.exit_if_raised
def list_keystore(obj: KcStateObj):
    obj.passwd_store.print_tree()


@cli.command("alias")
@click.argument("source_service_name")
@click.argument("destination_service_name")
@click.pass_obj
@misc.exit_if_raised
def alias(obj: KcStateObj, source_service_name: str, destination_service_name: str):
    obj.passwd_store.alias(source_service_name, destination_service_name)
