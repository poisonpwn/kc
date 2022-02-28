import logging
from dataclasses import dataclass
from functools import partial
from time import sleep

import click

import utils.logging as kc_logging
import utils.misc as misc
from master_keypair import MasterKeyPair
from pass_store import PasswdStore
from utils.exceptions import Exit
from utils.keyfiles import PublicKeyFile, SecretKeyFile
from utils.user_prompt import AskPasswd


@dataclass
class KcStateObj:
    master_keypair: MasterKeyPair
    passwd_store: PasswdStore
    should_confirm: bool


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
@click.option(
    "-v",
    "--verbose",
    "is_verbose_mode",
    is_flag=True,
    default=False,
    help="provide verbose output",
)
@click.option(
    "--debug",
    "is_debug_mode",
    is_flag=True,
    default=False,
    help="print debug logs to console",
)
@click.option(
    "--yes",
    "is_confirmed",
    is_flag=True,
    default=False,
    help="reply yes to all confirmation messages",
)
@click.pass_context
@misc.exit_if_raised
def cli(
    ctx,
    passwd_store_path,
    public_key_path,
    secret_key_path,
    is_verbose_mode: bool,
    is_debug_mode: bool,
    is_confirmed: bool,
):
    logger = kc_logging.get_global_logger()
    if is_verbose_mode:
        logger.setLevel(logging.INFO)
    if is_debug_mode:
        logger.setLevel(logging.DEBUG)
    ctx.obj = KcStateObj(
        master_keypair=MasterKeyPair(
            SecretKeyFile(secret_key_path),
            PublicKeyFile(public_key_path),
        ),
        passwd_store=PasswdStore(passwd_store_path),
        should_confirm=not is_confirmed,
    )


@cli.command()
@click.argument("service_name")
@click.option("-p", "--password", "passwd", required=False)
@click.pass_obj
@misc.exit_if_raised
def add(obj: KcStateObj, service_name: str, passwd: str):
    public_key = obj.master_keypair.get_public_key()
    if passwd is None:
        passwd = AskPasswd("Enter Password: ")
    elif passwd == "-":
        passwd = click.get_text_stream("stdin").readline().rstrip()
    obj.passwd_store.insert_passwd(
        service_name,
        passwd,
        public_key,
        should_confirm_overwrite=obj.should_confirm,
    )


@cli.command(name="get")
@click.argument("service_name", required=True)
@click.option(
    "-p",
    "--print",
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
@click.option(
    "-t",
    "--timeout",
    "timeout_seconds",
    default=21,
    type=float,
    help="the no of seconds before the password gets wiped from clipboard.",
)
@click.pass_obj
@misc.exit_if_raised
def retrieve_password(
    obj: KcStateObj,
    service_name: str,
    should_print: bool,
    should_copy: bool,
    timeout_seconds: float,
):
    if should_copy and timeout_seconds <= 0:
        click.echo("fatal: timeout must be greater than 0", err=True)
        raise Exit()
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
        sleep(timeout_seconds)
        pyperclip.copy(ctx.clipboard_contents)


@cli.command(name="generate")
@click.pass_obj
@misc.exit_if_raised
def generate_keypair(obj: KcStateObj):
    master_passwd_getter = partial(AskPasswd, prompt="Enter master password: ")
    obj.master_keypair.generate_keypair(
        master_passwd=master_passwd_getter,
        should_confirm_overwrite=obj.should_confirm,
    )


@cli.command(name="remove")
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
