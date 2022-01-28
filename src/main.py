from master_keypair import MasterKeyPair
from pass_store import PasswdStore
from utils.user_prompt import AskPasswd
from utils.keyfiles import PublicKeyFile, SecretKeyFile, PasswdFile
import click


@click.group()
@click.option(
    "--password-store",
    "passwd_store_path",
    envvar=PasswdStore.PASSWD_STORE_DIR_ENV_VAR,
    type=click.Path(dir_okay=True, readable=True, writable=True),
    default=PasswdStore.DEFAULT_LOCATION,
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
def cli(
    ctx,
    passwd_store_path,
    public_key_path,
    secret_key_path,
):
    obj = {
        "MASTER_KEYPAIR": MasterKeyPair(
            SecretKeyFile(secret_key_path),
            PublicKeyFile(public_key_path),
        ),
        "PASSWD_STORE": PasswdStore(passwd_store_path),
    }
    ctx.obj = obj


@cli.command()
@click.argument("service_name")
@click.option("--allow-empty", is_flag=True, help="allow the password to be empty")
@click.option("-p", "--password", "passwd", required=False)
@click.pass_obj
def add(obj, service_name: str, allow_empty: bool, passwd):
    public_key = obj["MASTER_KEYPAIR"].get_public_key()
    if passwd == "-":
        passwd = click.get_text_stream("stdin").readline().rstrip()
    else:
        passwd = AskPasswd("Enter Password: ", allow_empty=allow_empty)  # type: ignore
    obj["PASSWD_STORE"].insert_passwd(service_name, passwd, public_key)  # type: ignore


@cli.command(name="get")
@click.argument("service_name", required=True)
@click.option(
    "--print/--no-print",
    "should_print",
    is_flag=True,
    help="print the result to console",
    default=False,
)
@click.option(
    "--copy/--no-copy",
    "should_copy",
    default=True,
    is_flag=True,
    help="copy the password to clipboard",
)
@click.pass_obj
def retrieve_password(obj, service_name, should_print, should_copy):
    get_secret_key_callback = obj["MASTER_KEYPAIR"].get_secret_key
    passwd = obj["PASSWD_STORE"].retrieve_passwd(service_name, get_secret_key_callback)
    if should_print:
        click.echo(passwd)
    if should_copy:
        pass


@cli.command(name="generate")
@click.pass_obj
def generate_keypair(obj):
    obj["MASTER_KEYPAIR"].generate_keypair()


@cli.command()
@click.argument("service_name")
@click.confirmation_option(prompt="Are you sure you want to remove the password?")
@click.pass_obj
def remove(obj, service_name: str):
    obj["PASSWD_STORE"].remove_passwd(service_name)


@cli.command(name="list")
@click.pass_obj
def list_keystore(obj):
    obj["PASSWD_STORE"].print_tree()
