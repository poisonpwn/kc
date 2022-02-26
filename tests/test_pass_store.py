import pytest
from typing import Tuple
from pass_store import PasswdStore
from utils.keyfiles import PasswdFile
from dataclasses import dataclass
import utils.exceptions as exceptions
from pathlib import Path


@pytest.fixture(scope="module")
def pass_store(tmp_path_factory) -> PasswdStore:
    pass_store_parent = tmp_path_factory.mktemp("test_pass_store")
    pass_store = PasswdStore(pass_store_parent)
    return pass_store


passwd = "test_password"


@dataclass
class ServiceInfo:
    service_name: str
    passfile_path: Path


service_name_pairs = [
    ("test_service_name_0", "test_service_name_0"),
    (
        "outer_folder_1/test_inner_service_name_1",
        "outer_folder_1/test_inner_service_name_1",
    ),
    ("outer_folder_2/../../test_inner_service_name_2", "test_inner_service_name_2"),
    ("/../../test_inner_service_name_3", "test_inner_service_name_3"),
]


@pytest.fixture(autouse=True, params=service_name_pairs)
def service_info(pass_store: "PasswdStore", request):
    service_name, resolved_service_name = request.param
    return ServiceInfo(
        service_name,
        (pass_store.passwd_store_path / resolved_service_name).with_suffix(
            PasswdFile.PASSWD_FILE_EXT
        ),
    )


@pytest.fixture()
def tmp_alias_paths(pass_store: "PasswdStore"):
    target_service_names = (
        "test_source_name",  # source
        "not_there_test_dest_name",  # dest
    )
    target_paths = [
        (pass_store.passwd_store_path / service_name).with_suffix(
            PasswdFile.PASSWD_FILE_EXT
        )
        for service_name in target_service_names
    ]
    yield tuple(ServiceInfo(*pair) for pair in zip(target_service_names, target_paths))
    for path in target_paths:
        path.unlink(missing_ok=True)


@pytest.mark.dependency(name="insert passwd")
def test_insert_passwd(
    service_info: ServiceInfo, pass_store: "PasswdStore", public_key
):
    assert not service_info.passfile_path.exists()
    pass_store.insert_passwd(service_info.service_name, passwd, public_key)
    assert service_info.passfile_path.exists()


@pytest.mark.dependency(depends=["insert passwd"])
@pytest.mark.order(after="test_insert_passwd")
def test_retrieve_passwd(
    service_info: ServiceInfo, pass_store: "PasswdStore", secret_key
):
    get_secret_key_callback = lambda: secret_key
    decrypted_pass = pass_store.retrieve_passwd(
        service_info.service_name, get_secret_key_callback
    )
    assert decrypted_pass == passwd


def test_alias_nonexistant_service_name(
    pass_store: "PasswdStore", tmp_alias_paths: Tuple[ServiceInfo, ServiceInfo]
):
    source, dest = tmp_alias_paths
    assert not source.passfile_path.exists()
    assert not dest.passfile_path.exists()
    with pytest.raises(exceptions.Exit):
        pass_store.alias(
            source.service_name, dest.service_name
        )  # it should handle error message and exit
    assert not dest.passfile_path.exists()


def test_alias(
    service_info: ServiceInfo,
    tmp_alias_paths: Tuple[ServiceInfo, ServiceInfo],
    pass_store: "PasswdStore",
):
    _, dest = tmp_alias_paths
    assert service_info.passfile_path.exists()
    assert not dest.passfile_path.exists()
    pass_store.alias(service_info.service_name, dest.service_name)
    assert dest.passfile_path.exists()
    assert dest.passfile_path.is_symlink()
    assert dest.passfile_path.readlink() == service_info.passfile_path
