from unittest.mock import ANY, patch

from passwd_store import PasswdStore
from utils.keyfiles import PasswdFile
from pathlib import Path

from tests.tools import random_chars
import pytest
from unittest.mock import Mock, call
import utils.exceptions


@pytest.fixture(scope="module")
def passwd_store(tmp_path_factory) -> PasswdStore:
    passwd_file_parent = tmp_path_factory.mktemp("test_passwd_file")
    passwd_file = PasswdStore(passwd_file_parent)
    return passwd_file


@pytest.fixture()
def passwd_file_mock():
    passwd_file = Mock(spec=PasswdFile)
    passwd_file.path = Mock(spec=Path)
    yield passwd_file


@patch("passwd_store.PasswdStore.assymetric_encryptor", autosepc=True)
@patch("passwd_store.PasswdFileFactory.get_passwd_file", wraps=lambda x: x)
def test_insert_passwd(
    passwd_file_factory_mock,
    assymetric_encryptor_mock,
    passwd_store: "PasswdStore",
    passwd_file_mock,
    public_key,
):
    encryption_box_instance = assymetric_encryptor_mock.return_value
    encryption_box_instance.encrypt.return_value = b"encrypted passwd bytes"

    passwd = random_chars(15)
    passwd_store.insert_passwd(
        passwd_file_mock, passwd, public_key
    )  # mocking passwd file by passing the service name as a mock itself,
    # the factory will return back this instance

    passwd_file_factory_mock.assert_called_with(passwd_file_mock)
    passwd_file_mock.write.assert_called_with(
        encryption_box_instance.encrypt(),
        overwrite_mesg=ANY,
        should_backup=False,
        should_confirm_overwrite=ANY,
    )


@patch("passwd_store.PasswdStore.assymetric_encryptor", autosepc=True)
@patch(
    "passwd_store.PasswdStore.passwd_file_factory_cls.get_passwd_file",
    wraps=lambda x: x,
)
def test_retrieve_passwd(
    passwd_file_factory_mock,
    assymetric_encryptor_mock,
    passwd_store: "PasswdStore",
    secret_key,
):
    passwd_file_mock = Mock(spec=PasswdFile)
    passwd_file_mock.read.return_value = b"read encrypted bytes"
    encryptor_instance = assymetric_encryptor_mock.return_value
    encryptor_instance.decrypt.return_value = b"decrypted bytes"

    decrypted_pass = passwd_store.retrieve_passwd(passwd_file_mock, secret_key)

    passwd_file_factory_mock.assert_called_with(passwd_file_mock)
    assymetric_encryptor_mock.assert_called_with(secret_key)
    encryptor_instance.decrypt.assert_called_with(passwd_file_mock.read())
    assert decrypted_pass == encryptor_instance.decrypt().decode("utf-8")


@patch(
    "passwd_store.PasswdStore.passwd_file_factory_cls.get_passwd_file",
    wraps=lambda x: x,
)
def test_remove_nonexistant_passwd(
    passwd_file_factory_mock, passwd_store: "PasswdStore", passwd_file_mock
):
    passwd_file_mock.remove.side_effect = FileNotFoundError()
    with pytest.raises(utils.exceptions.Exit):
        passwd_store.remove_passwd(passwd_file_mock)
    passwd_file_factory_mock.assert_called_with(passwd_file_mock)


@patch(
    "passwd_store.PasswdStore.passwd_file_factory_cls.get_passwd_file",
    wraps=lambda x: x,
)
def test_remove_passwd(
    passwd_file_factory_mock, passwd_store: "PasswdStore", passwd_file_mock
):
    passwd_store.remove_passwd(passwd_file_mock)
    passwd_file_mock.remove.assert_called()


alias_dest_mock = passwd_file_mock


@patch(
    "passwd_store.PasswdStore.passwd_file_factory_cls.get_passwd_file",
    wraps=lambda x: x,
)
def test_alias_nonexistant(
    passwd_file_factory_mock,
    passwd_store: "PasswdStore",
    passwd_file_mock,
    alias_dest_mock,
):
    passwd_file_mock.alias.side_effect = FileNotFoundError()
    with pytest.raises(utils.exceptions.Exit):
        passwd_store.alias(passwd_file_mock, alias_dest_mock)
    assert call(passwd_file_mock) in passwd_file_factory_mock.mock_calls
    assert call(alias_dest_mock) in passwd_file_factory_mock.mock_calls


@patch(
    "passwd_store.PasswdStore.passwd_file_factory_cls.get_passwd_file",
    wraps=lambda x: x,
)
def test_alias(
    passwd_file_factory_mock,
    passwd_store: "PasswdStore",
    passwd_file_mock,
    alias_dest_mock,
):
    passwd_store.alias(passwd_file_mock, alias_dest_mock)
    passwd_file_mock.alias.assert_called_with(alias_dest_mock.path)
    assert call(passwd_file_mock) in passwd_file_factory_mock.mock_calls
    assert call(alias_dest_mock) in passwd_file_factory_mock.mock_calls
