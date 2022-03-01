from utils.serializible import Serializible
from dataclasses import dataclass
import pytest


@dataclass
class SerializibleMessage(Serializible):
    message: bytes
    other_info: str


serializible_instance = SerializibleMessage(
    b"this is a bytes message", "other info string"
)


@pytest.fixture(scope="module")
def serialized():
    return serializible_instance.serialize()


def test_desirialize(serialized):
    assert SerializibleMessage.from_bytes(serialized) == serializible_instance
