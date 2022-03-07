from utils.serializible import SerializibleDataclass
from dataclasses import dataclass
import pytest


@dataclass
class SerializibleMessage(SerializibleDataclass):
    message: bytes
    other_info: str


serializible_instance = SerializibleMessage(
    b"this is a bytes message", "other info string"
)


@pytest.fixture(scope="module")
def serialized():
    return serializible_instance.serialize()


def test_desirialize(serialized):
    assert SerializibleMessage.deserialize(serialized) == serializible_instance
