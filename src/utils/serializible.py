import bson
from dataclasses import asdict
from typing import Protocol


class Serializible(Protocol):
    def serialize(self):
        ...

    @classmethod
    def deserialize(cls, serialized_bytes: bytes):
        ...


class SerializibleDataclass:
    def serialize(self):
        return bson.dumps(asdict(self))

    @classmethod
    def deserialize(cls, serialized_bytes: bytes):
        return cls(**bson.loads(serialized_bytes))
