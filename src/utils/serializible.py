import bson
from dataclasses import asdict
from typing import Protocol


class Serializible(Protocol):
    def serialize(self):
        ...

    def deserialize(cls, serialized_bytes: bytes):
        ...


class SerializibleDataclass:
    def serialize(self):
        return bson.dumps(asdict(self))

    @classmethod
    def deserialize(cls, serialized_bytes: bytes):
        return cls(**bson.loads(serialized_bytes))


class SerializibleString(str):
    encoding = "utf-8"

    def serialize(self):
        return self.encode("utf-8")

    @classmethod
    def deserialize(cls, serialized_bytes: bytes):
        return serialized_bytes.decode(cls.encoding)
