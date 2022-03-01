import bson
from dataclasses import asdict
from abc import ABC


serializer = bson.dumps
deserializer = bson.loads


class Serializible(ABC):
    def serialize(self):
        return serializer(asdict(self))

    @classmethod
    def from_bytes(cls, bytes):
        return cls(**deserializer(bytes))
