from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Generator

class IDBIterable(ABC):
    @staticmethod
    @abstractmethod
    def iter() -> Generator[IDBIterable, None, None]:
        raise NotImplementedError
