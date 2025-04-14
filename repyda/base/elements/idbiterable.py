from __future__ import annotations
from abc import ABC, abstractstaticmethod
from typing import Generator

class IDBIterable(ABC):
    @abstractstaticmethod
    def iter() -> Generator[IDBIterable, None, None]:
        raise NotImplementedError