from typing import Generator
from abc import ABC, abstractmethod

from .xref import Xref


class Referenceable(ABC):
    @property
    @abstractmethod
    def references(self) -> Generator[Xref, None, None]:
        raise NotImplementedError

    @property
    @abstractmethod
    def all_references(self) -> Generator[Xref, None, None]:
        raise NotImplementedError
