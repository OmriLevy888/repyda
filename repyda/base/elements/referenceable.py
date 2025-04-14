from typing import Generator
from abc import ABC, abstractproperty

from .xref import Xref


class Referenceable(ABC):
    @abstractproperty
    def references(self) -> Generator[Xref, None, None]:
        raise NotImplementedError

    @abstractproperty
    def all_references(self) -> Generator[Xref, None, None]:
        raise NotImplementedError
