from typing import Generator
from abc import ABC, abstractproperty

from .xref import Xref


class Referencing(ABC):
    @abstractproperty
    def referencing(self) -> Generator[Xref, None, None]:
        raise NotImplementedError