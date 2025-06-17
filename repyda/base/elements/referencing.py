from typing import Generator
from abc import ABC, abstractmethod

from .xref import Xref


class Referencing(ABC):
    @property
    @abstractmethod
    def referencing(self) -> Generator[Xref, None, None]:
        raise NotImplementedError
