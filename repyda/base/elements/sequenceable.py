from __future__ import annotations
from typing import Optional, Generator

from abc import ABC, abstractproperty


class Sequenceable(ABC):
    @abstractproperty
    def next(self) -> Optional[Sequenceable]:
        raise NotImplementedError

    @abstractproperty
    def prev(self) -> Optional[Sequenceable]:
        raise NotImplementedError


class MultipleSequenceable(ABC):
    @abstractproperty
    def next(self) -> Generator[Sequenceable, None, None]:
        raise NotImplementedError

    @abstractproperty
    def prev(self) -> Generator[Sequenceable, None, None]:
        raise NotImplementedError