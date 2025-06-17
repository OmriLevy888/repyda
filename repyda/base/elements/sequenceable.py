from __future__ import annotations
from typing import Optional, Generator

from abc import ABC, abstractmethod


class Sequenceable(ABC):
    @property
    @abstractmethod
    def next(self) -> Optional[Sequenceable]:
        raise NotImplementedError

    @property
    @abstractmethod
    def prev(self) -> Optional[Sequenceable]:
        raise NotImplementedError


class MultipleSequenceable(ABC):
    @property
    @abstractmethod
    def next(self) -> Generator[Sequenceable, None, None]:
        raise NotImplementedError

    @property
    @abstractmethod
    def prev(self) -> Generator[Sequenceable, None, None]:
        raise NotImplementedError
