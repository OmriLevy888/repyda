from __future__ import annotations
from typing import Optional, TYPE_CHECKING

from abc import ABC, abstractmethod

if TYPE_CHECKING:
    from repyda.base.types.basic_types import Type


class Typed(ABC):
    @property
    def type(self) -> Type:
        user_type = self._get_type()
        if user_type is not None:
            return user_type

        return self.guessed_type

    @type.setter
    def type(self, value: Optional[Type]):
        if isinstance(value, str):
            from repyda.base.types.basic_types import Type
            value = Type.from_c(value)

        if value == self.type:
            return

        self._set_type(value)

    @type.deleter
    def type(self):
        self.type = None

    @abstractmethod
    def _get_type(self) -> Optional[Type]:
        raise NotImplementedError

    @abstractmethod
    def _set_type(self, value: Optional[Type]):
        raise NotImplementedError

    @property
    @abstractmethod
    def guessed_type(self) -> Type:
        pass

    @property
    def has_user_defined_type(self) -> bool:
        return self._get_type() is not None
