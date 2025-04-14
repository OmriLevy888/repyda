from __future__ import annotations

from abc import ABC, abstractproperty, abstractstaticmethod
from typing import Generator, Optional, Iterable, Union

import ida_bytes
import idc
import ida_kernwin


class Color:
    @classmethod
    def from_bgr(cls, bgr: int) -> Color:
        r = bgr & 0x0000ff
        g = (bgr & 0x00ff00) >> 0x8
        b = (bgr & 0xff0000) >> 0x10
        return cls(r=r, g=g, b=b)

    def __init__(self,
                 rgb: Optional[int] = None,
                 *,
                 r: Optional[int] = None,
                 g: Optional[int] = None,
                 b: Optional[int] = None):
        if rgb is not None:
            self.r = (rgb & 0xff0000) >> 0x10
            self.g = (rgb & 0x00ff00) >> 0x8
            self.b = rgb & 0x0000ff
        else:
            if r is None or g is None or b is None:
                raise ValueError('Must either pass rgb or all of r, g and b parameters')

            self.r = r
            self.g = g
            self.b = b

    def to_bgr(self) -> int:
        return self.b << 0x10 | self.g << 0x8 | self.r


class Addressable(ABC):
    @abstractstaticmethod
    def exists_at(ea: int) -> bool:
        raise NotImplementedError

    @staticmethod
    def at(ea: int) -> Optional[Addressable]:
        from repyda.base.data import Data
        from repyda.base.functions import Function, Instruction

        if Function.exists_at(ea):
            return Function(ea)
        elif Instruction.exists_at(ea):
            return Instruction(ea)
        elif Data.exists_at(ea):
            return Data(ea)
        else:
            raise ValueError(f'Nothing defined at {ea}')

    @staticmethod
    def exact_at(ea: int) -> Optional[Addressable]:
        from repyda.base.data import Data
        from repyda.base.functions import Function, Block, Instruction

        if Instruction.exists_at(ea):
            return Instruction(ea)
        elif Block.exists_at(ea):
            return Block(ea)
        elif Function.exists_at(ea):
            return Function(ea)
        elif Data.exists_at(ea):
            return Data(ea)
        else:
            raise ValueError(f'Nothing defined at {ea}')

    def __str__(self) -> str:
        return hex(self.ea)

    def __eq__(self, other) -> bool:
        if other is None:
            return False

        if not isinstance(other, Addressable):
            raise NotImplementedError

        return self.ea == other.ea and self.__class__ is other.__class__

    def __ne__(self, other) -> bool:
        if other is None:
            return True

        if not isinstance(other, Addressable):
            raise NotImplementedError

        return self.ea != other.ea

    @abstractproperty
    def ea(self) -> int:
        raise NotImplementedError

    @abstractproperty
    def flags(self) -> int:
        raise NotImplementedError

    @abstractproperty
    def size(self) -> int:
        raise NotImplementedError

    def __contains__(self, ea: Union[int, Addressable]) -> bool:
        if isinstance(ea, Addressable):
            ea = ea.ea

        return ea >= self.ea and ea < self.ea + self.size

    @property
    def bytes(self) -> Generator[int, int, int]:
        return (ida_bytes.get_wide_byte(i) for i in range(self.ea, idc.get_item_end(self.ea)))

    @bytes.setter
    def bytes(self, value: Optional[Iterable[int]]):
        self._bytes_setter(value)

    def _bytes_setter(self, value: Optional[Iterable[int]]):
        raise NotImplementedError

    @bytes.deleter
    def bytes(self):
        self.bytes = None

    @property
    def original_bytes(self) -> Generator[int, int, int]:
        return (ida_bytes.get_original_byte(i) for i in range(self.ea, idc.get_item_end(self.ea)))

    @property
    def color(self) -> Color:
        return Color.from_bgr(idc.get_color(self.ea, idc.CIC_ITEM))

    @color.setter
    def color(self, value: Union[Color, int]):
        if not isinstance(value, Color):
            value = Color(value)

        idc.set_color(self.ea, idc.CIC_ITEM, value.to_bgr())

    @color.deleter
    def color(self):
        raise NotImplementedError

    def move_cursor_to(self):
        ida_kernwin.jumpto(self.ea)
