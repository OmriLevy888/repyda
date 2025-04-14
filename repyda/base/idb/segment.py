from __future__ import annotations
from typing import Generator

import idaapi
import idc
import ida_segment
import enum

from repyda.base.elements import IDBIterable


class SegmentClass(enum.Enum):
    CODE    = "CODE"
    DATA    = "DATA"
    CONST   = "CONST"
    STACK   = "STACK"
    BSS     = "BSS"
    XTRN    = "XTRN"
    COMM    = "COMM"
    ABS     = "ABS"


class SegmentPermissions(enum.IntFlag):
    EXEC    = 1
    WRITE   = 2
    READ    = 4


class Segment(IDBIterable):
    def __init__(self, start_ea: int):
        self._segment = idaapi.getseg(start_ea)

    def __eq__(self, other: Segment) -> bool:
        if not isinstance(other, Segment):
            raise NotImplementedError
        return self.name == other.name

    def __ne__(self, other: Segment) -> bool:
        if not isinstance(other, Segment):
            raise NotImplementedError
        return self.name != other.name

    @property
    def iter(self) -> Generator[Segment, Segment, Segment]:
        raise NotImplementedError

    @property
    def name(self) -> str:
        return idc.get_segm_name(self.start_ea)

    @name.setter
    def name(self, value: str):
        if value == self.name:
            return

        ida_segment.set_segm_name(self._segment, value)

    @property
    def start_ea(self) -> int:
        return self._segment.start_ea

    @start_ea.setter
    def start_ea(self, value: int):
        ida_segment.set_segm_start(self.start_ea, value, 0)

    @property
    def end_ea(self) -> int:
        return self._segment.end_ea

    @end_ea.setter
    def end_ea(self, value: int):
        ida_segment.set_segm_end(self.start_ea, value, 0)

    @property
    def permissions(self) -> SegmentPermissions:
        formatted_perms = 0
        if self._segment.perm & ida_segment.SEGPERM_READ:
            formatted_perms |= SegmentPermissions.READ
        if self._segment.perm & ida_segment.SEGPERM_WRITE:
            formatted_perms |= SegmentPermissions.WRITE
        if self._segment.perm & ida_segment.SEGPERM_EXEC:
            formatted_perms |= SegmentPermissions.EXEC
        return formatted_perms

    @permissions.setter
    def permissions(self, value: SegmentPermissions):
        formatted_perms = 0
        if value & SegmentPermissions.READ:
            formatted_perms |= ida_segment.SEGPERM_READ
        if value & SegmentPermissions.WRITE:
            formatted_perms |= ida_segment.SEGPERM_WRITE
        if value & SegmentPermissions.EXEC:
            formatted_perms |= ida_segment.SEGPERM_EXEC
        self._segment.perm = formatted_perms

    def __str__(self):
        addresses = f'{hex(self.start_ea)}..{hex(self.end_ea)}'
        return f'{self.__class__.__name__}<name={self.name}, range={addresses}, permissions={self.permissions}>'