from __future__ import annotations
from typing import Optional, Generator, Any


import idc
import idautils
import ida_bytes
import ida_name
import ida_kernwin

from repyda.base.elements import Addressable, TreeType, \
    Referenceable, Referencing, Xref, Nameable


class Address(Addressable, Nameable, Referenceable, Referencing):
    def __init__(self, ea: Optional[int] = None, name: Optional[str] = None):
        if ea is None:
            if name is not None:
                ea = ida_name.get_name_ea(idc.BADADDR, name)
            else:
                ea = ida_kernwin.get_screen_ea()

        if not Address.exists_at(ea):
            raise ValueError(f'Bad address {hex(ea)}')

        self._ea = ea

    @property
    def ea(self) -> int:
        return self._ea

    @property
    def flags(self) -> int:
        return idc.get_full_flags(self.ea)

    @property
    def size(self) -> int:
        return idc.get_item_size(self.ea)
    
    @property
    def name(self) -> str:
        return ida_name.get_name(self.ea)

    @name.setter
    def name(self, value: Optional[str]):
        if value is None:
            value = ''

        if value == self.name:
            return

        ida_name.set_name(self.ea, value, idc.SN_CHECK)

    @name.deleter
    def name(self):
        self.name = None

    @property
    def is_auto_name(self) -> bool:
        return ida_bytes.has_auto_name(self.flags)

    @property
    def is_user_defined_name(self) -> bool:
        return ida_bytes.has_user_name(self.flags)

    def _default_tree_type(self) -> TreeType:
        return TreeType.Names

    def _is_valid_tree_type(self, type: TreeType) -> bool:
        return type == self._default_tree_type()

    @property
    def references(self) -> Generator[Xref, Xref, Xref]:
        for xref in idautils.XrefsTo(self.ea):
            yield Xref(xref)

    @property
    def all_references(self) -> Generator[Xref, Xref, Xref]:
        for ea in range(self.ea, self.ea + self.size):
            for xref in idautils.XrefsTo(ea):
                yield Xref(xref)

    @property
    def referencing(self) -> Generator[Xref, Xref, Xref]:
        for xref in idautils.XrefsFrom(self.ea):
            yield Xref(xref)

    def __eq__(self, other: Any) -> bool:
        return self.ea == other.ea

    def __str__(self) -> str:
        return f'{hex(self.ea)}: {self.name}'

    def __repr__(self) -> str:
        return f'{hex(self.ea)}: {self.name}'