from __future__ import annotations
from typing import Optional, TYPE_CHECKING
import typing
import enum

if TYPE_CHECKING:
    from .referencing import Referencing
    from .referenceable import Referenceable
    from repyda.base.types import StructMember, Struct, UnionMember, Union
    from repyda.hexrays import ObjectAddress


class IDAXrefFlags(enum.Enum):
    USER_SPECIFIED  = 0x20
    TAIL            = 0x40
    BASE            = 0x80


class XrefType(enum.Enum):
    OFFSET          = 0x01
    WRITE           = 0x02
    READ            = 0x03
    TEXT            = 0x04
    INFORMATIONAL   = 0x05
    CALL_FAR        = 0x10
    CALL_NEAR       = 0x11
    JUMP_FAR        = 0x12
    JUMP_NEAR       = 0x13
    ORDINARY_FLOW   = 0x15


class Xref:
    def __init__(self, xref):
        self._xref = xref

    @property
    def type(self) -> XrefType:
        TYPE_MASK = 0x1f
        return XrefType(self._xref.type & TYPE_MASK)

    @property
    def is_user_defined(self) -> bool:
        return self._xref.type & IDAXrefFlags.USER_SPECIFIED.value != 0

    def _handle_struct_or_union(self, id: int) -> typing.Union[StructMember, Struct, UnionMember, Union]:
        import ida_struct
        from repyda.base.types import Struct, Union

        struct = ida_struct.get_struc(id)
        if struct is not None:
            name = ida_struct.get_struc_name(struct.id)
            if struct.is_union():
                return Union(name)
            else:
                return Struct(name)

        member = ida_struct.get_member_by_id(id)
        if member is None:
            raise RuntimeError('No matching class for source')

        full_name = ida_struct.get_member_fullname(id)
        struct_name, member_name = full_name.split('.')
        struct = ida_struct.get_member_struc(full_name)
        if struct.is_union():
            return Union(struct_name).get_member(member_name)

        return Struct(struct_name).get_member(member_name)

    @property
    def source(self) -> Referencing:
        try:
            from .addressable import Addressable
            return Addressable.at(self._xref.frm)
        except ValueError:
            # for structs and unions, this is reversed
            return Addressable.at(self._xref.to)

    @property
    def destination(self) -> Referenceable:
        try:
            from .addressable import Addressable
            return Addressable.at(self._xref.to)
        except ValueError:
            return self._handle_struct_or_union(self._xref.frm)

    @property
    def exact_source(self) -> Referencing:
        try:
            from .addressable import Addressable
            return Addressable.exact_at(self._xref.frm)
        except ValueError:
            # for structs and unions, this is reversed
            return Addressable.exact_at(self._xref.to)

    @property
    def exact_destination(self) -> Referenceable:
        try:
            from .addressable import Addressable
            return Addressable.exact_at(self._xref.to)
        except ValueError:
            return self._handle_struct_or_union(self._xref.frm)

    @property
    def decompiled_source_from(self) -> Optional[ObjectAddress]:
        from repyda.base import Function
        if not isinstance(self.source, Function):
            return None

        from repyda.hexrays import HexraysItem, ObjectAddress
        decompiled_func = self.source.decompiled_function
        cfunc = decompiled_func._decompiled_function
        root = decompiled_func.root._hexrays_item

        for insn in decompiled_func.ea_map[self._xref.frm]:
            parent = root.find_parent_of(insn).cinsn
            item = HexraysItem.from_citem(insn, cfunc, parent)
            if reference := item.match(ObjectAddress(ea=self._xref.to)):
                return reference

        raise RuntimeError(f'Failed to find reference in decompiled code [{self._xref=}]')

    @property
    def is_call(self) -> bool:
        return self.type in (XrefType.CALL_NEAR, XrefType.CALL_FAR)

    @property
    def is_jump(self) -> bool:
        return self.type in (XrefType.JUMP_NEAR, XrefType.JUMP_FAR)

    @property
    def is_read(self) -> bool:
        return self.is_call or self.is_jump or self.type == XrefType.READ

    def __eq__(self, other) -> bool:
        if not isinstance(other, Xref):
            raise NotImplementedError

        return self.source.ea == other.source.ea and \
            self.exact_source.ea == other.exact_source.ea and \
            self.destination.ea == other.destination.ea and \
            self.exact_destination.ea == other.exact_destination.ea and \
            self.type == other.type and \
            self.is_user_defined == other.is_user_defined

    def __repr__(self) -> str:
        type = self.type
        source = hex(self.exact_source.ea)
        dest = hex(self.exact_destination.ea)
        return f'Xref({type=}, {source=}, {dest=})'