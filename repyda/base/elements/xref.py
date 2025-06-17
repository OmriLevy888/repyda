from __future__ import annotations
from typing import Optional, TYPE_CHECKING
import typing
import enum

if TYPE_CHECKING:
    from .referencing import Referencing
    from .referenceable import Referenceable
    from repyda.base.types import CompoundTypeMember, Struct, Union
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
    ENUM            = 0x06
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

    def _handle_struct_or_union(self, tid: int) -> typing.Union[CompoundTypeMember, Struct, Union]:
        from repyda.base.types import Struct, Union, Enum
        import ida_typeinf
        
        try:
            return Struct(tid=tid)
        except ValueError:
            try:
                return Union(tid=tid)
            except ValueError:
                try:
                    enum = Enum(tid=tid)
                    edm_idx = enum.get_tinfo().get_edm_by_tid(None, tid)
                    if edm_idx == -1:
                        return enum
                    
                    return enum.get_member(None, index=edm_idx)
                except ValueError:
                    pass

        udm = ida_typeinf.udm_t()
        tif = ida_typeinf.tinfo_t()
        member_idx = tif.get_udm_by_tid(udm, tid)
        if member_idx < 0:
            raise RuntimeError('No matching class for source')

        if tif.is_struct():
            compound = Struct(tinfo=tif)
        elif tif.is_union():
            compound = Union(tinfo=tif)
        else:
            raise RuntimeError(f'Failed getting parent of field reference')
        
        return compound.get_member(index=member_idx)

    @property
    def source(self) -> Referencing:
        try:
            from .addressable import Addressable
            return Addressable.at(self._xref.frm)
        except ValueError:
            return self._handle_struct_or_union(self._xref.frm)

    @property
    def destination(self) -> Referenceable:
        try:
            from .addressable import Addressable
            return Addressable.at(self._xref.to)
        except ValueError:
            return self._handle_struct_or_union(self._xref.to)

    @property
    def exact_source(self) -> Referencing:
        try:
            from .addressable import Addressable
            return Addressable.exact_at(self._xref.frm)
        except ValueError:
            return self._handle_struct_or_union(self._xref.frm)

    @property
    def exact_destination(self) -> Referenceable:
        try:
            from .addressable import Addressable
            return Addressable.exact_at(self._xref.to)
        except ValueError:
            return self._handle_struct_or_union(self._xref.to)

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
        
        return self.source == other.source and \
            self.exact_source == other.exact_source and \
            self.destination == other.destination and \
            self.exact_destination == other.exact_destination and \
            self.type == other.type and \
            self.is_user_defined == other.is_user_defined

    def __repr__(self) -> str:
        type = self.type
        source = self.exact_source
        dest = self.exact_destination
        return f'Xref({type=}, {source=}, {dest=})'