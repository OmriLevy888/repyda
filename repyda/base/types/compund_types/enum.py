from __future__ import annotations
from typing import Optional, Generator

from ..basic_types import Type
from repyda.base.elements import IDBIterable, Commentable, Referenceable, TreeType, Nameable, Xref

import ida_typeinf
import idautils


class EnumMember(Commentable, Referenceable, Nameable, IDBIterable):
    @staticmethod
    def iter() -> Generator[EnumMember, None, None]:
        for enum in Enum.iter():
            yield from enum.iter_members()

    def __init__(self, idx: int, enum: Enum):
        self._idx = idx
        self._enum = enum

    @property
    def _edm(self) -> ida_typeinf.edm_t:
        edm = ida_typeinf.edm_t()
        error = self.enum._tinfo.get_edm(edm, self._idx)
        if error != 0:
            raise RuntimeError(f'Failed to get edm for {self._enum}@{self._idx}: {ida_typeinf.tinfo_errstr(error)}')
        
        return edm

    @property
    def enum(self) -> Enum:
        return self._enum

    @property
    def comment(self) -> Optional[str]:
        return self._edm.cmt

    @comment.setter
    def comment(self, value: Optional[str]):
        if value is None:
            value = ''
        
        error = self._enum._tinfo.set_edm_cmt(self._idx, value)
        if error != 0:
            raise RuntimeError(f'Failed to set comment for {self.enum}::{self.name}: {ida_typeinf.tinfo_errstr(error)}')

    @comment.deleter
    def comment(self):
        self.comment = None

    @property
    def repeatable_comment(self) -> Optional[str]:
        return self._edm.cmt

    @repeatable_comment.setter
    def repeatable_comment(self, value: Optional[str]):
        if value is None:
            value = ''

        error = self._enum._tinfo.set_edm_cmt(self._idx, value)
        if error != 0:
            raise RuntimeError(f'Failed to set comment for {self.enum}::{self.name}: {ida_typeinf.tinfo_errstr(error)}')

    @repeatable_comment.deleter
    def repeatable_comment(self):
        self.repeatable_comment = None

    @property
    def name(self) -> str:
        return self._edm.name

    @name.setter
    def name(self, value: Optional[str]):
        if value is None:
            raise NotImplementedError('TODO')

        error = self._enum._tinfo.rename_edm(self._idx, value)
        if error != 0:
            raise RuntimeError(f'Failed to rename {self.enum}::{self.name} to {value}: {ida_typeinf.tinfo_errstr(error)}')

    @name.deleter
    def name(self):
        self.name = None

    @property
    def is_auto_name(self) -> bool:
        raise NotImplementedError

    @property
    def is_user_defined_name(self) -> bool:
        raise NotImplementedError

    def _default_tree_type(self) -> TreeType:
        raise NotImplementedError('Not implemented for EnumMember')

    def _is_valid_tree_type(self, type: TreeType) -> bool:
        raise NotImplementedError('Not implemented for EnumMember')

    @property
    def references(self) -> Generator[Xref, None, None]:
        yield from map(Xref, idautils.XrefsTo(self._edm.get_tid()))

    @property
    def all_references(self) -> Generator[Xref, None, None]:
        raise NotImplementedError

    @property
    def value(self) -> int:
        return self._edm.value

    @value.setter
    def value(self, value: int):
        # TODO: support bitmask
        # error = self._enum._tinfo.edit_edm(self._idx, value, self.bit_mask)
        error = self._enum._tinfo.edit_edm(self._idx, value, 0)
        if error != 0:
            raise RuntimeError(f'Failed to set value of {self.enum}::{self.name}: {ida_typeinf.tinfo_errstr(error)}')

    @property
    def bit_mask(self) -> int:
        # TODO: implement
        pass
    
    @bit_mask.setter
    def bit_mask(self, value: int):
        error = self._enum._tinfo.edit_edm(self._idx, self.value, value)
        if error != 0:
            raise RuntimeError(f'Failed to set value of {self.enum}::{self.name}: {ida_typeinf.tinfo_errstr(error)}')

    def delete(self):
        error = self._enum._tinfo.del_edm(self._idx)
        if error != 0:
            raise RuntimeError(f'Failed to delete {self.enum}::{self.name}: {ida_typeinf.tinfo_errstr(error)}')

    def __repr__(self) -> str:
        return f'{self.enum.base_type} {self.enum.name}::{self.name} = {self.value}'
    
    def __str__(self) -> str:
        return f'{self.enum.base_type} {self.enum.name}::{self.name} = {self.value}'


class Enum(Type, Nameable, Commentable, IDBIterable):
    @staticmethod
    def iter() -> Generator[Enum, None, None]:
        for ordinal, tid, name in idautils.Structs():
            try:
                yield Enum(tid=tid)
            except ValueError:
                continue
            
    @staticmethod
    def exists(name: str) -> bool:
        try:
            Enum(name)
            return True
        except ValueError:
            return False
    
    @classmethod
    def create_empty(cls, name: str):
        tif = ida_typeinf.tinfo_t()
        edm = ida_typeinf.enum_type_data_t()
        if not tif.create_enum(edm):
            raise RuntimeError(f'Could not create enum {name}')
        
        error = tif.set_named_type(None, name)
        if error != 0:
            raise RuntimeError(f'Failed to name enum {name}: {ida_typeinf.tinfo_errstr(error)}')
        
        return Enum(tinfo=tif)

    def __init__(self,
                 name: Optional[str] = None,
                 *,
                 tid: Optional[int] = None,
                 tinfo: Optional[ida_typeinf.tinfo_t] = None):
        if tid is not None:
            tinfo = ida_typeinf.tinfo_t()
            if not tinfo.get_type_by_tid(tid):
                raise ValueError(f'Failed to get type {tid}')
        elif name is not None:
            if name is not None and name.strip().startswith('enum '):
                name = name.strip().split(' ', maxsplit=1)[1]
                
            tinfo = ida_typeinf.tinfo_t()
            if not tinfo.get_named_type(name):
                raise ValueError(f'Failed to get type {name}')
        elif tinfo is None:
            raise ValueError('Missing type identifier')
        
        super().__init__(tinfo=tinfo)

    @property
    def name(self) -> str:
        return self._tinfo.get_type_name()

    @name.setter
    def name(self, value: Optional[str]):
        if value is None:
            raise NotImplementedError('Implement name deletion')

        error = self._tinfo.rename_type(value)
        if error != 0:
            raise RuntimeError(f'Failed to name {self} {value}: {ida_typeinf.tinfo_errstr(error)}')

    @name.deleter
    def name(self):
        self.name = None

    @property
    def is_auto_name(self) -> bool:
        raise NotImplementedError

    @property
    def is_user_defined_name(self) -> bool:
        raise NotImplementedError

    def _default_tree_type(self) -> TreeType:
        return TreeType.Types

    def _is_valid_tree_type(self, type: TreeType) -> bool:
        return type == TreeType.Types

    @property
    def comment(self) -> Optional[str]:
        return self._tinfo.get_type_cmt()

    @comment.setter
    def comment(self, value: Optional[str]):
        error = self._tinfo.set_type_cmt(value, is_regcmt=True)
        if error != 0:
            raise RuntimeError(f'Failed to comment {self}: {ida_typeinf.tinfo_errstr(error)}')

    @comment.deleter
    def comment(self):
        self.comment = None

    @property
    def repeatable_comment(self) -> Optional[str]:
        return self._tinfo.get_type_rptcmt()

    @repeatable_comment.setter
    def repeatable_comment(self, value: Optional[str]):
        error = self._tinfo.set_type_cmt(value, is_regcmt=False)
        if error != 0:
            raise RuntimeError(f'Failed to repeat comment {self}: {ida_typeinf.tinfo_errstr(error)}')

    @repeatable_comment.deleter
    def repeatable_comment(self):
        self.repeatable_comment = None

    def delete(self):
        if not ida_typeinf.del_named_type(None, self.name, ida_typeinf.NTF_TYPE):
            raise RuntimeError(f'Failed to delete type {self.name}')

    def iter_members(self) -> Generator[EnumMember, None, None]:
        for idx in range(self.count_values):
            yield EnumMember(idx, self)

    def get_member(self, name: Optional[str], *, index: int = None) -> EnumMember:
        for idx, member in enumerate(self.iter_members()):
            if member.name == name or idx == index:
                return member
        
        raise ValueError(f'No member {name=}|{index=} in {self.name}')

    def delete_member(self, name: str):
        self.get_member(name).delete()

    def add_member(self,
                   name: str,
                   value: Optional[int] = None) -> EnumMember:
        # TODO: support bitmask members
        edm = ida_typeinf.edm_t()
        edm.name = name
        if value is None:
            edm.value = self.max_value + 1
        
        error = self._tinfo.add_edm(edm, -1)
        if error != 0:
            raise RuntimeError(f'Failed to add new member {name}={value} to {self}: {ida_typeinf.tinfo_errstr(error)}')
        
        return EnumMember(self.count_values - 1, self)

    @property
    def count_values(self) -> int:
        return self._tinfo.get_enum_nmembers()

    @property
    def max_value(self) -> int:
        try:
            return sorted(self.iter_members(),
                          key=lambda member: member.value,
                          reverse=True)[0].value
        except IndexError:
            return -1

    @property
    def width(self) -> int:
        return self._tinfo.get_enum_width()

    @width.setter
    def width(self, value: int):
        error = self._tinfo.set_enum_width(value)
        if error != 0:
            raise ValueError(f'Unable to set enum to {value} bytes wide: {ida_typeinf.tinfo_errstr(error)}')

    @property
    def is_bitfield(self) -> bool:
        etd = ida_typeinf.enum_type_data_t()
        if not self._tinfo.get_enum_details(etd):
            raise RuntimeError(f'Failed to get enum data of {self}')
        
        return etd.is_bf()

    @is_bitfield.setter
    def is_bitfield(self, value: bool):
        self._tinfo.set_enum_is_bitmaks(value)
    
    @property
    def base_type(self) -> Type:
        from ..basic_types import SignedInt8, SignedInt16, SignedInt32, SignedInt64
        return {
            ida_typeinf.BT_INT8: SignedInt8,
            ida_typeinf.BT_INT16: SignedInt16,
            ida_typeinf.BT_INT32: SignedInt32,
            ida_typeinf.BT_INT64: SignedInt64,
        }.get(self._tinfo.get_enum_base_type())
    
    @base_type.setter
    def base_type(self, value: Type):
        from ..basic_types import SignedInt8, SignedInt16, SignedInt32, SignedInt64
        if value not in (SignedInt8, SignedInt16, SignedInt32, SignedInt64):
            raise ValueError(f'Invalid enum type {value}')
        
        self.width = value.size
    
    @property
    def references(self) -> Generator[Xref, None, None]:
        yield from map(Xref, idautils.XrefsTo(self._tinfo.get_tid()))

    @property
    def all_references(self) -> Generator[Xref, None, None]:
        raise NotImplementedError
