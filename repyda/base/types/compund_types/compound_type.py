from __future__ import annotations
from typing import Generator, Optional
from abc import abstractmethod

from ..basic_types import Type, CommentableType, DeleteableType, Array, Pointer
from ..function_type import FunctionType
from repyda.base.elements import Nameable, IDBIterable, Commentable, TreeType, Xref, Referenceable, Typed

import ida_typeinf
import idautils
import construct


class CompoundTypeMember(Commentable, Nameable, Referenceable, Typed):
    def __init__(self, idx: int, compound: CompoundType):
        self._idx = idx
        self._compound = compound
    
    @property
    def _udm(self) -> ida_typeinf.udm_t:
        udt = ida_typeinf.udt_type_data_t()
        if not self._compound._tinfo.get_udt_details(udt):
            raise RuntimeError(f'Failed to get compound type information for {self._compound}')
        
        return udt[self._idx]
    
    @property
    def parent(self) -> CompoundTypeMember:
        return self._compound
    
    def delete(self):
        self._compound._tinfo.del_udm(self._idx)
    
    @property
    def name(self) -> str:
        return self._udm.name
    
    @name.setter
    def name(self, value: Optional[str]):
        if value is None:
            raise NotImplementedError('TODO')

        self._compound.rename_udm(self._idx, value)
    
    @name.deleter
    def name(self):
        self.name = None
    
    @property
    def is_auto_name(self) -> bool:
        raise NotImplementedError('Not implemented for compound type memebers')
    
    @property
    def is_user_defined_name(self) -> bool:
        raise NotImplementedError('Not implemented for compound type members')
    
    def _default_tree_type(self) -> TreeType:
        raise NotImplementedError('Folders are not implemented for compound type members')
    
    def _is_valid_tree_type(self, type: TreeType) -> bool:
        raise NotImplementedError('Folders are not implemented for compound type members')
    
    def _get_type(self) -> Optional[Type]:
        # Only way i managed to make IDA not fuck up the life time of the tinfo,
        # tried manually coppying it in CompoundTypeMember._udm but it didn't work
        udt = ida_typeinf.udt_type_data_t()
        if not self._compound._tinfo.get_udt_details(udt):
            raise RuntimeError(f'Failed to get compound type information for {self._compound}')
        
        return Type.from_tinfo(ida_typeinf.tinfo_t(udt[self._idx].type))
    
    def _set_type(self, value: Optional[Type]):
        from ..basic_types import UnsignedInt8
        if value is None:
            value = UnsignedInt8
        
        if isinstance(value, FunctionType):
            value = Pointer(value)
        
        error = self._compound._tinfo.set_udm_type(self._idx, value.get_tinfo())
        if error != 0:
            raise RuntimeError(f'Faield to set type {value} to {self}: {ida_typeinf.tinfo_errstr(error)}')
    
    @property
    def guessed_type(self) -> Type:
        raise NotImplementedError('Not implemented for compount type members')
    
    @property
    def comment(self) -> Optional[str]:
        if not self._udm.is_regcmt():
            return None
        
        return self._udm.cmt

    @comment.setter
    def comment(self, value: Optional[str]):
        self._compound._tinfo.set_udm_cmt(self._idx, value, is_regcmt=True)

    @comment.deleter
    def comment(self):
        self.comment = None

    @property
    def repeatable_comment(self) -> Optional[str]:
        if self._udm.is_regcmt():
            return None
        
        return self._udm.cmt

    @repeatable_comment.setter
    def repeatable_comment(self, value: Optional[str]):
        self._compound._tinfo.set_udm_cmt(self._idx, value, is_regcmt=False)

    @repeatable_comment.deleter
    def repeatable_comment(self):
        self.repeatable_comment = None

    @property
    def references(self) -> Generator[Xref, None, None]:
        yield from map(Xref, idautils.XrefsTo(self._compound._tinfo.get_udm_tid(self._idx)))

    @property
    def all_references(self) -> Generator[Xref, None, None]:
        raise NotImplementedError
    
    def __str__(self) -> str:
        return f'{self.type} {self._compound.name}::{self.name}'
    
    def __repr__(self) -> str:
        return f'{self.type} {self._compound.name}::{self.name}'


class CompoundType(CommentableType, DeleteableType, IDBIterable):
    @classmethod
    def exists(cls, name: str) -> bool:
        try:
            cls(name)
            return True
        except ValueError:
            return False
    
    @classmethod
    def create_empty(cls, name: str, *, is_union: bool) -> CompoundType:
        if cls is CompoundType:
            raise NotImplementedError('Cannot be called from CompoundType, call from derived class')
        
        tif = ida_typeinf.tinfo_t()
        udt = ida_typeinf.udt_type_data_t()
        udt.name = name
        udt.is_union = is_union
        if not tif.create_udt(udt):
            raise RuntimeError(f'Cloud not create {cls.__name__} {name}')
    
        error = tif.set_named_type(None, name)
        if error != 0:
            raise RuntimeError(f'Failed to name {cls.__name__} {name}: {ida_typeinf.tinfo_errstr(error)}')

        return cls(tinfo=tif)
    
    @abstractmethod
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
            tinfo = ida_typeinf.tinfo_t()
            if not tinfo.get_named_type(name):
                raise ValueError(f'Failed to get type {name}')
        elif tinfo is None:
            raise ValueError('Missing type identifier')
        
        super().__init__(tinfo=tinfo)
    
    def delete(self):
        if not ida_typeinf.del_named_type(None, self.name, ida_typeinf.NTF_TYPE):
            raise RuntimeError(f'Failed to delete type {self.name}')
    
    def add_member(self,
                   name: str,
                   *,
                   type: Optional[Type] = None,
                   size: Optional[int] = None,
                   exists_ok: bool = True) -> CompoundTypeMember:
        if self.has_member(name):
            if exists_ok:
                return self.get_member(name)
            
            raise ValueError(f'{self.name}::{name} already exists')
        
        if size is None and type is None:
            size = 1
        elif size is not None and type is not None:
            raise ValueError('Must pass excatly one of size/type')
        
        if type is not None:
            size = type.size
        else:
            from ..basic_types import UnsignedInt8, UnsignedInt16, UnsignedInt32, UnsignedInt64, UnsignedInt128
            type = {
                1: UnsignedInt8,
                2: UnsignedInt16,
                4: UnsignedInt32,
                8: UnsignedInt64,
                16: UnsignedInt128,
            }.get(size, None)
            
            if type is None:
                type = Array(UnsignedInt8, size)
        
        udm = ida_typeinf.udm_t()
        udm.offset = self._add_member_offset()
        udm.size = size * 8
        udm.name = name
        udm.type = type.get_tinfo()
        
        error = self._tinfo.add_udm(udm)
        if error != 0:
            raise RuntimeError(f'Failed to add member {name} to {self}: {ida_typeinf.tinfo_errstr(error)}')

        return CompoundTypeMember(self.count_members - 1, self)
    
    def has_member(self, name: str) -> bool:
        try:
            self.get_member(name)
            return True
        except ValueError:
            return False
    
    def get_member(self, name: str, *, index: int = None) -> CompoundTypeMember:
        for idx, member in enumerate(self.iter_members()):
            if member.name == name or idx == index:
                return member
        
        raise ValueError(f'No member {name=}|{index=} in {self.name}')
    
    def delete_member(self, name: str):
        self.get_member(name).delete()
    
    @property
    def count_members(self) -> int:
        return self._tinfo.get_udt_nmembers()
    
    def iter_members(self) -> Generator[CompoundTypeMember, None, None]:
        if self.__class__ is CompoundType:
            raise NotImplementedError('Cannot be called from CompoundType, call from derived class')
        
        for idx in range(self.count_members):
            yield CompoundTypeMember(idx, self)
    
    @property
    def size(self) -> int:
        return self._tinfo.get_size()
    


class Struct(CompoundType):
    @staticmethod
    def iter() -> Generator[Struct, None, None]:
        for ordinal, tid, name in idautils.Structs():
            try:
                yield Struct(tid=tid)
            except ValueError:
                continue
    
    @classmethod
    def create_empty(cls, name: str) -> Struct:
        return super().create_empty(name, is_union=False)
    
    def __init__(self,
                 name: Optional[str] = None,
                 *,
                 tid: Optional[int] = None,
                 tinfo: Optional[ida_typeinf.tinfo_t] = None):
        if name is not None and name.strip().startswith('struct '):
            name = name.strip().split(' ', maxsplit=1)[1]
            
        super().__init__(name, tid=tid, tinfo=tinfo)
    
    def _add_member_offset(self) -> int:
        return self.size * 8
    
    def get_construct_struct(self) -> construct.Struct:
        raise NotImplementedError
    
    def __repr__(self) -> str:
        return f'struct {self.name}'

    def __str__(self) -> str:
        return f'struct {self.name}'
    

class Union(CompoundType):
    @staticmethod
    def iter() -> Generator[Union, None, None]:
        for ordinal, tid, name in idautils.Structs():
            try:
                yield Union(tid=tid)
            except ValueError:
                continue
    
    @classmethod
    def create_empty(cls, name: str) -> Union:
        return super().create_empty(name, is_union=True)
    
    def __init__(self,
                 name: Optional[str] = None,
                 *,
                 tid: Optional[int] = None,
                 tinfo: Optional[ida_typeinf.tinfo_t] = None):
        if name is not None and name.strip().startswith('union '):
            name = name.strip().split(' ', maxsplit=1)[1]
        
        super().__init__(name, tid=tid, tinfo=tinfo)
    
    def _add_member_offset(self) -> int:
        return 0
    
    def get_construct_struct(self) -> construct.Struct:
        raise NotImplementedError
    
    def __repr__(self) -> str:
        return f'union {self.name}'

    def __str__(self) -> str:
        return f'union {self.name}'
