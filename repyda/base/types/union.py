from __future__ import annotations
from typing import Optional, Generator

import ida_typeinf

from .basic_types import Type
from repyda.base.elements import TreeType, Nameable, Typed, IDBIterable, Referenceable, Xref

import ida_typeinf
import ida_struct
import idc
import idautils
import ida_bytes

import construct


class UnionMember(Nameable, Typed, Referenceable):
    def __init__(self, union: Union, udt_member: ida_typeinf.udt_member_t, offset: int):
        self._union = union
        self._udt_member = udt_member
        self.offset = offset

    @property
    def union(self) -> Union:
        return self._union

    @property
    def name(self) -> Optional[str]:
        return self._udt_member.name

    @name.setter
    def name(self, value: Optional[str]):
        if value is None:
            value = ''

        if value == self.name:
            return

        self._udt_member.name = value

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
        raise NotImplementedError('Not implemented for UnionMember')

    def _is_valid_tree_type(self, type: TreeType) -> bool:
        raise NotImplementedError('Not implemented for UnionMember')

    def _get_type(self) -> Optional[Type]:
        return Type.from_tinfo(ida_typeinf.tinfo_t(self._udt_member.type))

    def _set_type(self, value: Optional[Type]):
        if value is None:
            raise ValueError('Deleting type of union member is impossible')

        from repyda import FunctionType, Pointer
        if isinstance(value, FunctionType):
            value = Pointer(value)

        self._udt_member.type = value.get_tinfo()

    @property
    def guessed_type(self) -> Type:
        raise NotImplementedError

    @property
    def has_user_defined_type(self) -> bool:
        raise NotImplementedError

    def delete(self):
        ida_struct.del_struc_member(self._union._union, self.offset)

    @property
    def references(self) -> Generator[Xref, None, None]:
        full_name = '.'.join(self.union.name, self.name)
        member = ida_struct.get_member_by_fullname(full_name)
        for xref in idautils.XrefsTo(member.id):
            yield Xref(xref)

    @property
    def all_references(self) -> Generator[Xref, None, None]:
        raise NotImplementedError


class Union(Type, Nameable, IDBIterable, Referenceable):
    @staticmethod
    def iter() -> Generator[Union, None, None]:
        for _, _, name in idautils.Structs():
            try:
                yield Union(name)
            except ValueError:
                continue

    @classmethod
    def exists(cls, name: str) -> bool:
        return ida_struct.get_struc_id(name) != idc.BADADDR

    @classmethod
    def create_empty_union(cls,
                           name: Optional[str] = None,
                           exists_ok: bool = True) -> Union:
        if name is not None and cls.exists(name):
            if exists_ok:
                return cls(name)

            raise ValueError(f'Struct {name} already exists')

        if name is None:
            names = [union.name[len('union_'):] for union in Union.iter()
                     if union.name.startswith('union_')]
            names = [name for name in names if len(name) != 0]

            for n in range(0x100000):
                if str(n) not in names:
                    break
            else:
                raise RuntimeError(f'Ran out of union names')

            name = f'union_{n}'

        union_id = ida_struct.add_struc(idc.BADADDR, name, True)
        if union_id == idc.BADADDR:
            raise ValueError(f'Failed to create {name} (Hint: is there a forward declaration?)')

        return cls(name)

    def __init__(self,
                 name: Optional[str] = None,
                 *,
                 tinfo: Optional[ida_typeinf.tinfo_t] = None):
        if name is None and tinfo is None:
            raise ValueError(f'Must pass at least one of name or tinfo')
        elif name is None:
            name = str(tinfo)
            if name.startswith('union '):
                name = name.lstrip('union ').lstrip()

            name = name.rstrip()
            if ' ' in name:
                name = name.split(' ')[0]

        self._union_id = ida_struct.get_struc_id(name)
        if self._union_id == idc.BADADDR:
            raise ValueError(f'{name} does not exists')

        if not self._union.is_union():
            raise ValueError(f'Use Union class instead')

        if tinfo is not None:
            super().__init__(tinfo=tinfo)
        else:
            super().__init__(tinfo=self.get_tinfo())

        if tinfo is not None and ' ' in str(tinfo) and str(tinfo).split(' ')[1][0] == '{':
            # of the form "struct { int a; float b; ... };"
            # need to set type of fields
            raise NotImplementedError

    @property
    def _union(self) -> ida_struct.struc_t:
        return ida_struct.get_struc(self._union_id)

    @property
    def _union_type_data(self) -> ida_typeinf.udt_type_data_t:
        union_type_data = ida_typeinf.udt_type_data_t()
        if not self._tinfo.get_udt_details(union_type_data):
            raise RuntimeError(f'Failed to get details for union {self.name}')

        return union_type_data

    def get_tinfo(self) -> ida_typeinf.tinfo_t:
        tinfo = ida_typeinf.tinfo_t()
        declaration = f'union {self.name};'
        parse_flags = ida_typeinf.PT_TYP | ida_typeinf.PT_RAWARGS | ida_typeinf.PT_SIL

        if not ida_typeinf.parse_decl(tinfo, None, declaration, parse_flags):
            raise RuntimeError(f'Failed to parse {declaration}')

        return tinfo

    @property
    def name(self) -> str:
        return ida_struct.get_struc_name(self._union_id)

    @name.setter
    def name(self, value: Optional[str]):
        if value is None:
            value = ''

        if value == self.name:
            return

        ida_struct.set_struc_name(self._union_id, value)

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
    def count_members(self) -> int:
        return self._tinfo.get_udt_nmembers()

    def iter_members(self) -> Generator[UnionMember, None, None]:
        for idx in range(self.count_members):
            yield UnionMember(self, self._union_type_data[idx], idx)

    def get_member(self, name: str) -> UnionMember:
        for member in self.iter_members():
            if member.name == name:
                return member

        raise ValueError(f'Member {name} not found')

    def has_member(self, name: str) -> bool:
        try:
            self.get_member(name)
            return True
        except ValueError:
            return False

    def add_member(self,
                   name: Optional[str] = None,
                   type: Optional[Type] = None,
                   size: Optional[int] = 1,
                   exists_ok: bool = True) -> UnionMember:
        if self.has_member(name):
            if exists_ok:
                return self.get_member(name)

            raise ValueError(f'{name} already exists')

        if type is not None:
            from repyda.base.types.basic_types import Scalar

            if isinstance(type, str):
                type = Type.from_c(type)

            size = 1
            flags = idc.FF_DATA | idc.FF_BYTE

            if isinstance(type, Scalar):
                size = type.size
                flags = idc.FF_DATA | ida_bytes.get_flags_by_size(size)
        else:
            flags = idc.FF_DATA | ida_bytes.get_flags_by_size(size)

        if ida_struct.add_struc_member(self._union,
                                       name,
                                       idc.BADADDR,
                                       flags,
                                       None,
                                       size) < 0:
            raise RuntimeError(f'Failed to add member {name} to struct {self.name}')

        if name is None:
            last = ida_struct.get_struc_last_offset(self._union)
            member = UnionMember(self, self._union.members[last], offset=last)
        else:
            member = self.get_member(name)

        if type is not None:
            member.type = type

        return member

    def delete_member(self, name: str):
        self.get_member(name).delete()

    def get_construct_struct(self) -> construct.Struct:
        members = (member.name / member.type.get_construct_struct()
                   for member in self.iter_members())
        return construct.Struct(*members)

    @property
    def references(self) -> Generator[Xref, None, None]:
        for xref in idautils.XrefsTo(self._union_id):
            yield Xref(xref)

    @property
    def all_references(self) -> Generator[Xref, None, None]:
        raise NotImplementedError