from __future__ import annotations
from typing import Optional, Generator

import ida_typeinf
import ida_struct
import idc
import idautils
import ida_bytes
import construct

from repyda.base.elements.xref import Xref

from .basic_types import Type
from repyda.base.elements import Commentable, IDBIterable, TreeType, Nameable, Referenceable
from repyda.base.elements.typed import Typed


class StructMember(Commentable, Nameable, Referenceable, Typed):
    def __init__(self, member_id: int, struct_type: Struct, offset: int):
        self._member_id = member_id
        self._struct_type = struct_type
        self.offset = offset

    def delete(self):
        ida_struct.del_struc_member(self._struct_type._struct, self.offset)

    def _get_type(self) -> Optional[Type]:
        member, *_ = ida_struct.get_member_by_id(self._member_id)
        tinfo = ida_typeinf.tinfo_t()
        if not ida_struct.get_member_tinfo(tinfo, member):
            return None

        return Type.from_tinfo(tinfo)

    def _set_type(self, value: Optional[Type]):
        member, _, struct = ida_struct.get_member_by_id(self._member_id)

        if value is None:
            ida_struct.del_member_tinfo(struct, member)
        else:
            APPLY_TYPE_ENTIRE_MEMBER = 0

            USERSPECIFIED = 0x10

            from repyda import FunctionType, Pointer
            if isinstance(value, FunctionType):
                value = Pointer(value)

            ida_struct.set_member_tinfo(struct,
                                        member,
                                        APPLY_TYPE_ENTIRE_MEMBER,
                                        value.get_tinfo(),
                                        USERSPECIFIED)

    @property
    def guessed_type(self) -> Type:
        member, *_ = ida_struct.get_member_by_id(self._member_id)
        tinfo = ida_typeinf.tinfo_t()
        if not ida_struct.get_or_guess_member_tinfo(tinfo, member):
            raise RuntimeError(f'Failed to guess type of {self.name}')

        return Type.from_tinfo(tinfo)

    @property
    def name(self) -> str:
        return ida_struct.get_member_name(self._member_id)

    @name.setter
    def name(self, value: Optional[str]):
        if value is None:
            value = ''

        if value == self.name:
            return

        member, _, struct = ida_struct.get_member_by_id(self._member_id)
        ida_struct.set_member_name(struct, member.get_soff(), value)

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
        raise NotImplementedError('Not implemented for StructMemeber')

    def _is_valid_tree_type(self, type: TreeType) -> bool:
        raise NotImplementedError('Not implemented for StructMember')

    @property
    def comment(self) -> Optional[str]:
        member, *_ = ida_struct.get_member_by_id(self._member_id)
        return ida_struct.get_member_cmt(member, False)

    @comment.setter
    def comment(self, value: Optional[str]):
        if value is None:
            value = ''

        member, *_ = ida_struct.get_member_by_id(self._member_id)
        ida_struct.set_member_cmt(member, value, False)

    @comment.deleter
    def comment(self):
        self.comment = None

    @property
    def repeatable_comment(self) -> Optional[str]:
        member, *_ = ida_struct.get_member_by_id(self._member_id)
        return ida_struct.get_member_cmt(member, True)

    @repeatable_comment.setter
    def repeatable_comment(self, value: Optional[str]):
        if value is None:
            value = ''

        member, *_ = ida_struct.get_member_by_id(self._member_id)
        ida_struct.set_member_cmt(member, value, True)

    @repeatable_comment.deleter
    def repeatable_comment(self):
        self.repeatable_comment = None

    @property
    def references(self) -> Generator[Xref, None, None]:
        for xref in idautils.XrefsTo(self._member_id):
            yield Xref(xref)

    @property
    def all_references(self) -> Generator[Xref, None, None]:
        raise NotImplementedError


class Struct(Type, Commentable, IDBIterable, Nameable, Referenceable):
    @staticmethod
    def iter() -> Generator[Struct, None, None]:
        for _, _, name in idautils.Structs():
            try:
                yield Struct(name)
            except ValueError:
                continue

    @classmethod
    def exists(cls, name: str) -> bool:
        return ida_struct.get_struc_id(name) != idc.BADADDR

    @classmethod
    def create_empty_struct(cls,
                            name: Optional[str] = None,
                            exists_ok: bool = True) -> Struct:
        if name is not None and cls.exists(name):
            if exists_ok:
                return cls(name)

            raise ValueError(f'Struct {name} already exists')

        struct_id = ida_struct.add_struc(idc.BADADDR, name, False)
        if struct_id == idc.BADADDR:
            raise ValueError(f'Failed to create {name} (Hint: is there a forward declaration?)')

        if name is None:
            name = ida_struct.get_struc_name(struct_id)

        return cls(name)

    def __init__(self,
                 name: Optional[str] = None,
                 *,
                 tinfo: Optional[ida_typeinf.tinfo_t] = None):
        if name is None and tinfo is None:
            raise ValueError(f'Must pass at least one of name or tinfo')
        elif name is None:
            name = str(tinfo)
            if name.startswith('struct '):
                name = name[len('struct'):].lstrip()

            name = name.rstrip()
            if ' ' in name:
                name = name.split(' ')[0]

        self._struct_id = ida_struct.get_struc_id(name)
        if self._struct_id == idc.BADADDR:
            raise ValueError(f'{name} does not exists')

        if self._struct.is_union():
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
    def _struct(self) -> ida_struct.struc_t:
        return ida_struct.get_struc(self._struct_id)

    @property
    def size(self) -> int:
        return ida_struct.get_struc_size(self._struct)

    def delete(self):
        if not ida_struct.del_struc(self._struct):
            raise RuntimeError(f'Failed to delete struct {self.name}')

    @property
    def name(self) -> str:
        return ida_struct.get_struc_name(self._struct_id)

    @name.setter
    def name(self, value: Optional[str]):
        if value is None:
            value = ''

        if value == self.name:
            return

        ida_struct.set_struc_name(self._struct_id, value)

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
        return ida_struct.get_struc_cmt(self._struct_id, False)

    @comment.setter
    def comment(self, value: Optional[str]):
        if value is None:
            value = ''

        ida_struct.set_struc_cmt(self._struct_id, value, False)

    @comment.deleter
    def comment(self):
        self.comment = None

    @property
    def repeatable_comment(self) -> Optional[str]:
        return ida_struct.get_struc_cmt(self._struct_id, True)

    @repeatable_comment.setter
    def repeatable_comment(self, value: Optional[str]):
        if value is None:
            value = ''

        ida_struct.set_struc_cmt(self._struct_id, value, True)

    @repeatable_comment.deleter
    def repeatable_comment(self):
        self.repeatable_comment = None

    def get_tinfo(self) -> ida_typeinf.tinfo_t:
        tinfo = ida_typeinf.tinfo_t()
        declaration = f'struct {self.name};'
        parse_flags = ida_typeinf.PT_TYP | ida_typeinf.PT_RAWARGS | ida_typeinf.PT_SIL

        if not ida_typeinf.parse_decl(tinfo, None, declaration, parse_flags):
            raise RuntimeError(f'Failed to parse {declaration}')

        return tinfo

    def get_member(self,
                   name: Optional[str] = None,
                   *,
                   offset: Optional[int] = None) -> StructMember:
        if name is None and offset is None:
            raise ValueError(f'Must pass either name or offset')

        for member in self.iter_members():
            if name is not None:
                if member.name == name:
                    return member
            else:
                if member.offset == offset:
                    return member

        raise ValueError(f'Member {name=} {offset=} not found in {self}')

    @property
    def count_members(self):
        return len(self._struct.members)

    def iter_members(self) -> Generator[StructMember, None, None]:
        for member in self._struct.members:
            yield StructMember(member.id, self, member.get_soff())

    def has_member(self,
                   name: Optional[str] = None,
                   *,
                   offset: Optional[int] = None) -> bool:
        try:
            self.get_member(name=name, offset=offset)
            return True
        except ValueError:
            return False

    def add_member(self,
                   name: Optional[str] = None,
                   type: Optional[Type] = None,
                   size: Optional[int] = 1,
                   offset: Optional[int] = None,
                   exists_ok: bool = True) -> StructMember:
        if self.has_member(name=name, offset=offset):
            if exists_ok:
                return self.get_member(name=name, offset=offset)

            raise ValueError(f'Member {name=}, {offset=} already exists')

        if type is not None:
            from repyda.base.types.basic_types import Scalar, Array

            if isinstance(type, str):
                type = Type.from_c(type)

            size = 1
            flags = idc.FF_DATA | idc.FF_BYTE

            if type.is_instance(Array) and type.count_elements == 0:
                size = 0

            if isinstance(type, Scalar):
                size = type.size
                flags = idc.FF_DATA | ida_bytes.get_flags_by_size(size)
        else:
            flags = idc.FF_DATA | ida_bytes.get_flags_by_size(size)

        if offset is None:
            offset = idc.BADADDR

        if ida_struct.add_struc_member(self._struct,
                                       name,
                                       offset,
                                       flags,
                                       None,
                                       size) < 0:
            raise RuntimeError(f'Failed to add member {name} to struct {self.name}')

        if name is None:
            if offset == idc.BADADDR:
                offset = self.size - size

            member = self.get_member(offset=offset)
        else:
            member = self.get_member(name)

        if type is not None:
            member.type = type

        return member

    def delete_member(self,
                      name: Optional[str] = None,
                      *,
                      offset: Optional[int] = None):
        if name is None and offset is None:
            raise ValueError(f'Must pass either name or offset')

        self.get_member(name=name, offset=offset).delete()

    def add_gap(self, size: int):
        if size < 1:
            raise ValueError('Gap must be at least 1 byte long')

        gap_members = list()

        current_size = 32
        while current_size > size:
            current_size = max(current_size // 2, 1)

        while size >= current_size:
            gap_members.append(self.add_member(size=current_size))

            size -= current_size
            while size != 0 and current_size > size:
                current_size = max(current_size // 2, 1)

        self.add_member()

        for member in gap_members:
            member.delete()

    def get_construct_struct(self) -> construct.Struct:
        members = (member.name / member.type.get_construct_struct()
                   for member in self.iter_members())
        return construct.Struct(*members)

    @property
    def references(self) -> Generator[Xref, None, None]:
        for xref in idautils.XrefsTo(self._struct_id):
            yield Xref(xref)

    @property
    def all_references(self) -> Generator[Xref, None, None]:
        raise NotImplementedError