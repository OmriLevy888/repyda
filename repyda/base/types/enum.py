from __future__ import annotations
from typing import Optional, Generator

from .basic_types import Type
from repyda.base.elements import IDBIterable, Commentable, Referenceable, TreeType, Nameable, Xref

#import ida_enum
import idc
import ida_typeinf
import idaapi


class EnumMember(Commentable, Referenceable, Nameable, IDBIterable):
    @staticmethod
    def iter() -> Generator[EnumMember, None, None]:
        for enum in Enum.iter():
            for member in enum.iter_members():
                yield member

    def __init__(self,
                 name: Optional[str] = None,
                 *,
                 const_t: Optional[int] = None):
        if const_t is not None:
            self._member = const_t
        elif name is None:
            raise ValueError(f'Must either give name or const_t')
        else:
            member = ida_enum.get_enum_member_by_name(name)
            if member == idc.BADADDR:
                raise ValueError(f'No enum member {name}')

            self._member = member

    @property
    def enum(self) -> Enum:
        enum = ida_enum.get_enum_member_enum(self._member)
        name = ida_enum.get_enum_name(enum)
        return Enum(name)

    @property
    def comment(self) -> Optional[str]:
        return ida_enum.get_enum_member_cmt(self._member, False)

    @comment.setter
    def comment(self, value: Optional[str]):
        if value is None:
            value = ''

        ida_enum.set_enum_member_cmt(self._member, value, False)

    @comment.deleter
    def comment(self):
        self.comment = None

    @property
    def repeatable_comment(self) -> Optional[str]:
        return ida_enum.get_enum_member_cmt(self._member, True)

    @repeatable_comment.setter
    def repeatable_comment(self, value: Optional[str]):
        if value is None:
            value = ''

        ida_enum.set_enum_member_cmt(self._member, value, True)

    @repeatable_comment.deleter
    def repeatable_comment(self):
        self.repeatable_comment = None

    @property
    def name(self) -> str:
        return ida_enum.get_enum_member_name(self._member)

    @name.setter
    def name(self, value: Optional[str]):
        if value is None:
            value = ''

        if value == self.name:
            return

        ida_enum.set_enum_member_name(self._member, value)

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
        pass

    @property
    def all_references(self) -> Generator[Xref, None, None]:
        pass

    @property
    def value(self) -> int:
        return ida_enum.get_enum_member_value(self._member)

    @value.setter
    def value(self, value: int):
        enum, name = self.enum, self.name
        self.delete()
        enum.add_member(name, value)
        self._member = ida_enum.get_enum_member_by_name(name)

    @property
    def serial(self) -> int:
        return ida_enum.get_enum_member_serial(self._member)

    @property
    def bit_mask(self) -> int:
        return ida_enum.get_enum_member_bmask(self._member)

    def delete(self):
        if not ida_enum.del_enum_member(self._enum,
                                        self.value,
                                        self.serial,
                                        self.bit_mask):
            raise RuntimeError(f'Unable to delete enum member {self.name}')


class Enum(Type, Nameable, Commentable, IDBIterable):
    @staticmethod
    def iter() -> Generator[IDBIterable, None, None]:
        enums = [ida_enum.getn_enum(idx) for idx in range(ida_enum.get_enum_qty())]
        for enum in enums:
            name = ida_enum.get_enum_name(enum)
            yield Enum(name)

    @classmethod
    def create_empty_enum(cls, name: str = None):
        if name is not None and ida_enum.get_enum(name) != idc.BADADDR:
            raise ValueError(f'Enum {name} already exists')

        enum = ida_enum.add_enum(idc.BADADDR, name, 0)
        if enum == idc.BADADDR:
            raise RuntimeError(f'Failed to create enum {name}')

        name = ida_enum.get_enum_name(enum)
        return cls(name)

    def __init__(self,
                 name: Optional[str] = None,
                 *,
                 tinfo: Optional[ida_typeinf.tinfo_t] = None):
        if name is None and tinfo is None:
            raise ValueError('Must pass at least one of name or tinfo')

        if name is None:
            name = str(tinfo)
            if name.startswith('enum '):
                name = name[len('enum '):]
                name = name.lstrip()

            if name.endswith(';'):
                name = name.rstrip(';')

        self._enum = ida_enum.get_enum(name)
        if self._enum == idc.BADADDR:
            raise ValueError(f'Enum {name} does not exist')

        if tinfo is not None:
            super().__init__(tinfo=tinfo)
        else:
            # if not name.startswith('enum '):
                # name = 'enum ' + name

            if not name.endswith(';'):
                name = name + ';'

            tinfo = ida_typeinf.tinfo_t()
            parse_flags = ida_typeinf.PT_TYP | ida_typeinf.PT_RAWARGS | ida_typeinf.PT_SIL
            ret = ida_typeinf.parse_decl(tinfo, None, name, parse_flags)
            if ret is None:
                raise RuntimeError(f'Failed to find tinfo for enum {name}')

            super().__init__(tinfo=tinfo)

    @property
    def _enum_type_details(self) -> ida_typeinf.tinfo_t:
        enum_type_data = ida_typeinf.enum_type_data_t()
        if not self._tinfo.get_enum_details(enum_type_data):
            raise RuntimeError(f'Failed to fetch enum type details')

        return enum_type_data

    @property
    def name(self) -> str:
        return ida_enum.get_enum_name(self._enum)

    @name.setter
    def name(self, value: Optional[str]):
        if value is None:
            value = ''

        if value == self.name:
            return

        ida_enum.set_enum_name(self._enum, value)

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
        return TreeType.ENUMS

    def _is_valid_tree_type(self, type: TreeType) -> bool:
        return type in (TreeType.ENUMS, TreeType.LOCAL_TYPES)

    @property
    def comment(self) -> Optional[str]:
        return ida_enum.get_enum_cmt(self._enum, False)

    @comment.setter
    def comment(self, value: Optional[str]):
        if value is None:
            value = ''

        ida_enum.set_enum_cmt(self._enum, value, False)

    @comment.deleter
    def comment(self):
        self.comment = None

    @property
    def repeatable_comment(self) -> Optional[str]:
        return ida_enum.get_enum_cmt(self._enum, True)

    @repeatable_comment.setter
    def repeatable_comment(self, value: Optional[str]):
        if value is None:
            value = ''

        ida_enum.set_enum_cmt(self._enum, value, True)

    @repeatable_comment.deleter
    def repeatable_comment(self):
        self.repeatable_comment = None

    def delete(self):
        ida_enum.del_enum(self._enum)

    def iter_members(self) -> Generator[EnumMember, None, None]:
        for member in self._enum_type_details:
            yield EnumMember(member.name)

    def get_member(self, name: str) -> int:
        member = ida_enum.get_enum_member_by_name(name)
        if member == idc.BADADDR:
            raise ValueError(f'No enum member {name}')

        return ida_enum.get_enum_member_value(member)

    def delete_member(self, name: str):
        EnumMember(name).delete()

    def add_member(self,
                   name: str,
                   value: Optional[int] = None) -> EnumMember:
        if value is None:
            value = self.max_value + 1

        if ida_enum.add_enum_member(self._enum,
                                    name,
                                    value,
                                    ida_enum.DEFMASK) != 0:
            raise RuntimeError(f'Failed to add new member {name} ({value})')

        return EnumMember(name)

    @property
    def count_values(self) -> int:
        return ida_enum.get_enum_size(self._enum)

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
        return ida_enum.get_enum_width(self._enum)

    @width.setter
    def width(self, value: int):
        if not ida_enum.set_enum_width(self._enum, value):
            raise ValueError(f'Unable to set enum to {value} bytes wide')

    @property
    def is_bitfield(self) -> bool:
        return ida_enum.is_bf(self._enum)

    @is_bitfield.setter
    def is_bitfield(self, value: bool):
        if not idaapi.set_enum_bf(self._enum, value):
            raise RuntimeError(f'Failed to change between enum and bitfield')