from __future__ import annotations
from typing import Optional, Generator, Any, Iterable, Union, Callable
import io

import construct

import idaapi
import ida_nalt
import idc
import idautils
import ida_bytes
import ida_name
import ida_search
import ida_typeinf
import ida_kernwin

from repyda.base.elements import Addressable, Commentable, IDBIterable, Nameable, \
    TreeType, Referenceable, Referencing, Sequenceable, Typed, Xref
from repyda.base.types import Type, Pointer, Scalar, Array, Struct


class Data(Addressable, Commentable, IDBIterable, Nameable, Referenceable, Referencing, Sequenceable, Typed):
    @staticmethod
    def exists_at(ea: int) -> bool:
        return idc.is_data(idc.get_full_flags(ea))

    @staticmethod
    def iter() -> Generator[Data, Data, Data]:
        from repyda.base.idb import IDB
        for head in idautils.Heads(IDB.min_ea(), IDB.max_ea()):
            if idc.is_data(idc.get_full_flags(head)):
                yield Data(head)

    @staticmethod
    def set_raw_bytes_at(ea: int, value: Iterable[int]):
        ida_bytes.patch_bytes(ea, bytes(value))

    @staticmethod
    def get_raw_bytes_at(ea: int, count: int) -> bytes:
        data = ida_bytes.get_bytes(ea, count)
        if data is None:
            raise ValueError(f'Could not read data at {hex(ea)} of size {hex(count)}')

        return data

    @classmethod
    def create_at(cls, ea: Optional[int] = None, *, size: int = 1, type: Type = None):
        if ea is None:
            ea = ida_kernwin.get_screen_ea()

        if isinstance(type, str):
            type = Type.from_c(type)

        if type is not None:
            if isinstance(type, str):
                type = Type.from_c(type)

            size = 1
            flags = idc.FF_DATA | idc.FF_BYTE

            if isinstance(type, Scalar):
                size = type.size
                flags = idc.FF_DATA | ida_bytes.get_flags_by_size(size)
        else:
            flags = idc.FF_DATA | ida_bytes.get_flags_by_size(size)

        if not ida_bytes.create_data(ea, flags, size, idc.BADADDR):
            raise RuntimeError(f'Failed to create data at {hex(ea)}')

        data = cls(ea)
        if type is not None:
            details = type.get_type_details()
            if not idc.apply_type(data.ea, details):
                raise RuntimeError(f'Failed to set type {type} at {hex(data.ea)}, this is a bug')

        return data

    def __init__(self, ea: Optional[int] = None, name: Optional[str] = None):
        if ea is None:
            if name is not None:
                ea = ida_name.get_name_ea(idc.BADADDR, name)
            else:
                ea = ida_kernwin.get_screen_ea()

        if not Data.exists_at(ea):
            prev_data = ida_search.find_data(ea, ida_search.SEARCH_UP)
            if prev_data is idc.BADADDR:
                raise ValueError(f'Bad data address {hex(ea)}')

            if ea < idc.get_item_end(prev_data):
                ea = prev_data
            else:
                raise ValueError(f'No data defined at {hex(ea)}')

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
    def comment(self) -> Optional[str]:
        return ida_bytes.get_cmt(self.ea, False) or None

    @comment.setter
    def comment(self, value: Optional[str]):
        if value is None:
            value = ''

        ida_bytes.set_cmt(self.ea, value, False)

    @comment.deleter
    def comment(self):
        self.comment = None

    @property
    def repeatable_comment(self) -> Optional[str]:
        return ida_bytes.get_cmt(self.ea, True) or None

    @repeatable_comment.setter
    def repeatable_comment(self, value: Optional[str]):
        if value is None:
            value = ''

        ida_bytes.set_cmt(self.ea, value, True)

    @repeatable_comment.deleter
    def repeatable_comment(self):
        self.repeatable_comment = None

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

    @property
    def next(self) -> Optional[Data]:
        next_data = ida_search.find_data(self.ea, ida_search.SEARCH_DOWN)
        if next_data == idc.BADADDR:
            return None

        return Data(next_data)

    @property
    def prev(self) -> Optional[Data]:
        prev_data = ida_search.find_data(self.ea, ida_search.SEARCH_UP)
        if prev_data == idc.BADADDR:
            return None

        return Data(prev_data)

    def _get_type(self) -> Optional[Type]:
        if not idaapi.is_userti(self.ea):
            return None

        tinfo_t = ida_typeinf.tinfo_t()
        return None if not ida_nalt.get_tinfo(tinfo_t, self.ea) \
            else Type.from_tinfo(tinfo_t)

    def _set_type(self, value: Optional[Type]):
        if value is None:
            value = self.guessed_type

        self.undefine()
        Data.create_at(self.ea, type=value)

    @property
    def guessed_type(self) -> Type:
        guessed_type = idc.guess_type(self.ea)
        if guessed_type is None:
            from repyda import Pointer, Void, IDB
            if self.size == IDB.ptr_size():
                return Pointer(Void)

            raise RuntimeError(f'Failed to get guessed type for {hex(self.ea)}')
        return Type.from_c(guessed_type)

    def _bytes_setter(self, value: Optional[Iterable[int]]):
        if value is None:
            value = self.original_bytes

        ida_bytes.patch_bytes(self.ea, bytes(value))

    @classmethod
    def type_value_at(cls,
                      type: Union[Type, str],
                      ea: Optional[int] = None,
                      *,
                      constraints: Optional[Callable[[construct.Construct], construct.Construct]] = None) -> Any:
        from .idb_stream import IDBStream

        if ea is None:
            ea = ida_kernwin.get_screen_ea()

        if isinstance(type, str):
            type = Type.from_c(type)

        type_construct = type.get_construct_struct()
        if constraints is not None:
            type_construct = constraints(type_construct)
        parsed = type_construct.parse_stream(IDBStream(ea))

        if hasattr(parsed, '_io') and isinstance(getattr(parsed, '_io'), io.IOBase):
            delattr(parsed, '_io')

        return cls._unpack_parsed(parsed, type)

    @classmethod
    def _unpack_parsed(cls, parsed: construct.Struct, type: Type) -> Any:
        class Unpacked:
            _fields = dict()

            def __iter__(self):
                return iter(self._fields.values())

            def __getattribute__(self, name: str) -> Any:
                if name == '_fields':
                    return super().__getattribute__('_fields')

                try:
                    return super().__getattribute__('_fields')[name]
                except KeyError:
                    return super().__getattribute__(name)

            def __setattr__(self, name: str, value: Any):
                self._fields[name] = value

            def add_field(self, name, value):
                self._fields[name] = value

        def unpack_pointer(value) -> Any:
            try:
                return Addressable.at(value)
            except ValueError:
                return parsed

        def unpack_array(value, element_type) -> Any:
            from repyda import Char
            if element_type.is_instance(Char):
                string_value = bytes(value).decode()
                if string_value[-1] == '\x00':
                    return string_value[:-1]
                else:
                    return string_value
            elif isinstance(element_type, Pointer):
                return [unpack_pointer(item) for item in value]
            elif isinstance(element_type, Array):
                return [unpack_array(item, element_type.element_type) for item in value]
            elif isinstance(element_type, Struct):
                return [unpack_struct(item, element_type) for item in value]
            else:
                return [item for item in value]

        def unpack_struct(value, struct_type) -> Any:
            unpacked = Unpacked()
            for member in struct_type.iter_members():
                member_value = getattr(value, member.name)

                if isinstance(member.type, Pointer):
                    unpacked.add_field(member.name, unpack_pointer(member_value))
                elif isinstance(member.type, Array):
                    unpacked.add_field(member.name, unpack_array(member_value, member.type.element_type))
                elif isinstance(member.type, Struct):
                    unpacked.add_field(member.name, unpack_struct(member_value, member.type))
                else:
                    unpacked.add_field(member.name, member_value)

            return unpacked

        if isinstance(type, Pointer):
            return unpack_pointer(parsed)
        elif isinstance(type, Array):
            return unpack_array(parsed, type.element_type)
        elif isinstance(type, Struct):
            return unpack_struct(parsed, type)
        else:
            return parsed

    def value_with_constraints(self, constraints: Optional[Callable[[construct.Construct], construct.Construct]] = None) -> Any:
        if self.type is not None:
            data_type = self.type
        else:
            data_type = self.guessed_type

        return self.type_value_at(data_type, self.ea, constraints=constraints)

    @property
    def value(self) -> Any:
        return self.value_with_constraints()

    @value.setter
    def value(self, value: Optional[Any]):
        if self.type is not None:
            data_type = self.type
        else:
            data_type = self.guessed_type

        if isinstance(value, str):
            value = value.encode()

        if value is None:
            value = bytes(ida_bytes.get_original_byte(ea)
                          for ea in range(self.ea, self.ea + data_type.size))

        struct = data_type.get_construct_struct()

        if isinstance(data_type, Pointer) and isinstance(value, Addressable):
            ida_bytes.patch_bytes(self.ea, struct.build(value.ea))
        elif isinstance(value, bytes):
            ida_bytes.patch_bytes(self.ea, value)
        else:
            ida_bytes.patch_bytes(self.ea, struct.build(value))

    @value.deleter
    def value(self):
        self.value = None

    def undefine(self):
        if not ida_bytes.del_items(self.ea, 0, self.size, None):
            raise RuntimeError(f'Failed to delete data at {hex(self.ea)}')

        ida_name.del_global_name(self.ea)

    def original_value(self) -> bytes:
        return bytes(ida_bytes.get_original_byte(ea)
                     for ea in range(self.ea, self.ea + self.size))

    def __eq__(self, other: Any) -> bool:
        if self.value == other:
            return True

        try:
            super().__eq__(other)
        except NotImplementedError:
            return False

    def __str__(self) -> str:
        actual_type = self.type if self.has_user_defined_type else self.guessed_type
        return f'{hex(self.ea)}: {self.name} [{actual_type}] ({self.value})'

    def __repr__(self) -> str:
        return f'{hex(self.ea)}: {self.name}'