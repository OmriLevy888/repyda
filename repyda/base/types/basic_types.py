from __future__ import annotations
from abc import ABCMeta

import idc
import ida_typeinf
import ida_kernwin
import ida_nalt
import ida_ida
import idautils
from typing import Optional, Tuple, TypeVar, Generic, Union, Any, Generator, TYPE_CHECKING

import sys
import construct

from repyda.base.elements import Referenceable, Xref, XrefType, IDBIterable, Commentable, Nameable, TreeType

if TYPE_CHECKING:
    from .compund_types import CompoundTypeMember, EnumMember


def _is_generic_alias(object: Any) -> bool:
    return hasattr(object, '__origin__')


def import_c_header():
    raise NotImplementedError


def get_handling_class_for_tinfo(tinfo: ida_typeinf.tinfo_t) -> type:
    from repyda.base.types.function_type import FunctionType
    from repyda.base.types.compund_types import Struct, Union, Enum
    
    if (tinfo.is_typedef() or (tinfo.is_from_subtil() and tinfo.is_typeref())) and not tinfo.is_forward_decl():
        return TypeDefinition
    elif tinfo.is_ptr():
        return Pointer
    elif tinfo.is_array():
        return Array
    elif tinfo.is_func():
        return FunctionType
    elif tinfo.is_struct():
        return Struct
    elif tinfo.is_enum():
        return Enum
    elif tinfo.is_union():
        return Union
    elif not tinfo.is_void():
        return Scalar
    else:
        return Type


class TypeMeta(ABCMeta):
    def __instancecheck__(self, instance: Any) -> bool:
        if instance.__class__ == TypeDefinition:
            return isinstance(instance.target, self)
        
        return super().__instancecheck__(instance)


class Type(Referenceable, metaclass=TypeMeta):
    CLEAN_TYPE_DETAILS = ('', b'', b'\x01')

    @staticmethod
    def from_tinfo(tinfo: ida_typeinf.tinfo_t) -> Type:
        return get_handling_class_for_tinfo(tinfo)(tinfo=tinfo)
    
    @staticmethod
    def from_tid(tid: ida_typeinf.tinfo_t,
                 *,
                 mermbers_return_parent: bool = False) -> Union[Type, CompoundTypeMember, EnumMember]:
        from .compund_types import Enum, CompoundType
        
        tif = ida_typeinf.tinfo_t()
        if not tif.get_type_by_tid(tid):
            raise RuntimeError(f'Failed to get tinfo for {tid}')

        type_object = get_handling_class_for_tinfo(tif)(tinfo=tif)
        if mermbers_return_parent:
            return type_object
        
        if isinstance(type_object, Enum):
            edm_idx = type_object._tinfo.get_edm_by_tid(None, tid)
            if edm_idx != -1:
                return type_object.get_member(index=edm_idx)
        elif isinstance(type_object, CompoundType):
            udm = ida_typeinf.udm_t()
            member_idx = type_object._tinfo.get_udm_by_tid(udm, tid)
            if member_idx >= 0:
                return type_object.get_member(index=member_idx)
        
        return type_object

    @staticmethod
    def _fix_declaration_padding(declaration: str) -> str:
        declaration = declaration.strip()
        if declaration[-1] != ';':
            declaration += ';'

        return declaration

    @staticmethod
    def from_c(declaration: str) -> Type:
        tinfo = ida_typeinf.tinfo_t()
        declaration = Type._fix_declaration_padding(declaration)

        from repyda.base.types import FunctionType
        if FunctionType.is_function_type(declaration):
            declaration = FunctionType.make_function_type_ida_parseable(declaration)

        parse_flags = ida_typeinf.PT_TYP | ida_typeinf.PT_RAWARGS | ida_typeinf.PT_SIL

        ret = ida_typeinf.parse_decl(tinfo, None, declaration, parse_flags)
        if ret is None:
            if declaration.rstrip() == 'void;':
                return Void

            found_alias, alias = Scalar._alias_tinfo(declaration.rstrip(' ;').lstrip())
            if found_alias:
                return Type.from_c(alias)

            raise ValueError(f'Unable to create Type from declaration {declaration}')

        if get_handling_class_for_tinfo(tinfo) is TypeDefinition:
            return TypeDefinition(tinfo)
        elif tinfo.is_struct():
            from repyda.base.types.struct import Struct

            name = ret
            return Struct(name, tinfo=tinfo)
        elif tinfo.is_union():
            from repyda.base.types.union import Union

            name = ret
            return Union(name, tinfo=tinfo)

        return Type.from_tinfo(tinfo)

    @staticmethod
    def from_ida_type_t_simple_type(type_t: int) -> Type:
        tinfo = ida_typeinf.tinfo_t()
        if not tinfo.create_simple_type(type_t):
            raise RuntimeError(f'Unable to create simple type from {type_t}')

        return Type.from_tinfo(tinfo)

    def __init__(self, tinfo: ida_typeinf.tinfo_t):
        right_class = get_handling_class_for_tinfo(tinfo)
        if right_class is not self.__class__:
            raise ValueError(f'Should use {right_class.__name__} rather than {self.__class__.__name__}')

        self._tinfo = tinfo

    def __str__(self) -> str:
        return self.get_tinfo().dstr()

    def __repr__(self) -> str:
        return self.get_tinfo().dstr()

    def get_type_details(self) -> Tuple[str, bytes, bytes]:
        declaration = Type._fix_declaration_padding(str(self))
        details = idc.parse_decl(declaration, idc.PT_SILENT)
        if details is None:
            raise RuntimeError(f'Failed to parse {declaration}, this is a bug!')

        return details

    def get_tinfo(self) -> ida_typeinf.tinfo_t:
        return ida_typeinf.tinfo_t(self._tinfo)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, str):
            other = Type.from_c(other)
        elif isinstance(other, ida_typeinf.tinfo_t):
            other = Type.from_tinfo(ida_typeinf.tinfo_t(other))

        return self.__str__() == other.__str__()

    def __ne__(self, other: Any) -> bool:
        if isinstance(other, str):
            other = Type.from_c(other)
        elif isinstance(other, ida_typeinf.tinfo_t):
            other = Type.from_tinfo(ida_typeinf.tinfo_t(other))

        return self.__str__() != other.__str__()

    def __hash__(self) -> int:
        return hash(self.__str__())

    @property
    def references(self) -> Generator[Xref, None, None]:
        yield from map(Xref, idautils.XrefsTo(self._tinfo.get_tid()))

    @property
    def all_references(self)  -> Generator[Xref, None, None]:
        raise NotImplementedError

    @property
    def size(self) -> int:
        size = self.get_tinfo().get_size()
        if size == idc.BADADDR:
            raise RuntimeError('Tried to get size of void')
        return size

    @property
    def as_string(self) -> str:
        return self.get_tinfo().dstr()

    def set_at(self, ea: int):
        if not ida_typeinf.apply_type(ea,
                                      ida_typeinf.tinfo_t(self.get_tinfo()),
                                      ida_typeinf.TINFO_DEFINITE):
            raise RuntimeError(f'Unable to set type {self} at address {hex(ea)}')

    @staticmethod
    def get_at(ea: Optional[int] = None) -> Optional[Type]:
        if ea is None:
            ea = ida_kernwin.get_screen_ea()

        tinfo = ida_typeinf.tinfo_t()
        if ida_nalt.get_tinfo(tinfo, ea):
            return Type.from_tinfo(tinfo)

        return None

    @staticmethod
    def guess_at(ea: Optional[int] = None) -> Optional[Type]:
        if ea is None:
            ea = ida_kernwin.get_screen_ea()

        tinfo = ida_typeinf.tinfo_t()
        if ida_typeinf.guess_tinfo(tinfo, ea) == ida_typeinf.GUESS_FUNC_OK:
            return Type.from_tinfo(tinfo)

        return None

    @staticmethod
    def del_at(ea: int = None):
        if ea is None:
            ea = ida_kernwin.get_screen_ea()

        ida_nalt.del_tinfo(ea)

    def clone(self) -> Type:
        return Type.from_tinfo(ida_typeinf.tinfo_t(self.get_tinfo()))

    @property
    def const(self) -> bool:
        return self._tinfo.is_const()

    @const.setter
    def const(self, value: bool):
        if value:
            self._tinfo.set_const()
        else:
            self._tinfo.clr_const()

    @property
    def volatile(self) -> bool:
        return self._tinfo.is_volatile()

    @volatile.setter
    def volatile(self, value: bool):
        if value:
            self._tinfo.set_volatile()
        else:
            self._tinfo.clr_volatile()

    def without_qualifiers(self) -> Type:
        tinfo = ida_typeinf.tinfo_t(self.get_tinfo())
        tinfo.clr_const()
        tinfo.clr_volatile()
        return Type.from_tinfo(tinfo)

    def get_construct_struct(self) -> construct.Struct:
        raise NotImplementedError

    def is_instance(self, type: Union[Generic[TypeT], Type]) -> bool:
        if _is_generic_alias(type):
            return False

        if (type.const and not self.const) or \
            (type.volatile and not self.volatile):
            return False

        return self.without_qualifiers() == type.without_qualifiers()


class CommentableType(Type, Commentable):
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


class NameableType(Type, Nameable):
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

    def _default_tree_type(self) -> TreeType:
        return TreeType.Types

    def _is_valid_tree_type(self, type: TreeType) -> bool:
        return type == TreeType.Types


class DeleteableType(NameableType):
    def delete(self):
        if not ida_typeinf.del_named_type(None, self.name, ida_typeinf.NTF_TYPE):
            raise RuntimeError(f'Failed to delete type {self.name}')


TypeT = TypeVar('TypeT', bound=Type)


class Pointer(Type, Generic[TypeT]):
    def __init__(self,
                 pointed: Optional[TypeT] = None,
                 *,
                 tinfo: Optional[ida_typeinf.tinfo_t] = None):
        if tinfo is not None:
            super().__init__(tinfo=tinfo)
        else:
            if pointed is None:
                raise ValueError(f'Must specify pointer or tinfo')

            self._tinfo = ida_typeinf.tinfo_t()
            if not self._tinfo.create_ptr(pointed._tinfo):
                raise RuntimeError(f'Failed to create pointer to type {pointed}')

    @property
    def pointed(self) -> TypeT:
        return Type.from_tinfo(ida_typeinf.tinfo_t(self._tinfo.get_pointed_object()))

    def get_construct_struct(self) -> construct.Struct:
        from repyda.base.idb.idb import IDB, Endianness
        count_bytes = IDB.ptr_size()
        endianness = 'b' if IDB.get_endianness() == Endianness.BIG else 'l'
        return getattr(construct, f'Int{count_bytes * 8}u{endianness}')

    def is_instance(self, type: Union[Generic[TypeT], Type]) -> bool:
        if type is self.__class__:
            return True
        elif not _is_generic_alias(type):
            return False

        return isinstance(self, type.__origin__) and self.pointed.is_instance(type.__args__[0])


class Array(Type, Generic[TypeT]):
    def __init__(self,
                 element: Optional[TypeT] = None,
                 count: Optional[int] = None,
                 *,
                 tinfo: Optional[ida_typeinf.tinfo_t] = None):
        if tinfo is not None:
            super().__init__(tinfo=tinfo)
        else:
            if element is None:
                raise ValueError('Must specify element')

            if count is None:
                count = 0

            from repyda import FunctionType
            if isinstance(element, FunctionType):
                element = Pointer(element)

            self._tinfo = ida_typeinf.tinfo_t()
            if not self._tinfo.create_array(element._tinfo, count):
                raise RuntimeError(f'Failed to create array type of {element} with {count} elements')

    @property
    def element_type(self) -> TypeT:
        array_info = ida_typeinf.array_type_data_t()
        self._tinfo.get_array_details(array_info)
        return Type.from_tinfo(ida_typeinf.tinfo_t(array_info.elem_type))

    @property
    def count_elements(self) -> int:
        array_info = ida_typeinf.array_type_data_t()
        self._tinfo.get_array_details(array_info)
        return array_info.nelems

    def get_construct_struct(self) -> construct.Struct:
        element_struct = self.element_type.get_construct_struct()

        if self.element_type.is_instance(Char) and self.count_elements == 0:
            return construct.CString('utf-8')

        return construct.Array(self.count_elements, element_struct)

    def is_instance(self, type: Union[Generic[TypeT], Type]) -> bool:
        if type is self.__class__:
            return True
        elif not _is_generic_alias(type):
            return False

        return isinstance(self, type.__origin__) and self.element_type.is_instance(type.__args__[0])


class Scalar(Type):
    @staticmethod
    def _alias_tinfo(source: str) -> Tuple[bool, str]:
        mapping = {
            'signed __int8': ('int8_t', 'signed int8_t',
                              '__int8'),
            'unsigned __int8': ('uint8_t', 'unsigned int8_t',
                                'unsigned uint8_t',
                                'unsigned __int8'),
            'signed __int16': ('int16_t', 'signed int16_t',
                              '__int16'),
            'unsigned __int16': ('uint16_t', 'unsigned int16_t',
                                'unsigned uint16_t',
                                'unsigned __int16'),
            'signed __int32': ('int', 'signed int',
                               'int32_t', 'signed int32_t',
                               '__int32'),
            'unsigned __int32': ('uint', 'unsigned int',
                               'uint32_t', 'unsigned uint32_t',
                                'unsigned int32_t'),
            'signed __int64': ('int64_t', 'signed int64_t',
                               '__int64'),
            'unsigned __int64': ('uint64_t', 'unsigned uint64_t',
                                 'unsigned int64_t'),
        }
        for mapped, aliases in mapping.items():
            if source in aliases:
                return True, mapped

        return False, None

    @property
    def signed(self) -> bool:
        self._tinfo.is_scalar()
        return self._tinfo.is_signed()

    def get_construct_struct(self) -> construct.Struct:
        type_to_construct = [
            (Bool, 'Int8u{}'),
            (Char, 'Int8u{}'),
            (UnsignedChar, 'Int8u{}'),
            (UnsignedInt8, 'Int8u{}'),
            (UnsignedInt16, 'Int16u{}'),
            (UnsignedInt32, 'Int32u{}'),
            (UnsignedInt64, 'Int64u{}'),
            #Unsupported - (UnsignedInt128, 'Int8u{}'),
            (SignedInt8, 'Int8s{}'),
            (SignedInt16, 'Int16s{}'),
            (SignedInt32, 'Int32s{}'),
            (SignedInt64, 'Int64s{}'),
            #Unsupported - (SignedInt128, 'Int8u{}'),
            (Float, 'Float32{}'),
            (Double, 'Float64{}'),
            (SizeT, f'Int{SizeT.size * 8}u{{}}'),
            (OffT, f'Int{OffT.size * 8}s{{}}'),
        ]

        from repyda.base.idb.idb import IDB, Endianness
        if IDB.get_endianness() == Endianness.BIG:
            endianness = 'b'
        else:
            endianness = 'l'

        for candidate, type_format in type_to_construct:
            if candidate == self:
                return getattr(construct, type_format.format(endianness))

        raise ValueError(f'{self} does not support conversion to construct.Struct')

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Scalar):
            return super().__eq__(other)

        return self._tinfo.is_signed() == other._tinfo.is_signed() and \
            self._tinfo.get_size() == other._tinfo.get_size() and \
            self._tinfo.is_float() == other._tinfo.is_float()


class TypeDefinition(CommentableType, DeleteableType, IDBIterable):
    @staticmethod
    def iter() -> Generator[TypeDefinition, None, None]:
        raise NotImplementedError('TODO')

    @classmethod
    def create_typedef(cls,
                       name: str,
                       *,
                       target: Union[str, Type] = None,
                       tinfo: ida_typeinf.tinfo_t = None) -> TypeDefinition:
        if tinfo is not None:
            target = Type.from_tinfo(tinfo)
        elif isinstance(target, str):
            target = Type.from_c(target)
        
        tif = ida_typeinf.tinfo_t()
        ttd = ida_typeinf.typedef_type_data_t(None, name)
        ttd.name = target._tinfo.dstr()
        if not tif.create_typedef(ttd):
            raise RuntimeError(f'Failed to create typedef {target.name} {name}')

        error = tif.set_named_type(None, name)
        if error != 0:
            raise RuntimeError(f'Failed to name typedef {target.name} {name}: {ida_typeinf.tinfo_errstr(error)}')
        
        return TypeDefinition(tinfo=tif)
    
    @classmethod
    def iter_for_type(cls,
                      target: Union[str, Type] = None,
                      *,
                      tinfo: ida_typeinf.tinfo_t = None) -> Generator[TypeDefinition, None, None]:
        if tinfo is not None:
            target = Type.from_tinfo(tinfo)
        elif isinstance(target, str):
            target = Type.from_c(target)
        
        for xref in target.references:
            if xref.type == XrefType.TYPEDEF:
                yield xref.source
    
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
    
    @property
    def target(self) -> Type:
        if self._tinfo.is_ptr():
            return Pointer(Type.from_tinfo(self._tinfo.get_pointed_object()))
        elif self._tinfo.is_array():
            return Array(Type.from_tinfo(self._tinfo.get_array_element()),
                         self._tinfo.get_array_nelems())
        else:
            return Type.from_c(self._tinfo.get_next_type_name())
    
    @property
    def final_target(self) -> Type:
        return Type.from_c(self._tinfo.get_final_type_name())
    

def _compute_architecutre_dependant_scalar_types():
    def tinfo_from_ida_type_t_simple_type(type_t: int) -> ida_typeinf.tinfo_t:
        tinfo = ida_typeinf.tinfo_t()
        if not tinfo.create_simple_type(type_t):
            raise RuntimeError(f'Unable to create simple type from {type_t}')

        return tinfo

    if ida_ida.inf_is_64bit():
        size_t  = tinfo_from_ida_type_t_simple_type(ida_typeinf.BTF_UINT64)
        off_t   = tinfo_from_ida_type_t_simple_type(ida_typeinf.BTF_INT64)
    elif ida_ida.inf_is_32bit_exactly():
        size_t  = tinfo_from_ida_type_t_simple_type(ida_typeinf.BTF_UINT32)
        off_t   = tinfo_from_ida_type_t_simple_type(ida_typeinf.BTF_INT32)
    elif ida_ida.inf_is_32bit_or_higher():
        size_t  = tinfo_from_ida_type_t_simple_type(ida_typeinf.BTF_UINT128)
        off_t   = tinfo_from_ida_type_t_simple_type(ida_typeinf.BTF_INT128)
    elif ida_ida.inf_is_16bit():
        size_t  = tinfo_from_ida_type_t_simple_type(ida_typeinf.BTF_UINT16)
        off_t   = tinfo_from_ida_type_t_simple_type(ida_typeinf.BTF_INT16)
    else:
        size_t  = tinfo_from_ida_type_t_simple_type(ida_typeinf.BTF_UINT8)
        off_t   = tinfo_from_ida_type_t_simple_type(ida_typeinf.BTF_INT8)

    SizeT._tinfo = size_t
    OffT._tinfo = off_t


if 'sphinx' in sys.modules:
    Void            = None
    Bool            = None
    Char            = None
    UnsignedChar    = None
    UnsignedInt8    = None
    UnsignedInt16   = None
    UnsignedInt32   = None
    UnsignedInt64   = None
    UnsignedInt128  = None
    SignedInt8      = None
    SignedInt16     = None
    SignedInt32     = None
    SignedInt64     = None
    SignedInt128    = None
    Float           = None
    Double          = None
    SizeT           = None
    OffT            = None
else:
    Void            = Type.from_ida_type_t_simple_type(ida_typeinf.BTF_VOID)
    Bool            = Type.from_ida_type_t_simple_type(ida_typeinf.BTF_BOOL)
    Char            = Type.from_ida_type_t_simple_type(ida_typeinf.BTF_CHAR)
    UnsignedChar    = Type.from_ida_type_t_simple_type(ida_typeinf.BTF_UCHAR)
    UnsignedInt8    = Type.from_ida_type_t_simple_type(ida_typeinf.BTF_UINT8)
    UnsignedInt16   = Type.from_ida_type_t_simple_type(ida_typeinf.BTF_UINT16)
    UnsignedInt32   = Type.from_ida_type_t_simple_type(ida_typeinf.BTF_UINT32)
    UnsignedInt64   = Type.from_ida_type_t_simple_type(ida_typeinf.BTF_UINT64)
    UnsignedInt128  = Type.from_ida_type_t_simple_type(ida_typeinf.BTF_UINT128)
    SignedInt8      = Type.from_ida_type_t_simple_type(ida_typeinf.BTF_INT8)
    SignedInt16     = Type.from_ida_type_t_simple_type(ida_typeinf.BTF_INT16)
    SignedInt32     = Type.from_ida_type_t_simple_type(ida_typeinf.BTF_INT32)
    SignedInt64     = Type.from_ida_type_t_simple_type(ida_typeinf.BTF_INT64)
    SignedInt128    = Type.from_ida_type_t_simple_type(ida_typeinf.BTF_INT128)
    Float           = Type.from_ida_type_t_simple_type(ida_typeinf.BTF_FLOAT)
    Double          = Type.from_ida_type_t_simple_type(ida_typeinf.BTF_DOUBLE)

    SizeT   = Type.from_ida_type_t_simple_type(ida_typeinf.BTF_UINT8)
    OffT    = Type.from_ida_type_t_simple_type(ida_typeinf.BTF_INT8)
    _compute_architecutre_dependant_scalar_types()


def _fix_types_after_load(*args):
    _compute_architecutre_dependant_scalar_types()


import ida_idaapi
ida_idaapi.notify_when(ida_idaapi.NW_OPENIDB, _fix_types_after_load)