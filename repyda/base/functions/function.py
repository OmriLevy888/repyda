from __future__ import annotations
from typing import Generator, Optional, Union, TYPE_CHECKING

import idc
import ida_name
import ida_kernwin
import idaapi
import ida_nalt
import ida_gdl
import ida_bytes
import ida_search
import ida_typeinf
import idautils

from repyda.base.elements import IDBIterable, Referencing, Referenceable, TreeType, \
    Nameable, Commentable, Addressable, Sequenceable, Typed, Xref, XrefType
from repyda.base.elements.nameable import TreeType
from repyda.base.types import Type, FunctionType, Argument

if TYPE_CHECKING:
    from repyda.base.functions.block import Block
    from repyda.base.functions.instruction import Instruction
    from repyda.hexrays.functions import DecompiledFunction
    import ida_hexrays


class Function(IDBIterable, Referencing, Referenceable, Nameable, Commentable, Addressable, Sequenceable, Typed):
    @staticmethod
    def exists_at(ea: int) -> bool:
        return idaapi.get_func(ea) is not None

    def __init__(self,
                 ea: Optional[int] = None,
                 *,
                 name: Optional[str] = None,
                 function: Optional[Union[idaapi.func_t, ida_hexrays.cfunc_t, ida_hexrays.cfuncptr_t, Function, DecompiledFunction]] = None):
        if function is not None:
            if isinstance(function, idaapi.func_t):
                self._function = function
            elif isinstance(function, (ida_hexrays.cfunc_t, ida_hexrays.cfuncptr_t)):
                self._function = idaapi.get_func(function.entry_ea)
            elif isinstance(function, Function):
                self._function = function._function
            elif isinstance(function, DecompiledFunction):
                self._function = idaapi.get_func(function.ea)
        else:
            if ea is not None and name is not None:
                raise ValueError('Can only pass one of ea/name')

            if name is not None:
                ea = ida_name.get_name_ea(idc.BADADDR, name)
                if ea == idc.BADADDR:
                    raise ValueError(f'Could not find name {name}')
            elif ea is None:
                ea = ida_kernwin.get_screen_ea()

            self._function = idaapi.get_func(ea)
            if self._function is None:
                raise ValueError(f'No function for ({ea=}, {name=})')

    @property
    def decompiled_function(self) -> DecompiledFunction:
        try:
            from repyda.hexrays.functions import DecompiledFunction
        except:
            raise RuntimeError('HexRays plugin not initialized')
        return DecompiledFunction(function=self)

    @staticmethod
    def iter() -> Generator[Function, None, None]:
        for ea in idautils.Functions():
            yield Function(ea)

    @property
    def ea(self) -> int:
        return self._function.start_ea

    @property
    def name(self) -> str:
        return idc.get_name(self.ea, ida_name.GN_VISIBLE)

    @name.setter
    def name(self, value: Optional[str]):
        if value is None:
            value = ''

        if value == self.name:
            return

        idc.set_name(self.ea, value, idc.SN_CHECK)

    @name.deleter
    def name(self):
        self.name = None

    @property
    def is_auto_name(self) -> bool:
        return ida_bytes.has_auto_name(ida_bytes.get_full_flags(self.ea))

    @property
    def is_user_defined_name(self) -> bool:
        return ida_bytes.has_user_name(ida_bytes.get_flags(self.ea))

    def _default_tree_type(self) -> TreeType:
        return TreeType.FUNCS

    def _is_valid_tree_type(self, type: TreeType) -> bool:
        return type in (TreeType.FUNCS, TreeType.NAMES)

    @property
    def size(self) -> int:
        return self._function.size()

    def _is_self_contained_xref(self, xref: Xref) -> bool:
        try:
            return idaapi.get_func(xref._xref.frm).start_ea == self.ea and \
                idaapi.get_func(xref._xref.to).start_ea == self.ea
        except AttributeError:
            return False

    @property
    def references(self) -> Generator[Xref, None, None]:
        for xref in idautils.XrefsTo(self.ea):
            xref = Xref(xref)
            if xref.type == XrefType.ORDINARY_FLOW or self._is_self_contained_xref(xref):
                continue

            yield xref

    @property
    def all_references(self) -> Generator[Xref, None, None]:
        for block in self.iter_blocks():
            for xref in block.all_references:
                if not self._is_self_contained_xref(xref):
                    yield xref

    @property
    def referencing(self) -> Generator[Xref, None, None]:
        for block in self.iter_blocks():
            for xref in block.referencing:
                if not self._is_self_contained_xref(xref):
                    yield xref

    @property
    def first_block(self) -> Block:
        from repyda.base.functions import Block
        return Block(self._flowchart()[0].start_ea)

    def iter_blocks(self) -> Generator[Block, None, None]:
        from repyda.base.functions.block import Block
        for block in self._flowchart():
            yield Block(block.start_ea)

    def iter_instructions(self) -> Generator[Instruction, None, None]:
        from repyda.base.functions.instruction import Instruction
        for head in idautils.Heads(self.ea, self.ea + self.size):
            if idc.is_code(ida_bytes.get_full_flags(head)):
                yield Instruction(head)

    def iter_arguments(self) -> Generator[Argument, None, None]:
        if self.type:
            for argument in self.type.iter_arguments():
                yield argument

    def iter_variables(self):
        raise NotImplementedError

    def _flowchart(self) -> idaapi.FlowChart:
        return idaapi.FlowChart(self._function,
                                flags=ida_gdl.FC_PREDS | ida_gdl.FC_NOEXT)

    @property
    def flags(self) -> int:
        return idc.get_func_attr(self.ea, idc.FUNCATTR_FLAGS)

    @property
    def count_blocks(self) -> int:
        return self._flowchart().size

    @property
    def count_args(self) -> Optional[int]:
        return self.type.count_args

    @property
    def count_instructions(self) -> int:
        return sum(block.count_instructions for block in self.iter_blocks())

    @property
    def comment(self) -> Optional[str]:
        return idc.get_func_cmt(self.ea, False) or None

    @comment.setter
    def comment(self, value: Optional[str]):
        if value is None:
            value = ''
        idc.set_func_cmt(self.ea, value, False)

    @comment.deleter
    def comment(self):
        self.comment = None

    @property
    def repeatable_comment(self) -> Optional[str]:
        return idc.get_func_cmt(self.ea, True) or None

    @repeatable_comment.setter
    def repeatable_comment(self, value: Optional[str]):
        if value is None:
            value = ''

        idc.set_func_cmt(self.ea, value, True)

    @repeatable_comment.deleter
    def repeatable_comment(self):
        self.repeatable_comment = None

    @property
    def next(self) -> Optional[Function]:
        address = ida_search.find_code(self.ea + self.size, ida_search.SEARCH_DOWN)
        return None if address == idc.BADADDR else Function(address)

    @property
    def prev(self) -> Optional[Function]:
        address = ida_search.find_code(self.ea, ida_search.SEARCH_UP)
        return None if address == idc.BADADDR else Function(address)

    def _get_type(self) -> Optional[FunctionType]:
        if not idaapi.is_userti(self.ea):
            return None

        tinfo_t = ida_typeinf.tinfo_t()
        return None if not ida_nalt.get_tinfo(tinfo_t, self.ea) \
            else FunctionType.from_tinfo(tinfo_t)

    def _set_type(self, value: Optional[FunctionType]):
        if value is None:
            details = Type.CLEAN_TYPE_DETAILS
        else:
            details = value.get_type_details()

        if not idc.apply_type(self.ea, details):
            raise RuntimeError(f'Failed to set type {value} at {hex(self.ea)}, this is a bug!')

    @property
    def guessed_type(self) -> FunctionType:
        return FunctionType.from_c(idc.guess_type(self.ea))

    @property
    def ordinal(self) -> int:
        return idaapi.get_func_num(self.ea)

    def iter_callers(self,
                     *,
                     include_jump: bool = True,
                     as_instructions: bool = False) -> Generator[Union[Function, Instruction], None, None]:
        for xref in self.references:
            if xref.is_call or (include_jump and xref.is_jump):
                if not as_instructions:
                    source = xref.source
                    if isinstance(source, Function):
                        yield source
                else:
                    yield xref.exact_source

    def iter_callees(self,
                     *,
                     include_jump: bool = True,
                     as_instructions: bool = False) -> Generator[Union[Function, Instruction], None, None]:
        for xref in self.referencing:
            if xref.is_call or (include_jump and xref.is_jump):
                if as_instructions:
                    yield xref.exact_source
                    continue

                try:
                    yield xref.destination
                except ValueError:
                    pass

    def __repr__(self) -> str:
        return f'Function({hex(self.ea)}: {self.name})'

    def __str__(self) -> str:
        function_type = self.type or self.guessed_type
        return f'{hex(self.ea)}: {self.name} [{function_type}]'