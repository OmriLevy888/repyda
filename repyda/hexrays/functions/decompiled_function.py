from __future__ import annotations
from typing import Generator, Optional, Union, Dict, Any, TYPE_CHECKING

from repyda.base.types.basic_types import Type

from .. import Matchable, HexraysItem, Statement
from repyda.base.elements import IDBIterable, Referencing, Referenceable, TreeType, \
    Nameable, Commentable, Addressable, Sequenceable, Typed, Xref
from repyda.base.types import FunctionType, Argument

import ida_hexrays
import idaapi

if TYPE_CHECKING:
    from repyda.base.functions import Function
    from repyda.hexrays.expressions import Call
    from . import Line, Variable
    from .. import View


class DecompiledFunction(Matchable, IDBIterable, Referencing, Referenceable, Nameable, Commentable, Addressable, Sequenceable, Typed):
    @staticmethod
    def exists_at(ea: int) -> bool:
        # check that was decompiled at already
        raise NotImplementedError

    def __init__(self,
                 ea: Optional[int] = None,
                 name: Optional[str] = None,
                 function: Optional[Union[Function, ida_hexrays.cfunc_t, ida_hexrays.cfuncptr_t, idaapi.func_t]] = None):
        from repyda.base.functions import Function

        if function is None:
            function = Function(ea=ea, name=name)

        if isinstance(function, (ida_hexrays.cfunc_t, ida_hexrays.cfuncptr_t)):
            self.function = Function(ea=function.entry_ea)
        elif isinstance(function, idaapi.func_t):
            self.function = Function(function=function)
        else:
            self.function = function

        self._decompiled_function = ida_hexrays.decompile(self.function.ea)

    def iter_children(self) -> Generator[HexraysItem, None, None]:
        yield self.root

    @staticmethod
    def iter() -> Generator[DecompiledFunction, None, None]:
        for function in Function.iter():
            try:
                yield function.decompiled_function
            except:
                continue

    @property
    def ea(self) -> int:
        return self.function.ea

    @property
    def name(self) -> str:
        return self.function.name

    @name.setter
    def name(self, value: Optional[str]):
        if value is None:
            value = ''

        if value == self.name:
            return

        self.function.name = value

        if self.view is not None:
            self.view.refresh_view()

    @name.deleter
    def name(self):
        self.name = None

    @property
    def is_auto_name(self) -> bool:
        return self.function.is_auto_name

    @property
    def is_user_defined_name(self) -> bool:
        return self.function.is_user_defined_name

    def _default_tree_type(self) -> TreeType:
        return TreeType.Functions

    def _is_valid_tree_type(self, type: TreeType) -> bool:
        return type in (TreeType.Functions, TreeType.Names)

    @property
    def size(self) -> int:
        return self.function.size

    def __contains__(self, ea: Union[int, Addressable]) -> bool:
        return self.function.__contains__(ea)

    @property
    def references(self) -> Generator[Xref, None, None]:
        for xref in self.function.references:
            yield xref

    @property
    def all_references(self) -> Generator[Xref, None, None]:
        for xref in self.function.all_references:
            yield xref

    @property
    def referencing(self) -> Generator[Xref, None, None]:
        for xref in self.function.referencing:
            yield xref

    @property
    def root(self) -> Statement:
        return HexraysItem.from_citem(self._decompiled_function.body, self._decompiled_function, self)

    def iter_arguments(self) -> Generator[Argument, None, None]:
        raise NotImplementedError

    def iter_variables(self) -> Generator[Variable, None, None]:
        from . import Variable
        for idx in range(len(self._decompiled_function.get_lvars())):
            yield Variable(idx, self)

    def get_variable(self, name: str) -> Variable:
        for var in self.iter_variables():
            if var.name == name:
                return var

        raise ValueError(f'No variable with name {name}')

    @property
    def flags(self) -> int:
        return self.function.flags

    @property
    def count_blocks(self) -> int:
        raise NotImplementedError

    @property
    def count_args(self) -> int:
        raise NotImplementedError

    @property
    def comment(self) -> Optional[str]:
        raise NotImplementedError

    @comment.setter
    def comment(self, value: Optional[str]):
        raise NotImplementedError

    @comment.deleter
    def comment(self):
        self.comment = None

    @property
    def repeatable_comment(self) -> Optional[str]:
        raise NotImplementedError

    @repeatable_comment.setter
    def reapeatable_comment(self, value: Optional[str]):
        raise NotImplementedError

    @reapeatable_comment.deleter
    def reapeatable_comment(self):
        self.reapeatable_comment = None

    @property
    def next(self) -> Optional[DecompiledFunction]:
        raise NotImplementedError

    @property
    def prev(self) -> Optional[DecompiledFunction]:
        raise NotImplementedError

    def _get_type(self) -> Optional[FunctionType]:
        return self.function.type

    def _set_type(self, value: Optional[FunctionType]):
        self.function.type = value

        if self.view is not None:
            self.view.refresh_view()

    @property
    def guessed_type(self) -> Type:
        return self.function.guessed_type

    @property
    def ordinal(self) -> int:
        return self.function.ordinal

    def iter_callers(self,
                     *,
                     include_jump: bool = True,
                     as_calls: bool = False) -> Generator[Union[DecompiledFunction, Call], None, None]:
        if as_calls:
            for xref in self.references:
                if not xref.is_call and not xref.is_jump:
                    continue

                yield xref.decompiled_source_from()

        for function in self.function.iter_callers(include_jump=include_jump):
            yield DecompiledFunction(function=function)

    def iter_callees(self, *, include_jump: bool = True) -> Generator[DecompiledFunction, None, None]:
        for callee in self.function.iter_callees(include_jump=include_jump):
            yield DecompiledFunction(function=callee)

    @property
    def ea_map(self) -> Dict[int, Any]:
        return dict(self._decompiled_function.eamap)

    @property
    def lines(self) -> Generator[Line, None, None]:
        from . import Line

        unique_vecs = list()
        for ea, vec in self.ea_map:
            if vec not in unique_vecs:
                unique_vecs.append(vec)
                yield Line(ea, self._decompiled_function)

    @property
    def view(self) -> View:
        from repyda.hexrays.view import View, UIFLags
        try:
            return View.get(ea=self.ea, flags=UIFLags.REUSE)
        except ValueError:
            return View.get(ea=self.ea, flags=UIFLags.NEW_WINDOW)

    def __str__(self) -> str:
        return str(self._decompiled_function)

    def __repr__(self) -> str:
        return f'{hex(self.ea)}: {self.name}'