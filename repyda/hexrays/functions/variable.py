from __future__ import annotations
from typing import Optional, Generator, TYPE_CHECKING

from repyda.base.elements import Commentable, TreeType, Nameable, Referenceable, Typed, Xref
from repyda.base.types import Type

import ida_hexrays
from repyda.base.types.basic_types import Type

if TYPE_CHECKING:
    from .decompiled_function import DecompiledFunction


class Variable(Commentable, Nameable, Referenceable, Typed):
    def __init__(self, index: int, function: DecompiledFunction):
        self._index = index
        self._function = function

    @property
    def _lvar(self) -> ida_hexrays.lvar_t:
        return self._function._decompiled_function.get_lvars()[self._index]

    @property
    def comment(self) -> Optional[str]:
        return self._lvar.cmt

    @comment.setter
    def comment(self, value: Optional[str]):
        if value is None:
            value = ''

        self._lvar.cmt = value
        self._function.view.refresh_ctext()

    @comment.deleter
    def comment(self):
        self.comment = None

    @property
    def repeatable_comment(self) -> Optional[str]:
        pass

    @repeatable_comment.setter
    def reapeatable_comment(self, value: Optional[str]):
        pass

    @repeatable_comment.deleter
    def repeatable_comment(self):
        self.repeatable_comment = None

    @property
    def name(self) -> str:
        return self._lvar.name

    @name.setter
    def name(self, value: Optional[str]):
        if value == self.name:
            return

        self._lvar.name = value
        self._lvar.set_user_name()
        self._function.view.refresh_ctext()

    @name.deleter
    def name(self):
        self.name = None

    def _default_tree_type(self) -> TreeType:
        raise NotImplementedError('Not implemented for Variable')

    def _is_valid_tree_type(self, type: TreeType) -> bool:
        raise NotImplementedError('Not implemented for Variable')

    @property
    def references(self) -> Generator[Xref, None, None]:
        pass

    @property
    def all_references(self) -> Generator[Xref, None, None]:
        pass

    def _get_type(self) -> Optional[Type]:
        return Type.from_tinfo(self._lvar.type())

    def _set_type(self, value: Optional[Type]):
        if value is None:
            raise NotImplementedError

        self._function.view._vu.set_lvar_type(self._lvar, value.get_tinfo())

    @property
    def guessed_type(self) -> Type:
        raise NotImplementedError

    @property
    def is_argument(self) -> bool:
        return self._lvar.is_arg_var

    @property
    def is_in_register(self) -> bool:
        return self._lvar.is_reg_var()

    @property
    def is_on_stack(self) -> bool:
        return self._lvar.is_stk_var()

    @property
    def stack_offset(self) -> int:
        return self._lvar.get_stkoff()

    def __str__(self) -> str:
        return f'{self.type} {self.name}'