from __future__ import annotations
from typing import Any, Generator, Optional, Iterable, Union, TYPE_CHECKING

from . import Statement
from .. import Expression, HexraysItem, bound_value

import ida_hexrays

import json

if TYPE_CHECKING:
    from repyda.hexrays.functions.decompiled_function import DecompiledFunction


class ControlFlow(Statement):
    pass


class If(ControlFlow):
    HEXRAYS_TYPE = ida_hexrays.cit_if

    def __init__(self,
                 *,
                 condition: Expression = None,
                 true: Statement = None,
                 false: Statement = None,
                 elseif: Statement = None,
                 **kwargs):
        super().__init__(**kwargs)
        self._condition = HexraysItem._wrap(condition)
        self._true = HexraysItem._wrap(true)
        self._false = HexraysItem._wrap(false)

        if elseif is not None:
            from repyda.hexrays.statements import BlockStatement
            self._false = BlockStatement(statements=elseif)

    def iter_children(self) -> Generator[HexraysItem, None, None]:
        yield from super().iter_children()
        yield self.condition
        yield self.true

        if self.false is not None:
            yield self.false

    @property
    @bound_value
    def condition(self) -> Expression:
        return Expression.from_citem(self._hexrays_item.cif.expr, self._cfunc, self)

    @property
    @bound_value
    def true(self) -> Statement:
        return Statement.from_citem(self._hexrays_item.cif.ithen, self._cfunc, self)

    @property
    @bound_value
    def false(self) -> Optional[Statement]:
        if self._hexrays_item.cif.ielse is None:
            return None

        return Statement.from_citem(self._hexrays_item.cif.ielse, self._cfunc, self)

    def make_citem_t(self) -> ida_hexrays.citem_t:
        insn = ida_hexrays.cinsn_t()
        insn.op = ida_hexrays.cit_if

        cif = ida_hexrays.cif_t()
        cif.expr = self.condition.make_citem_t()

        if self.true is not None:
            cif.ithen = self.true.make_citem_t()

        if self.false is not None:
            cif.ielse = self.false.make_citem_t()

        insn.cif = cif
        return insn


class DefaultValue:
    def __eq__(self, _: Any) -> bool:
        return True

    def __str__(self) -> str:
        return json.dumps({
            'node': self.__class__.__name__
        })

Default = DefaultValue()


class SwitchCase(Statement):
    def __init__(self, *, value: int = None, body: Statement = None, **kwargs):
        super().__init__(**kwargs)
        self._value = value
        self._body = HexraysItem._wrap(body)

    def iter_children(self) -> Generator[HexraysItem, None, None]:
        yield from super().iter_children()
        yield self.body

    @property
    @bound_value
    def value(self) -> Union[int, DefaultValue]:
        if len(list(self._hexrays_item.values)) == 0:
            return Default

        return self._hexrays_item.value(0)

    @property
    @bound_value
    def body(self) -> Statement:
        return Statement.from_citem(self._hexrays_item, self._cfunc, self)

    def make_citem_t(self) -> ida_hexrays.citem_t:
        raise NotImplementedError

    @classmethod
    def from_citem(cls,
                    citem: ida_hexrays.ccase_t,
                    cfunc: ida_hexrays.cfunc_t,
                    parent: Union[DecompiledFunction, HexraysItem]) -> SwitchCase:
        obj = cls()
        obj._hexrays_item = citem
        obj._cfunc = cfunc
        obj._parent = parent
        return obj


class Switch(ControlFlow):
    HEXRAYS_TYPE = ida_hexrays.cit_switch

    def __init__(self, *, expression: Expression = None, cases: Union[Iterable[SwitchCase], SwitchCase] = None, **kwargs):
        super().__init__(**kwargs)

        self._expression = HexraysItem._wrap(expression)
        if not isinstance(cases, Iterable) and cases is not None:
            cases = (cases,)
        self._cases = [HexraysItem._wrap(case) for case in cases or ()] or None

    def iter_children(self) -> Generator[HexraysItem, None, None]:
        yield from super().iter_children()
        yield self.expression
        yield from self.cases or ()

    @property
    @bound_value
    def expression(self) -> Expression:
        return Expression.from_citem(self._hexrays_item.cswitch.expr, self._cfunc, self)

    @property
    @bound_value
    def cases(self) -> Generator[SwitchCase, None, None]:
        for case in self._hexrays_item.cswitch.cases:
            yield SwitchCase.from_citem(case, self._cfunc, self)

    def make_citem_t(self) -> ida_hexrays.citem_t:
        #TODO: implement make_citem_t
        raise NotImplementedError


class Break(ControlFlow):
    HEXRAYS_TYPE = ida_hexrays.cit_break

    def make_citem_t(self) -> ida_hexrays.citem_t:
        insn = ida_hexrays.cinsn_t()
        insn.op = ida_hexrays.cit_break
        return insn


class Continue(ControlFlow):
    HEXRAYS_TYPE = ida_hexrays.cit_continue

    def make_citem_t(self) -> ida_hexrays.citem_t:
        insn = ida_hexrays.cinsn_t()
        insn.op = ida_hexrays.cit_continue
        return insn


class Return(ControlFlow):
    HEXRAYS_TYPE = ida_hexrays.cit_return

    def __init__(self, expression: Expression = None, **kwargs):
        super().__init__(**kwargs)
        self._expression = HexraysItem._wrap(expression)

    def iter_children(self) -> Generator[HexraysItem, None, None]:
        yield self.expression

    @property
    @bound_value
    def expression(self) -> Expression:
        return Expression.from_citem(self._hexrays_item.creturn.expr, self._cfunc, self)

    def make_citem_t(self) -> ida_hexrays.citem_t:
        #TODO: make this not crash
        ret = ida_hexrays.cinsn_t()
        ret.op = ida_hexrays.cit_return
        if self.expression is not None:
            ret.expr = self.expression.make_citem_t()
        return ret


class Goto(ControlFlow):
    HEXRAYS_TYPE = ida_hexrays.cit_goto

    def __init__(self, label_id: int = None, **kwargs):
        super().__init__(**kwargs)
        self._label_id = label_id

    @property
    @bound_value
    def label_id(self) -> int:
        return self._hexrays_item.cgoto.label_num

    def make_citem_t(self) -> ida_hexrays.citem_t:
        #TODO: implement make_citem_t
        raise NotImplementedError


class Try(ControlFlow):
    HEXRAYS_TYPE = ida_hexrays.cit_try

    def __init__(self,
                 *,
                 condition: Expression = None,
                 true: Statement = None,
                 false: Statement = None,
                 elseif: Statement = None,
                 **kwargs):
        super().__init__(**kwargs)
        self._condition = HexraysItem._wrap(condition)
        self._true = HexraysItem._wrap(true)
        self._false = HexraysItem._wrap(false)

        if elseif is not None:
            from repyda.hexrays.statements import BlockStatement
            self._false = BlockStatement(statements=elseif)

    def iter_children(self) -> Generator[HexraysItem, None, None]:
        yield from super().iter_children()
        yield self.condition
        yield self.true

        if self.false is not None:
            yield self.false

    @property
    @bound_value
    def condition(self) -> Expression:
        return Expression.from_citem(self._hexrays_item.cif.expr, self._cfunc, self)

    @property
    @bound_value
    def true(self) -> Statement:
        return Statement.from_citem(self._hexrays_item.cif.ithen, self._cfunc, self)

    @property
    @bound_value
    def false(self) -> Optional[Statement]:
        if self._hexrays_item.cif.ielse is None:
            return None

        return Statement.from_citem(self._hexrays_item.cif.ielse, self._cfunc, self)

    def make_citem_t(self) -> ida_hexrays.citem_t:
        insn = ida_hexrays.cinsn_t()
        insn.op = ida_hexrays.cit_if

        cif = ida_hexrays.cif_t()
        cif.expr = self.condition.make_citem_t()

        if self.true is not None:
            cif.ithen = self.true.make_citem_t()

        if self.false is not None:
            cif.ielse = self.false.make_citem_t()

        insn.cif = cif
        return insn


class Throw(ControlFlow):
        HEXRAYS_TYPE = ida_hexrays.cit_throw
        
        def __init__(self, exception: Expression = None, **kwargs):
            super().__init__(**kwargs)
            self._exception = HexraysItem._wrap(exception)
        
        def iter_children(self) -> Generator[HexraysItem, None, None]:
            yield self.Expression

        @property
        @bound_value
        def exception(self) -> Expression:
            return Expression.from_citem(self._hexrays_item.creturn.expr, self._cfunc, self)
        
        def make_citem_t(self) -> ida_hexrays.citem_t:
            throw = ida_hexrays.cinsn_t()
            throw.op = ida_hexrays.cit_return
            if self.expression is not None:
                throw.expr = self.expression.make_citem_t()
            return throw

