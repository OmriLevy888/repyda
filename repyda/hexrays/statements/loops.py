from typing import Generator

from repyda.hexrays import HexraysItem
from . import Statement, ControlFlow
from .. import Expression, HexraysItem, bound_value

import ida_hexrays


class Loop(ControlFlow):
    def __init__(self, *, condition: Expression = None, body: Statement = None, **kwargs):
        super().__init__(**kwargs)
        self._condition = HexraysItem._wrap(condition)
        self._body = HexraysItem._wrap(body)

    def iter_children(self) -> Generator[HexraysItem, None, None]:
        yield from super().iter_children()
        yield self.condition
        yield self.body

    @property
    @bound_value
    def condition(self) -> Expression:
        #TODO: need to return Any node
        raise NotImplementedError

    @property
    @bound_value
    def body(self) -> Statement:
        #TODO: need to return Any node
        raise NotImplementedError


class ForLoop(Loop):
    HEXRAYS_TYPE = ida_hexrays.cit_for

    def __init__(self,
                 *,
                 init: Expression = None,
                 step: Expression = None,
                 **kwargs):
        super().__init__(**kwargs)
        self._init = HexraysItem._wrap(init)
        self._step = HexraysItem._wrap(step)

    def iter_children(self) -> Generator[HexraysItem, None, None]:
        yield from super().iter_children()
        yield self.init
        yield self.condition
        yield self.step
        yield self.body

    @property
    @bound_value
    def init(self) -> Expression:
        return Expression.from_citem(self._hexrays_item.cfor.init, self._cfunc, self)

    @property
    @bound_value
    def condition(self) -> Expression:
        return Expression.from_citem(self._hexrays_item.cfor.expr, self._cfunc, self)

    @property
    @bound_value
    def step(self) -> Expression:
        return Expression.from_citem(self._hexrays_item.cfor.step, self._cfunc, self)

    @property
    @bound_value
    def body(self) -> Statement:
        return Statement.from_citem(self._hexrays_item.cfor.body, self._cfunc, self)

    def make_citem_t(self) -> ida_hexrays.citem_t:
        insn = ida_hexrays.cinsn_t()
        insn.op = self.HEXRAYS_TYPE

        cfor = ida_hexrays.cfor_t()
        cfor.init = self.init.make_citem_t()
        cfor.expr = self.condition.make_citem_t()
        cfor.step = self.step.make_citem_t()
        cfor.body = self.body.make_citem_t()

        insn.cfor = cfor
        return insn


class WhileLoop(Loop):
    HEXRAYS_TYPE = ida_hexrays.cit_while

    @property
    @bound_value
    def condition(self) -> Expression:
        return Expression.from_citem(self._hexrays_item.cwhile.expr, self._cfunc, self)

    @property
    @bound_value
    def body(self) -> Statement:
        return Statement.from_citem(self._hexrays_item.cwhile.body, self._cfunc, self)

    def make_citem_t(self) -> ida_hexrays.citem_t:
        insn = ida_hexrays.cinsn_t()
        insn.op = self.HEXRAYS_TYPE

        cwhile = ida_hexrays.cwhile_t()
        cwhile.expr = self.condition.make_citem_t()
        cwhile.body = self.body.make_citem_t()

        insn.cwhile = cwhile
        return insn


class DoWhileLoop(Loop):
    HEXRAYS_TYPE = ida_hexrays.cit_do

    @property
    @bound_value
    def condition(self) -> Expression:
        return Expression.from_citem(self._hexrays_item.cdo.expr, self._cfunc, self)

    @property
    @bound_value
    def body(self) -> Statement:
        return Statement.from_citem(self._hexrays_item.cdo.body, self._cfunc, self)

    def make_citem_t(self) -> ida_hexrays.citem_t:
        insn = ida_hexrays.cinsn_t()
        insn.op = self.HEXRAYS_TYPE

        cdo = ida_hexrays.cdo_t()
        cdo.expr = self.condition.make_citem_t()
        cdo.body = self.body.make_citem_t()

        insn.cdo = cdo
        return insn