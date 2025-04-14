from typing import Generator
from . import Expression
from .. import HexraysItem, bound_value

import ida_hexrays


class UnaryOp(Expression):
    def __init__(self, operand: Exception = None, **kwargs):
        super().__init__(**kwargs)
        self._operand = HexraysItem._wrap(operand)

    def iter_children(self) -> Generator[HexraysItem, None, None]:
        yield from super().iter_children()
        yield self.operand

    @property
    @bound_value
    def operand(self) -> Expression:
        return Expression.from_citem(self._hexrays_item.x, self._cfunc, self)

    def make_citem_t(self) -> ida_hexrays.citem_t:
        return ida_hexrays.cexpr_t(self.HEXRAYS_TYPE, self.operand.make_citem_t())


class PreOp(UnaryOp):
    pass


class FloatingNegation(PreOp):
    HEXRAYS_TYPE = ida_hexrays.cot_fneg


class Negation(PreOp):
    HEXRAYS_TYPE = ida_hexrays.cot_neg


class LogicalNot(PreOp):
    HEXRAYS_TYPE = ida_hexrays.cot_lnot


class BinaryNot(PreOp):
    HEXRAYS_TYPE = ida_hexrays.cot_bnot


class PointerDeref(PreOp):
    HEXRAYS_TYPE = ida_hexrays.cot_ptr


class AddressRef(PreOp):
    HEXRAYS_TYPE = ida_hexrays.cot_ref


class PreInc(PreOp):
    HEXRAYS_TYPE = ida_hexrays.cot_preinc


class PreDec(PreOp):
    HEXRAYS_TYPE = ida_hexrays.cot_predec


class Sizeof(PreOp):
    HEXRAYS_TYPE = ida_hexrays.cot_sizeof

    def __init__(self, expression: Expression = None, *, size: int = None, **kwargs):
        super().__init__(operand=expression, **kwargs)
        self._size = size

    @property
    @bound_value
    def size(self) -> int:
        pass


class PostOp(UnaryOp):
    pass


class PostInc(PostOp):
    HEXRAYS_TYPE = ida_hexrays.cot_postinc


class PostDec(PostOp):
    HEXRAYS_TYPE = ida_hexrays.cot_postdec