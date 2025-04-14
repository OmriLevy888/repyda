from typing import Generator
from . import Expression
from .. import HexraysItem, bound_value

import ida_hexrays


class BinaryOp(Expression):
    def __init__(self, *, left: Expression = None, right: Expression = None, **kwargs):
        super().__init__(**kwargs)
        self._left = HexraysItem._wrap(left)
        self._right = HexraysItem._wrap(right)

    def iter_children(self) -> Generator[HexraysItem, None, None]:
        yield from super().iter_children()
        yield self.left
        yield self.right

    @property
    @bound_value
    def left(self) -> Expression:
        return Expression.from_citem(self._hexrays_item.x, self._cfunc, self)

    @property
    @bound_value
    def right(self) -> Expression:
        return Expression.from_citem(self._hexrays_item.y, self._cfunc, self)

    def make_citem_t(self) -> ida_hexrays.citem_t:
        return ida_hexrays.cexpr_t(self.HEXRAYS_TYPE, self.left.make_citem_t(), self.right.make_citem_t())


class Comma(BinaryOp):
    HEXRAYS_TYPE = ida_hexrays.cot_comma


class LogicalOr(BinaryOp):
    HEXRAYS_TYPE = ida_hexrays.cot_lor


class LogicalAnd(BinaryOp):
    HEXRAYS_TYPE = ida_hexrays.cot_land


class BinaryOr(BinaryOp):
    HEXRAYS_TYPE = ida_hexrays.cot_bor


class Xor(BinaryOp):
    HEXRAYS_TYPE = ida_hexrays.cot_xor


class BinaryAnd(BinaryOp):
    HEXRAYS_TYPE = ida_hexrays.cot_band


class ShiftRight(BinaryOp):
    pass


class ShiftRightSigned(ShiftRight):
    HEXRAYS_TYPE = ida_hexrays.cot_sshr


class ShiftRightUnsigned(ShiftRight):
    HEXRAYS_TYPE = ida_hexrays.cot_ushr


class ShiftLeft(BinaryOp):
    HEXRAYS_TYPE = ida_hexrays.cot_shl


class Add(BinaryOp):
    HEXRAYS_TYPE = ida_hexrays.cot_add


class Sub(BinaryOp):
    HEXRAYS_TYPE = ida_hexrays.cot_sub


class Mul(BinaryOp):
    HEXRAYS_TYPE = ida_hexrays.cot_mul


class Div(BinaryOp):
    pass


class DivSigned(Div):
    HEXRAYS_TYPE = ida_hexrays.cot_sdiv


class DivUnsigned(Div):
    HEXRAYS_TYPE = ida_hexrays.cot_udiv


class Mod(BinaryOp):
    pass


class ModSigned(Mod):
    HEXRAYS_TYPE = ida_hexrays.cot_smod


class ModUnsigned(Mod):
    HEXRAYS_TYPE = ida_hexrays.cot_umod


class FloatAdd(BinaryOp):
    HEXRAYS_TYPE = ida_hexrays.cot_fadd


class FloatSub(BinaryOp):
    HEXRAYS_TYPE = ida_hexrays.cot_fsub


class FloatMul(BinaryOp):
    HEXRAYS_TYPE = ida_hexrays.cot_fmul


class FloatDiv(BinaryOp):
    HEXRAYS_TYPE = ida_hexrays.cot_fdiv