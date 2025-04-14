from . import BinaryOp

import ida_hexrays


class Comparison(BinaryOp):
    pass


class Equal(Comparison):
    HEXRAYS_TYPE = ida_hexrays.cot_eq


class NotEqual(Comparison):
    HEXRAYS_TYPE = ida_hexrays.cot_ne


class GreaterEqual(Comparison):
    HEXRAYS_TYPE = ida_hexrays.cot_sge


class AboveEqual(Comparison):
    HEXRAYS_TYPE = ida_hexrays.cot_uge


class LesserEqual(Comparison):
    HEXRAYS_TYPE = ida_hexrays.cot_sle


class BelowEqual(Comparison):
    HEXRAYS_TYPE = ida_hexrays.cot_ule


class Greater(Comparison):
    HEXRAYS_TYPE = ida_hexrays.cot_sgt


class Above(Comparison):
    HEXRAYS_TYPE = ida_hexrays.cot_ugt


class Lesser(Comparison):
    HEXRAYS_TYPE = ida_hexrays.cot_slt


class Below(Comparison):
    HEXRAYS_TYPE = ida_hexrays.cot_ult