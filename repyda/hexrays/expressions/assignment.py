from . import BinaryOp

import ida_hexrays


class AssignmentOp(BinaryOp):
    pass


class Assignment(AssignmentOp):
    HEXRAYS_TYPE = ida_hexrays.cot_asg


class AssignmentOr(AssignmentOp):
    HEXRAYS_TYPE = ida_hexrays.cot_asgbor


class AssignmentXor(AssignmentOp):
    HEXRAYS_TYPE = ida_hexrays.cot_asgxor


class AssignmentAnd(AssignmentOp):
    HEXRAYS_TYPE = ida_hexrays.cot_asgband


class AssignmentAdd(AssignmentOp):
    HEXRAYS_TYPE = ida_hexrays.cot_asgadd


class AssignmentSub(AssignmentOp):
    HEXRAYS_TYPE = ida_hexrays.cot_asgsub


class AssignmentMul(AssignmentOp):
    HEXRAYS_TYPE = ida_hexrays.cot_asgmul


class AssignmentShiftRight(AssignmentOp):
    pass


class AssignmentShiftRightSigned(AssignmentShiftRight):
    HEXRAYS_TYPE = ida_hexrays.cot_asgsshr


class AssignmentShiftRightUnsigned(AssignmentShiftRight):
    HEXRAYS_TYPE = ida_hexrays.cot_asgushr


class AssignmentShiftLeft(AssignmentOp):
    HEXRAYS_TYPE = ida_hexrays.cot_asgshl


class AssignmentDiv(AssignmentOp):
    pass


class AssignmentDivSigned(AssignmentDiv):
    HEXRAYS_TYPE = ida_hexrays.cot_asgsdiv


class AssignmentDivUnsigned(AssignmentDiv):
    HEXRAYS_TYPE = ida_hexrays.cot_asgudiv


class AssignmentMod(AssignmentOp):
    pass


class AssignmentModSigned(AssignmentMod):
    HEXRAYS_TYPE = ida_hexrays.cot_asgsmod


class AssignmentModUnsigned(AssignmentMod):
    HEXRAYS_TYPE = ida_hexrays.cot_asgumod