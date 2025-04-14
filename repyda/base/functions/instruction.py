from __future__ import annotations
from typing import Generator, Optional, TYPE_CHECKING

import idaapi
import idc
import ida_ua
import ida_kernwin
import ida_bytes
import idautils

from repyda.base.elements import Addressable, Commentable, Referenceable, \
    Referencing, Sequenceable, Xref, XrefType


if TYPE_CHECKING:
    from repyda.base.functions import Function, Operand


class Instruction(Addressable, Commentable, Referenceable, Referencing, Sequenceable):
    @staticmethod
    def exists_at(ea: int) -> bool:
        return idc.is_code(ida_bytes.get_full_flags(ea))

    def __init__(self, ea: Optional[int] = None):
        if ea is None:
            ea = ida_kernwin.get_screen_ea()

        instruction = ida_ua.insn_t()
        ida_ua.decode_insn(instruction, ea)
        self._instruction = instruction

    def __repr__(self) -> str:
        return f'Instruction({self.ea=}, {self.__str__()})'

    def __str__(self) -> str:
        return idc.GetDisasm(self.ea)

    @property
    def ea(self) -> int:
        return self._instruction.ea

    @property
    def flags(self) -> int:
        return ida_bytes.get_full_flags(self.ea)

    @property
    def size(self) -> int:
        return idc.get_item_end(self.ea) - self.ea

    @property
    def comment(self) -> Optional[str]:
        return ida_bytes.get_cmt(self.ea, False) or None

    @comment.setter
    def comment(self, value: Optional[str]):
        if value is None:
            value = ''

        ida_bytes.set_cmt(self.ea, value, False)

    @comment.deleter
    def comment(self):
        self.comment = None

    @property
    def repeatable_comment(self) -> Optional[str]:
        return ida_bytes.get_cmt(self.ea, True) or None

    @repeatable_comment.setter
    def repeatable_comment(self, value: Optional[str]):
        if self.value is None:
            value = ''

        ida_bytes.set_cmt(self.ea, value, True)

    @repeatable_comment.deleter
    def repeatable_comment(self):
        self.repeatable_comment = None

    @property
    def next(self) -> Optional[Instruction]:
        next_instruction = Instruction(idc.next_head(self.ea))
        if self.function != next_instruction.function:
            return None

        return next_instruction

    @property
    def prev(self) -> Optional[Instruction]:
        prev_instruction = Instruction(idc.prev_head(self.ea))
        if self.function != prev_instruction.function:
            return None

        return prev_instruction

    def _xrefs(self, xref_func, ea: int) -> Generator[Xref]:
        for xref in xref_func(ea):
            xref = Xref(xref)
            if xref.type == XrefType.ORDINARY_FLOW:
                continue

            yield xref

    @property
    def references(self) -> Generator[Xref, Xref, Xref]:
        for xref in self._xrefs(idautils.XrefsTo, self.ea):
            yield xref

    @property
    def all_references(self) -> Generator[Xref, Xref, Xref]:
        for ea in range(self.ea, self.ea + self.size):
            for xref in self._xrefs(idautils.XrefsTo, ea):
                yield xref

    @property
    def referencing(self) -> Generator[Xref, Xref, Xref]:
        for xref in self._xrefs(idautils.XrefsFrom, self.ea):
            yield xref

    @property
    def function(self) -> Optional[Function]:
        try:
            from repyda.base.functions import Function
            return Function(self.ea)
        except ValueError:
            return None

    @property
    def mnemonic(self) -> str:
        return self._instruction.get_canon_mnem()

    @property
    def count_operands(self) -> int:
        from repyda.base.functions.operand import OperandType

        count = 0
        MAX_OPERANDS = 8
        while count < MAX_OPERANDS and self._instruction.ops[count].type != OperandType.NO_OPERAND.value:
            count += 1

        return count

    def get_operand(self, idx: int) -> Operand:
        from repyda.base.functions.operand import Operand
        return Operand(self, idx)

    def iter_operands(self) -> Generator[Operand, Operand, Operand]:
        for idx in range(self.count_operands):
            yield self.get_operand(idx)

    def is_call(self) -> bool:
        return idaapi.is_call_insn(self.ea)

    def is_return(self) -> bool:
        return idaapi.is_ret_insn(self.ea)

    def is_indirect_jump(self) -> bool:
        return idaapi.is_indirect_jump_insn(self.ea)