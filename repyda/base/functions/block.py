from __future__ import annotations
from typing import Generator, Optional, TYPE_CHECKING

import idc
import idautils
import ida_bytes
import ida_kernwin

from repyda.base.elements import Addressable, Commentable, Nameable, Referenceable, \
    Referencing, MultipleSequenceable, Xref, XrefType

if TYPE_CHECKING:
    from repyda.base.functions.function import Function
    from repyda.base.functions.instruction import Instruction


class Block(Addressable, Commentable, Nameable, Referenceable, Referencing, MultipleSequenceable):
    @staticmethod
    def exists_at(ea: int) -> bool:
        return idc.is_code(ida_bytes.get_full_flags(ea))

    def __init__(self, ea: Optional[int] = None):
        if ea is None:
            ea = ida_kernwin.get_screen_ea()

        from repyda.base.functions.function import Function
        try:
            function = Function(ea)
        except ValueError:
            raise ValueError(f'Could not find function containing basic block at ea {hex(ea)}') from None

        for basic_block in function._flowchart():
            if ea >= basic_block.start_ea and ea < basic_block.end_ea:
                self._basic_block = basic_block
                break
        else:
            raise RuntimeError(f'Address {hex(ea)} corresponds to function at {hex(function.ea)} but no basic block matched')

    def __str__(self) -> str:
        return '\n'.join(str(inst) for inst in self.iter_instructions())

    @property
    def ea(self) -> int:
        return self._basic_block.start_ea

    @property
    def flags(self) -> int:
        raise NotImplementedError

    @property
    def size(self) -> int:
        return self._basic_block.end_ea - self._basic_block.start_ea

    @property
    def comment(self) -> Optional[str]:
        # TODO: is this the same as setting a comment on the first instruction?
        raise NotImplementedError

    @comment.setter
    def comment(self, value: Optional[str]):
        raise NotImplementedError

    @comment.deleter
    def comment(self):
        raise NotImplementedError

    @property
    def repeatable_comment(self) -> Optional[str]:
        raise NotImplementedError

    @repeatable_comment.setter
    def repeaterable_comment(self, value: Optional[str]):
        raise NotImplementedError

    @repeatable_comment.deleter
    def repeatable_comment(self):
        raise NotImplementedError

    @property
    def name(self) -> str:
        raise NotImplementedError

    @name.setter
    def name(self, value: Optional[str]):
        raise NotImplementedError

    @name.deleter
    def name(self):
        raise NotImplementedError

    @property
    def is_auto_name(self) -> bool:
        raise NotImplementedError

    @property
    def is_user_defined_name(self) -> bool:
        raise NotImplementedError

    @property
    def references(self) -> Generator[Xref, None, None]:
        for xref in idautils.XrefsTo(self.ea):
            xref = Xref(xref)
            if xref.type == XrefType.ORDINARY_FLOW:
                continue

            yield xref

    @property
    def all_references(self) -> Generator[Xref, None, None]:
        for instruction in self.iter_instructions():
            for xref in instruction.all_references:
                yield xref

    @property
    def referencing(self) -> Generator[Xref, None, None]:
        for instruction in self.iter_instructions():
            for xref in instruction.referencing:
                yield xref

    @property
    def next(self) -> Generator[Block, None, None]:
        for block in self._basic_block.succs():
            yield Block(block.start_ea)

    @property
    def prev(self) -> Generator[Block, None, None]:
        for block in self._basic_block.preds():
            yield Block(block.start_ea)

    @property
    def function(self) -> Function:
        from repyda.base.functions.function import Function
        try:
            return Function(self.ea)
        except ValueError:
            raise ValueError(f'Could not find function containing basic block at ea {hex(self.ea)}') from None

    def iter_instructions(self) -> Generator[Instruction]:
        from repyda.base.functions.instruction import Instruction

        for head in idautils.Heads(self.ea, self.ea + self.size):
            if idc.is_code(ida_bytes.get_full_flags(head)):
                yield Instruction(head)

    @property
    def count_instructions(self) -> int:
        return sum(1 for head in idautils.Heads(self.ea, self.ea + self.size)
                   if idc.is_code(ida_bytes.get_full_flags(head)))