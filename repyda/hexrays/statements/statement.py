from typing import Generator, Iterable, Union

from .. import HexraysItem, Expression, bound_value
from ... import Instruction

import ida_hexrays


class Statement(HexraysItem):
    pass


class EmptyStatement(Statement):
    HEXRAYS_TYPE = ida_hexrays.cit_empty


class BlockStatement(Statement):
    HEXRAYS_TYPE = ida_hexrays.cit_block

    def __init__(self, statements: Union[Iterable[HexraysItem], HexraysItem] = None, **kwargs):
        super().__init__(**kwargs)

        if not isinstance(statements, Iterable) and statements is not None:
            statements = (statements,)

        self._statements = [HexraysItem._wrap(statement) for statement in statements or ()] or None

    def iter_children(self) -> Generator[HexraysItem, None, None]:
        yield from super().iter_children()
        yield from self.statements or ()

    @property
    @bound_value
    def statements(self) -> Generator[Statement, Statement, Statement]:
        for statement in self._hexrays_item.cblock:
            yield Statement.from_citem(statement, self._cfunc, self)

    def make_citem_t(self) -> ida_hexrays.citem_t:
        block = ida_hexrays.new_block()
        for statement in self.statements:
            block.cblock.push_back(statement.make_citem_t())
        return block


class ExpressionStatement(Statement):
    HEXRAYS_TYPE = ida_hexrays.cit_expr

    def __init__(self, expression: Expression = None, **kwrags):
        super().__init__(**kwrags)
        self._expression = HexraysItem._wrap(expression)

    def iter_children(self) -> Generator[HexraysItem, None, None]:
        yield from super().iter_children()
        yield self.expression

    @property
    @bound_value
    def expression(self) -> Expression:
        return Expression.from_citem(self._hexrays_item.cexpr, self._cfunc, self)

    def make_citem_t(self) -> ida_hexrays.citem_t:
        insn = ida_hexrays.cinsn_t()
        insn.op = ida_hexrays.cit_expr
        insn.cexpr = self.expression.make_citem_t()
        return insn


class AssemblyBlock(Statement):
    HEXRAYS_TYPE = ida_hexrays.cit_asm

    def __len__(self) -> int:
        return self._hexrays_item.casm.size()

    def iter_instructions(self) -> Generator[Instruction, Instruction, Instruction]:
        for ea in self._hexrays_item.casm:
            yield Instruction(ea)

    def make_citem_t(self) -> ida_hexrays.citem_t:
        #TODO: implement make_citem_t
        raise NotImplementedError