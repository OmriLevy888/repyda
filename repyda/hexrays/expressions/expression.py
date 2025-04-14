from __future__ import annotations

from typing import Generator, TYPE_CHECKING
from collections.abc import Iterable

from .. import HexraysItem, bound_value
from repyda.base.types import Type, StructMember

import ida_hexrays

if TYPE_CHECKING:
    from repyda.hexrays.functions import Variable


class Expression(HexraysItem):
    def __init__(self, type: Type = None, **kwargs):
        super().__init__(**kwargs)
        self._type = type

    @property
    @bound_value
    def type(self) -> Type:
        return Type.from_tinfo(self._hexrays_item.type)

    @type.setter
    def type(self, value: Type):
        if not self.is_bound():
            self._type = value
        else:
            expr = ida_hexrays.cexpr_t(self._hexrays_item)
            expr.type = value.get_tinfo()
            self._hexrays_item.swap(expr)
            from repyda.hexrays.functions.decompiled_function import DecompiledFunction
            function = DecompiledFunction(function=self._cfunc)
            if function.view is not None:
                function.view.refresh_ctext()

    def unwrap(self) -> Expression:
        from repyda.hexrays.expressions import Cast, AddressRef, PointerDeref

        if isinstance(self, (Cast, AddressRef, PointerDeref)):
            return self.operand.unwrap()
        else:
            return self

class EmptyExpression(Expression):
    HEXRAYS_TYPE = ida_hexrays.cot_empty


class Ternary(Expression):
    HEXRAYS_TYPE = ida_hexrays.cot_tern

    def __init__(self,
                 *,
                 condition: Expression = None,
                 true: Expression = None,
                 false: Expression = None,
                 **kwargs):
        super().__init__(**kwargs)
        self._condition = HexraysItem._wrap(condition)
        self._true = HexraysItem._wrap(true)
        self._false = HexraysItem._wrap(false)

    def iter_children(self) -> Generator[HexraysItem, None, None]:
        yield from super().iter_children()
        yield self.condition
        yield self.true
        yield self.false

    @property
    @bound_value
    def condition(self) -> Expression:
        return Expression.from_citem(self._hexrays_item.x, self._cfunc, self)

    @property
    @bound_value
    def true(self) -> Expression:
        return Expression.from_citem(self._hexrays_item.y, self._cfunc, self)

    @property
    @bound_value
    def false(self) -> Expression:
        return Expression.from_citem(self._hexrays_item.z, self._cfunc, self)

    def make_citem_t(self) -> ida_hexrays.citem_t:
        return ida_hexrays.cexpr_t(self.HEXRAYS_TYPE,
                                   self.condition.make_citem_t(),
                                   self.true.make_citem_t(),
                                   self.false.make_citem_t())


class Call(Expression):
    HEXRAYS_TYPE = ida_hexrays.cot_call

    def __init__(self, *, callee: Expression = None, arguments: Iterable[Expression] = None, **kwargs):
        super().__init__(**kwargs)
        self._callee = HexraysItem._wrap(callee)
        # TODO: work on argument matching
        self._arguments = arguments

    def iter_children(self) -> Generator[Expression, None, None]:
        yield from super().iter_children()
        yield self.callee
        yield from self.arguments

    @property
    @bound_value
    def arguments(self) -> Generator[Expression, None, None]:
        for argument in self._hexrays_item.a:
            yield Expression.from_citem(argument, self._cfunc, self)

    @property
    @bound_value
    def callee(self) -> Expression:
        return Expression.from_citem(self._hexrays_item.x, self._cfunc, self)

    def get_argument(self, name: str = None, *, index: int = None) -> Expression:
        if not self.is_bound():
            return None

        if name is not None:
            from repyda.base.types import Pointer
            func_type = self.callee.type
            if isinstance(func_type, Pointer):
                func_type = func_type.pointed

            try:
                index = func_type.get_argument(name=name).idx
            except AttributeError:
                raise ValueError(f'No such argument {name}') from None

        if index is None:
            raise ValueError('Must pass either name or index')

        for idx, argument in enumerate(self.arguments):
            if idx == index:
                return argument

    def make_citem_t(self) -> ida_hexrays.citem_t:
        expr = ida_hexrays.cexpr_t(self.HEXRAYS_TYPE, self.callee.make_citem_t())

        expr.a = ida_hexrays.carglist_t()
        for arg in self.arguments:
            carg_t = ida_hexrays.carg_t()
            arg_expr = arg.make_citem_t()
            carg_t.consume_cexpr(arg_expr)
            expr.a.push_back(carg_t)
            # consume_expr takes cepxt_t* (raw pointer), swaps it with the internal
            # expr of the carg_t object and calls delete on the pointer -> it consumes
            # the pointer and frees it. python will later try to call __swig_destroy__
            # of the local arg_expr object, calling delete_cexpr_t in the process,
            # which causes a memory issue. setting None to __swig_destroy__ will avoid
            # the second free. note that this has to happen after consume_cexpr so that
            # the delete in consume_expr actually deletes the old object and avoid
            # memory leakage.
            arg_expr.__swig_destroy__ = None

        return expr


class VariableExpression(Expression):
    HEXRAYS_TYPE = ida_hexrays.cot_var

    def __init__(self, name: str = None, *, index: int = None, is_argument: bool = None, **kwargs):
        super().__init__(**kwargs)
        self._index = index
        self._name = name
        self._is_argument = is_argument

    @property
    @bound_value
    def index(self) -> int:
        return self._hexrays_item.v.idx

    @property
    @bound_value
    def name(self) -> str:
        return self._cfunc.lvars[self.index].name

    @property
    @bound_value
    def is_argument(self) -> bool:
        return self._cfunc.lvars[self.index].is_arg_var

    def get_variable(self) -> Variable:
        from repyda.hexrays.functions import DecompiledFunction, Variable
        return Variable(self.index, DecompiledFunction(ea=self._cfunc.entry_ea))

    def make_citem_t(self) -> ida_hexrays.citem_t:
        expr = ida_hexrays.cexpr_t()
        expr.op = self.HEXRAYS_TYPE

        v = ida_hexrays.var_ref_t()
        v.idx = self.index

        expr.v = v
        return expr


class InstructionExpression(Expression):
    HEXRAYS_TYPE = ida_hexrays.cot_insn

    #TODO: when is this even a thing?

    def make_citem_t(self) -> ida_hexrays.citem_t:
        #TODO: implement make_citem_t
        raise NotImplementedError


class HelperExpression(Expression):
    HEXRAYS_TYPE = ida_hexrays.cot_helper

    def __init__(self, value: str = None, **kwargs):
        super().__init__(**kwargs)
        self._value = value

    @property
    @bound_value
    def value(self) -> str:
        return self._hexrays_item.helper

    def make_citem_t(self) -> ida_hexrays.citem_t:
        if self.type is None:
            from repyda.base.types import SignedInt32
            type = SignedInt32.get_tinfo()
        else:
            self.type.get_tinfo()
        return ida_hexrays.create_helper(True, type, self.value)


class TypeExpression(Expression):
    HEXRAYS_TYPE = ida_hexrays.cot_type

    def make_citem_t(self) -> ida_hexrays.citem_t:
        #TODO: implement make_citem_t
        raise NotImplementedError


class MemberAccess(Expression):
    HEXRAYS_TYPE = ida_hexrays.cot_memref

    def __init__(self,
                 *,
                 object: Expression = None,
                 offset: int = None,
                 name: str = None,
                 **kwargs):
        super().__init__(**kwargs)
        self._object = HexraysItem._wrap(object)
        self._offset = offset
        self._name = name

    def iter_children(self) -> Generator[HexraysItem, None, None]:
        yield from super().iter_children()
        yield self.object

    @property
    @bound_value
    def object(self) -> Expression:
        return Expression.from_citem(self._hexrays_item.x, self._cfunc, self)

    @property
    @bound_value
    def offset(self) -> int:
        return self._hexrays_item.m

    @property
    @bound_value
    def name(self) -> str:
        return self.object.type.get_member(offset=self.offset).name

    def get_struct_member(self) -> StructMember:
        if self.object is None or self.offset is None:
            raise RuntimeError("Can't find StructMember object for partially initialized MemberAccess")

        return self.object.type.get_member(offset=self.offset)

    def make_citem_t(self) -> ida_hexrays.citem_t:
        return ida_hexrays.cexpr_t(self.HEXRAYS_TYPE, self.object.make_citem_t(), self._hexrays_item.m)


class MemberArrow(Expression):
    HEXRAYS_TYPE = ida_hexrays.cot_memptr

    def __init__(self,
                 *,
                 object: Expression = None,
                 offset: int = None,
                 name: str = None,
                 **kwargs):
        super().__init__(**kwargs)
        self._object = HexraysItem._wrap(object)
        self._offset = offset
        self._name = name

    def iter_children(self) -> Generator[HexraysItem, None, None]:
        yield from super().iter_children()
        yield self.object

    @property
    @bound_value
    def object(self) -> Expression:
        return Expression.from_citem(self._hexrays_item.x, self._cfunc, self)

    @property
    @bound_value
    def offset(self) -> int:
        return self._hexrays_item.m

    @property
    @bound_value
    def name(self) -> str:
        return self.object.type.pointed.get_member(offset=self.offset).name

    def get_struct_member(self) -> StructMember:
        if self.object is None or self.offset is None:
            raise RuntimeError("Can't find StructMember object for partially initialized MemberArrow")

        return self.object.type.pointed.get_member(offset=self.offset)

    def make_citem_t(self) -> ida_hexrays.citem_t:
        return ida_hexrays.cexpr_t(self.HEXRAYS_TYPE, self.object.make_citem_t(), self._hexrays_item.m)


class Cast(Expression):
    HEXRAYS_TYPE = ida_hexrays.cot_cast

    def __init__(self, operand: Expression = None, **kwargs):
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
        expr = ida_hexrays.cexpr_t(ida_hexrays.cot_cast, self.operand.make_citem_t())
        expr.type = self.type.get_tinfo()
        return expr


class Index(Expression):
    HEXRAYS_TYPE = ida_hexrays.cot_idx

    def __init__(self, *, array: Expression = None, index: Expression = None, **kwargs):
        super().__init__(**kwargs)
        self._array = HexraysItem._wrap(array)
        self._index = HexraysItem._wrap(index)

    def iter_children(self) -> Generator[HexraysItem, None, None]:
        yield from super().iter_children()
        yield self.array
        yield self.index

    @property
    @bound_value
    def array(self) -> Expression:
        return Expression.from_citem(self._hexrays_item.x, self._cfunc, self)

    @property
    @bound_value
    def index(self) -> Expression:
        return Expression.from_citem(self._hexrays_item.y, self._cfunc, self)

    def make_citem_t(self) -> ida_hexrays.citem_t:
        return ida_hexrays.cexpr_t(self.HEXRAYS_TYPE, self.array.make_citem_t(), self.index.make_citem_t())