from __future__ import annotations
from typing import Any, Generator, Union, Optional, Callable, TypeVar, TYPE_CHECKING
from collections.abc import Iterable
from .matchable import Matchable
from construct import Container

import ida_hexrays
import ida_lines

import json

if TYPE_CHECKING:
    from repyda.hexrays.functions.decompiled_function import DecompiledFunction
    from .match_modifiers import Contains, Either


class FoundEnd(StopIteration):
    pass


class HexraysItemJSONEncoder(json.JSONEncoder):
    def default(self, object: Any) -> Any:
        from repyda.hexrays.statements.control_flow import Default
        from repyda.base.elements.addressable import Addressable

        if isinstance(object, Default.__class__):
            return {
                'node': object.__class__.__name__,
            }
        elif isinstance(object, Addressable):
            return str(object)

        return super().default(object)


class HexraysItem(Matchable):
    HEXRAYS_TYPE: int = -1

    def __init__(self, *, contains: HexraysItem = None):
        self._contains = HexraysItem._wrap(contains)
        self._hexrays_item = None
        self._cfunc = None
        self._parent = None

    @classmethod
    def from_citem(cls,
                   citem: ida_hexrays.citem_t,
                   cfunc: ida_hexrays.cfunc_t,
                   parent: Union[DecompiledFunction, HexraysItem]):
        done = set()
        todo = set(cls.__subclasses__())

        while len(todo) != 0:
            curr_cls = todo.pop()
            if curr_cls in done:
                continue

            if curr_cls.HEXRAYS_TYPE == citem.op:
                obj = curr_cls()
                obj._hexrays_item = citem
                obj._cfunc = cfunc
                obj._parent = parent
                return obj
            else:
                done.add(curr_cls)
                todo |= set(curr_cls.__subclasses__())

        raise RuntimeError(f'Failed to find class for {citem.op=}, this should never happen!')

    @property
    def ea(self) -> int:
        if not self.is_bound():
            raise RuntimeError('Tried to get ea of unbound HexraysItem')

        return self._hexrays_item.ea

    @property
    def parent(self) -> Union[None, DecompiledFunction, HexraysItem]:
        return self._parent

    def is_bound(self) -> bool:
        try:
            return self._hexrays_item is not None
        except AttributeError:
            return False

    @property
    def function(self) -> DecompiledFunction:
        if not self.is_bound():
            raise RuntimeError('Can only get function of bound HexRaysItem')

        from repyda.hexrays.functions import DecompiledFunction
        return DecompiledFunction(function=self._cfunc)

    def iter_children(self) -> Generator[HexraysItem, None, None]:
        yield from ()

    def next_in_parent(self) -> Union[HexraysItem, None]:
        return_next = False
        for sibling in self.parent.iter_children():
            if sibling == self:
                return_next = True
            elif return_next:
                return sibling

    def prev_in_parent(self) -> Union[HexraysItem, None]:
        prev = None
        for sibling in self.parent.iter_children():
            if sibling == self:
                return prev

    def _get_properties(self, only_set: bool = False) -> Generator[str, str, str]:
        for member in dir(self):
            if member.startswith('_') or member in ('ea', 'parent', 'function'):
                continue

            if not isinstance(getattr(self.__class__, member), property):
                continue

            if only_set and getattr(self, member, None) is None:
                continue

            yield member

    def as_dict(self) -> dict:
        from repyda.base.types import Type

        description = {
            'node': self.__class__.__name__,
            'is_bound': self.is_bound(),
        }

        if getattr(self, '_contains', None) is not None:
            description['_contains'] = self._contains.as_dict()

        for prop in self._get_properties(only_set=True):
            value = getattr(self, prop)

            def jsonize(item):
                if isinstance(item, HexraysItem):
                    return item.as_dict()
                elif isinstance(item, Type):
                    return str(item)
                elif isinstance(item, str):
                    return item
                elif isinstance(item, Iterable):
                    return list(jsonize(cell) for cell in item)
                else:
                    return value

            description[prop] = jsonize(value)

        return description

    def clone_unbound(self) -> HexraysItem:
        from .match_modifiers import Either, Contains
        if isinstance(self, Either):
            return Either(*(option.clone_unbound() for option in self._options))
        elif isinstance(self, Contains):
            return Contains(self._pattern.clone_unbound())

        kwargs = dict()

        for prop in self._get_properties(only_set=True):
            value = getattr(self, prop)

            if isinstance(value, HexraysItem):
                kwargs[prop] = value.clone_unbound()
            elif isinstance(value, Iterable) and not isinstance(value, str):
                kwargs[prop] = [cell.clone_unbound() for cell in value]
            else:
                kwargs[prop] = value

        return self.__class__(**kwargs)

    def __str__(self) -> str:
        if not self.is_bound():
            return repr(self)
        return ida_lines.tag_remove(self._hexrays_item.print1(self._cfunc))

    def __repr__(self) -> str:
        return json.dumps(self.as_dict(), indent=4, cls=HexraysItemJSONEncoder)

    def __repr__(self) -> str:
        return json.dumps(self.as_dict(), cls=HexraysItemJSONEncoder)

    def __truediv__(self, other: HexraysItem) -> HexraysItem:
        if not isinstance(other, HexraysItem):
            return NotImplemented

        cloned = self.clone_unbound()
        if getattr(cloned, '_contains', None) is None:
            cloned._contains = other
        else:
            cloned._contains |= other

        return cloned

    def __or__(self, other: HexraysItem) -> Either:
        if not isinstance(other, HexraysItem):
            other = HexraysItem._wrap(other)

        from .match_modifiers import Either
        return Either(self, other)

    def __pos__(self) -> Contains:
        from .match_modifiers import Contains
        return Contains(self)

    @staticmethod
    def _wrap(item: Union[None, HexraysItem, int, float, str, bytes, Container, type]) -> Optional[HexraysItem]:
        if item is None:
            return item
        elif isinstance(item, HexraysItem):
            return item.clone_unbound()
        elif isinstance(item, int):
            from repyda.hexrays.expressions import Number, ObjectAddress
            from repyda.hexrays.match_modifiers import Either
            return Either(Number(value=item), ObjectAddress(ea=item))
        elif isinstance(item, float):
            from repyda.hexrays.expressions import FloatLiteral
            return FloatLiteral(value=item)
        elif isinstance(item, str):
            from repyda.hexrays.expressions import ObjectAddress, VariableExpression
            from repyda.hexrays.match_modifiers import Either
            return Either(ObjectAddress(name=item), ObjectAddress(object=item), VariableExpression(name=item))
        elif isinstance(item, (bytes, Container)):
            from repyda.hexrays.expressions import ObjectAddress
            return ObjectAddress(value=item)
        elif isinstance(item, type):
            return item()

        raise RuntimeError('Item does not match any type, this should never happen')

    @staticmethod
    def _compare_list(this: Iterable[HexraysItem],
                      other: Union[Callable, Iterable[HexraysItem], Iterable[Iterable[HexraysItem]]]) -> bool:
        if isinstance(other, Callable):
            return other(list(this))

        from repyda.hexrays.match_modifiers import Contains
        if isinstance(other, Contains):
            for value in this:
                if other == value:
                    return True

            return False

        this = list(this)
        other = list(other)

        if len(this) == len(other) and len(this) == 0:
            return True
        elif len(this) == 0 or len(other) == 0:
            return False

        if len(this) != len(other):
            return False

        for value, match in zip(this, other):
            if isinstance(value, HexraysItem) and not isinstance(match, HexraysItem):
                match = HexraysItem._wrap(match)

            if value != match:
                return False

        return True

    @staticmethod
    def _compare_prop(this: Union[HexraysItem, Iterable[HexraysItem]],
                      other: Union[HexraysItem, Iterable[HexraysItem], Iterable[Iterable[HexraysItem]]]) -> bool:
        if isinstance(this, Iterable) and not isinstance(this, str):
            return HexraysItem._compare_list(this, other)

        if isinstance(other, Iterable) and not isinstance(other, str):
            for value in other:
                if isinstance(value, Callable):
                    if value(this):
                        return True
                    else:
                        continue
                elif this == value:
                    return True
            else:
                return False
        elif isinstance(other, Callable):
            return other(this)
        else:
            return this == other

    def __eq__(self, pattern: HexraysItem) -> bool:
        if not isinstance(pattern, HexraysItem):
            return NotImplemented

        if self.is_bound() and pattern.is_bound():
            return self._hexrays_item == pattern._hexrays_item

        if not self.is_bound():
            return NotImplemented

        from repyda.hexrays.match_modifiers import Contains, Either
        if isinstance(pattern, (Contains, Either)):
            return pattern == self

        if not isinstance(self, type(pattern)):
            return False

        if getattr(pattern, '_contains', None) is not None:
            contains = pattern._contains
            if not isinstance(contains, Contains):
                contains = Contains(contains)

            return contains == self

        for prop in pattern._get_properties(only_set=True):
            if not hasattr(self, prop):
                return False

            this = getattr(self, prop)
            other = getattr(pattern, prop)

            if not HexraysItem._compare_prop(this, other):
                return False

        return True

    def make_citem_t(self) -> ida_hexrays.citem_t:
        raise NotImplementedError('Only implemented on base classes')

    def _swap_bound(self, other: HexraysItem) -> Union[DecompiledFunction, HexraysItem]:
        original_parent = self.parent

        self._parent, other._parent = other._parent, self._parent
        self._cfunc, other._cfunc = other._cfunc, self._cfunc

        self._hexrays_item.swap(other.make_citem_t())
        self._hexrays_item, other._hexrays_item = other._hexrays_item, self._hexrays_item

        return original_parent

    def swap(self, other: HexraysItem, *, do_refresh: bool = True) -> Union[DecompiledFunction, HexraysItem]:
        from repyda.hexrays.expressions import Expression
        from repyda.hexrays.statements import Statement

        if do_refresh:
            # Fetch view before update in case it was not yet registered
            from repyda.hexrays.functions.decompiled_function import DecompiledFunction
            DecompiledFunction(function=self._cfunc).view

        if isinstance(self, Expression) and not isinstance(other, Expression):
            raise RuntimeError(f'Can only swap statement with another statement {self.__class__.__name__} -> {other.__class__.__name__}')
        elif isinstance(self, Statement) and isinstance(other, Expression):
            from repyda.hexrays.statements import ExpressionStatement
            other = ExpressionStatement(expression=other)

        if not self.is_bound():
            raise RuntimeError('Can only swap bound HexraysItem instances')

        if other.is_bound():
            return self._swap_bound(other)

        cfunc = self._cfunc
        parent = self._parent
        hexrays_item = self._hexrays_item
        unbound_clone = self.clone_unbound()

        for prop in unbound_clone._get_properties(only_set=True):
            value = getattr(self, prop)

            prop = f'_{prop}'
            if isinstance(value, HexraysItem):
                setattr(self, prop, value.clone_unbound())
            elif isinstance(value, Iterable) and not isinstance(value, str):
                setattr(self, prop, [cell.clone_unbound() for cell in value])
            else:
                setattr(self, prop, value)

        self._hexrays_item = None
        self._cfunc = None
        self._parent = None

        hexrays_item.swap(other.make_citem_t())

        if do_refresh:
            from repyda.hexrays.functions.decompiled_function import DecompiledFunction
            DecompiledFunction(function=cfunc).view.refresh_ctext()

        return parent


SelfT = TypeVar('SelfT', bound=HexraysItem)
PropertyT = TypeVar('PropertyT')
PropertyCallableT = Callable[[SelfT], PropertyT]


def bound_value(callable: PropertyCallableT) -> PropertyCallableT:
    def _wrapper(self: SelfT) -> PropertyT:
        if not self.is_bound():
            return getattr(self, f'_{callable.__name__}', None)

        return callable(self)

    _wrapper.__annotations__ = callable.__annotations__
    return _wrapper