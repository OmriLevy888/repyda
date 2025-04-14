from __future__ import annotations
from typing import Generator, Optional, TypeVar, TYPE_CHECKING
from abc import abstractmethod

if TYPE_CHECKING:
    from .hexrays_item import HexraysItem
    from repyda.hexrays.functions import DecompiledFunction
    PatternT = TypeVar('PatternT', bound=HexraysItem)


class LimitWrapper:
    def __init__(self, item: HexraysItem):
        self.item = item
        self.found = item is None

    def validate(self, function: DecompiledFunction) -> LimitWrapper:
        if self.item is not None and \
            self.item.is_bound() and \
            self.item.function != function:
            raise ValueError('Limit not inside function')
        return self


class Matchable:
    @abstractmethod
    def iter_children(self) -> Generator[HexraysItem, None, None]:
        raise NotImplementedError

    @staticmethod
    def _comapre(item: HexraysItem, pattern: HexraysItem) -> bool:
        from repyda.hexrays.match_modifiers import Contains, Either

        if not isinstance(item, type(pattern)) and not isinstance(pattern, (Contains, Either)):
            return False

        return item == pattern

    def _get_function(self) -> DecompiledFunction:
        from repyda.hexrays.functions import DecompiledFunction
        if isinstance(self, DecompiledFunction):
            return self
        return self.function

    def _match_impl(self,
                    pattern: PatternT,
                    start: LimitWrapper,
                    end: LimitWrapper) -> Optional[PatternT]:
        if not start.found:
            if Matchable._comapre(self, start.item):
                start.found = True
        elif end.item is not None:
            if Matchable._comapre(self, end.item):
                end.found = True
                return None
        elif Matchable._comapre(self, pattern):
            return self

        for child in self.iter_children():
            matched = Matchable._match_impl(child, pattern, start=start, end=end)
            if matched is not None or (end.item is not None and end.found):
                return matched

    def _match_all_impl(self,
                        pattern: PatternT,
                        start: LimitWrapper,
                        end: LimitWrapper) -> Generator[PatternT, None, None]:
        if not start.found:
            if Matchable._comapre(self, start.item):
                start.found = True
        elif end.item is not None:
            if Matchable._comapre(self, end.item):
                end.found = True
        elif Matchable._comapre(self, pattern):
            yield self

        if end.item is None or not end.found:
            for child in self.iter_children():
                yield from Matchable._match_all_impl(child, pattern, start=start, end=end)

    def match(self,
              pattern: PatternT,
              *,
              start: PatternT = None,
              end: PatternT = None) -> Optional[PatternT]:
        from .hexrays_item import HexraysItem
        start = LimitWrapper(HexraysItem._wrap(start)).validate(self._get_function())
        end = LimitWrapper(HexraysItem._wrap(end)).validate(self._get_function())
        return self._match_impl(HexraysItem._wrap(pattern), start, end)

    def match_all(self,
                  pattern: PatternT,
                  *,
                  start: PatternT = None,
                  end: PatternT = None) -> Generator[PatternT, None, None]:
        from .hexrays_item import HexraysItem
        start = LimitWrapper(HexraysItem._wrap(start)).validate(self._get_function())
        end = LimitWrapper(HexraysItem._wrap(end)).validate(self._get_function())
        yield from self._match_all_impl(HexraysItem._wrap(pattern), start, end)