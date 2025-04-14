from .hexrays_item import HexraysItem


class Contains(HexraysItem):
    def __init__(self, pattern: HexraysItem):
        self._pattern = HexraysItem._wrap(pattern)

    def __eq__(self, other: HexraysItem) -> bool:
        if other == self._pattern:
            return True

        if other is None:
            return False

        for child in other.iter_children():
            if child == self:
                return True

        return False

    def as_dict(self) -> dict:
        return {
            'node': self.__class__.__name__,
            'is_bound': self.is_bound(),
            'pattern': self._pattern.as_dict(),
        }


class Either(HexraysItem):
    def __init__(self, *options):
        self._options = list(map(HexraysItem._wrap, options))

    def __eq__(self, other: HexraysItem) -> bool:
        for option in self._options:
            if other == option:
                return True

        return False

    def as_dict(self) -> dict:
        return {
            'node': self.__class__.__name__,
            'is_bound': self.is_bound(),
            'options': list(option.as_dict() for option in self._options),
        }