from typing import Any


class ExportedSymbol:
    def __init__(self, name: str, ea: int, ordinal: int):
        self._name = name
        self._ea = ea
        self._ordinal = ordinal

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, ExportedSymbol):
            raise NotImplementedError

        return self.name == other.name and \
            self.ea == other.ea and self.ordinal == other.ordinal

    def __ne__(self, other: Any) -> bool:
        if not isinstance(other, ExportedSymbol):
            raise NotImplementedError

        return self.name != other.name or \
            self.ea != other.ea or self.ordinal != other.ordinal

    @property
    def name(self) -> str:
        return self._name

    @property
    def ea(self) -> int:
        return self._ea

    @property
    def ordinal(self) -> int:
        return self._ordinal
