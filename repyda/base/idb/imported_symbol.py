from typing import Any


class ImportedSymbol:
    def __init__(self, module_name: str, name: str, ea: int, ordinal: int):
        self._module_name = module_name
        self._name = name
        self._ea = ea
        self._ordinal = ordinal

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, ImportedSymbol):
            raise NotImplementedError

        return self.module_name == other.module_name and self.ordinal == other.ordinal

    def __ne__(self, other: Any) -> bool:
        if not isinstance(other, ImportedSymbol):
            raise NotImplementedError

        return self.module_name != other.module_name or self.ordinal != other.ordinal

    @property
    def module_name(self) -> str:
        return self._module_name

    @property
    def name(self) -> str:
        return self._name

    @property
    def ea(self) -> int:
        return self._ea

    @property
    def ordinal(self) -> int:
        return self._ordinal