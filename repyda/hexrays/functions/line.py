from __future__ import annotations

from typing import Optional, Union, TYPE_CHECKING

from repyda.base.elements import Addressable, Sequenceable

import ida_hexrays

if TYPE_CHECKING:
    from . import DecompiledFunction


class Line(Addressable, Sequenceable):
    def __init__(self, ea: int, decompiled_function: DecompiledFunction):
        self._ea = ea
        self._decompiled_function = decompiled_function

    @property
    def ea(self) -> int:
        return self._ea

    def __contains__(self, ea: Union[int, Addressable]) -> bool:
        raise NotImplementedError

    @property
    def next(self) -> Optional[Line]:
        raise NotImplementedError

    @property
    def prev(self) -> Optional[Line]:
        raise NotImplementedError

    @property
    def function(self) -> DecompiledFunction:
        return self._decompiled_function

    @property
    def number(self) -> int:
        raise NotImplementedError

    def __repr__(self) -> str:
        trimmed_line = str(self).replace('\n', ' ')[:16]
        if len(trimmed_line) > 13:
            trimmed_line = trimmed_line[:13] + '...'
        return f'Line({self.ea}, {repr(self.function)}, [{trimmed_line}])'

    def __str__(self) -> str:
        try:
            insnvec = self.function.ea_map[self.ea]
            lines = list()

            for statement in insnvec:
                printer = ida_hexrays.qstring_printer_t(
                    self.function._decompiled_function.__deref__(), False)
                statement.print(0, printer)
                lines.append(printer.s.split('\n')[0])

            return '\n'.join(lines)
        except ValueError:
            return '}'