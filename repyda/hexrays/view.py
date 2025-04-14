from __future__ import annotations
from typing import Generator, Union, Dict, Optional, TYPE_CHECKING

import enum
import sys
import threading

import ida_hexrays
import ida_kernwin
import idaapi

from repyda.base.elements import IDBIterable
from repyda.hexrays.event import HexraysEvent, HookManager

if TYPE_CHECKING:
    from repyda.base.functions import Function
    from repyda.hexrays.functions import DecompiledFunction


class UIFLags(enum.Flag):
    REUSE               = 0  # ida_hexrays.OPF_REUSE
    NEW_WINDOW          = 1  # ida_hexrays.OPF_NEW_WINDOW
    REUSE_ACTIVE        = 2  # ida_hexrays.OPF_REUSE_ACTIVE
    WINDOW_MGMT_TASK    = 7  # ida_hexrays.OPF_WINDOW_MGMT_TASK
    NO_WAIT             = 8  # ida_hexrays.OPF_NO_WAIT


_lock: threading.Lock = threading.Lock()
_all_views: Dict[int, View] = dict()
_HOOK_ID: str = 'repyda.hexrays.view:register_hexrays_view_collection_hook.collect_view_hook'


class View(IDBIterable):
    @classmethod
    def get(cls,
            *,
            vu: Optional[ida_hexrays.vdui_t] = None,
            ea: Optional[int] = None,
            flags: UIFLags = UIFLags.REUSE | UIFLags.NO_WAIT) -> View:
        if vu is None:
            if ea is None:
                ea = ida_kernwin.get_screen_ea()

            if isinstance(flags, UIFLags):
                flags = flags.value

            vu = ida_hexrays.open_pseudocode(ea, flags)
            if vu is None:
                raise ValueError(f'Failed to open Hexrays view ({ea=}, {UIFLags(flags)=})')

        with _lock:
            for index, view in _all_views.items():
                if index == vu.view_idx:
                    return view

            _all_views[vu.view_idx] = vu
            view = View(vu)
            _all_views[vu.view_idx] = view
            return view

    def __init__(self, vu: ida_hexrays.vdui_t):
        if vu.view_idx not in _all_views:
            raise RuntimeError('Do not call this function directly, use View.get(...) instead')

        self._vu = vu

    @staticmethod
    def iter() -> Generator[View, None, None]:
        with _lock:
            invalid = list()
            for index, view in _all_views.items():
                if not view._vu.valid():
                    invalid.append(index)

            for index in invalid:
                del _all_views[index]

            views = list(_all_views.values())

        yield from views

    @property
    def index(self) -> int:
        return self._vu.view_idx

    def __eq__(self, other: View) -> bool:
        return self.index == other.index

    @property
    def visible(self) -> bool:
        return self._vu.visible()

    @visible.setter
    def visibile(self, value: bool):
        self._vu.set_visible(value)

    @property
    def function(self) -> DecompiledFunction:
        from repyda.hexrays.functions import DecompiledFunction
        return DecompiledFunction(function=self._vu.cfunc)

    @function.setter
    def function(self, value: Union[int, str, Function, DecompiledFunction, ida_hexrays.cfunc_t, idaapi.func_t]):
        from repyda.hexrays.functions import DecompiledFunction

        if isinstance(value, int):
            function = DecompiledFunction(ea=value)
        elif isinstance(value, str):
            function = DecompiledFunction(name=value)
        else:
            function = DecompiledFunction(function=value)

        self._vu.switch_to(function._decompiled_function)

    def refresh_view(self, force_redecompile: bool = True):
        self._vu.refresh_view(force_redecompile)

    def refresh_ctext(self):
        self._vu.refresh_ctext()


def register_hexrays_views_collection_hook():
    #TODO: make this a plugin
    def collect_view_hook(event: HexraysEvent, view: View):
        if event == HexraysEvent.CLOSE_HEXRAYS_VIEW:
            if view._vu.view_idx in _all_views:
                del _all_views[view._vu.view_idx]

    HookManager.register(collect_view_hook,
                         HexraysEvent.OPEN_HEXRAYS_VIEW |
                         HexraysEvent.CLOSE_HEXRAYS_VIEW |
                         HexraysEvent.REFRESH_HEXRAYS_VIEW |
                         HexraysEvent.SWITCH_PSEUDOCODE,
                         identifier=_HOOK_ID)


if 'sphinx' not in sys.modules:
    register_hexrays_views_collection_hook()

del register_hexrays_views_collection_hook