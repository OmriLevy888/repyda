from typing import Tuple, List, Dict, Callable, Optional

import ida_hexrays
import ida_kernwin


import enum
import functools
import operator


class HexraysEvent(enum.Flag):
    FLOWCHART               = 0x00000001    # ida_hexrays.hxe_flowchart
    stkpnts                 = 0x00000002    # ida_hexrays.hxe_stkpnts
    prolog                  = 0x00000004    # ida_hexrays.hxe_prolog
    microcode               = 0x00000008    # ida_hexrays.hxe_microcode
    preoptimized            = 0x00000010    # ida_hexrays.hxe_preoptimized
    locopt                  = 0x00000020    # ida_hexrays.hxe_locopt
    prealloc                = 0x00000040    # ida_hexrays.hxe_prealloc
    glbopt                  = 0x00000080    # ida_hexrays.hxe_glbopt
    structural              = 0x00000100    # ida_hexrays.hxe_structural
    maturity                = 0x00000200    # ida_hexrays.hxe_maturity
    interr                  = 0x00000400    # ida_hexrays.hxe_interr
    combine                 = 0x00000800    # ida_hexrays.hxe_combine
    print_func              = 0x00001000    # ida_hexrays.hxe_print_func
    func_printed            = 0x00002000    # ida_hexrays.hxe_func_printed
    resolve_stkaddrs        = 0x00004000    # ida_hexrays.hxe_resolve_stkaddrs
    OPEN_HEXRAYS_VIEW       = 0x00008000    # ida_hexrays.hxe_open_pseudocode
    SWITCH_PSEUDOCODE       = 0x00010000    # ida_hexrays.hxe_switch_pseudocode
    REFRESH_HEXRAYS_VIEW    = 0x00020000    # ida_hexrays.hxe_refresh_pseudocode
    CLOSE_HEXRAYS_VIEW      = 0x00040000    # ida_hexrays.hxe_close_pseudocode
    KEYBOARD                = 0x00080000    # ida_hexrays.hxe_keyboard
    RIGHT_CLICK             = 0x00100000    # ida_hexrays.hxe_right_click
    DOUBLE_CLICK            = 0x00200000    # ida_hexrays.hxe_double_click
    CURSOR_POSITION_MOVE    = 0x00400000    # ida_hexrays.hxe_curpos
    CREATE_HINT             = 0x00800000    # ida_hexrays.hxe_create_hint
    text_ready              = 0x01000000    # ida_hexrays.hxe_text_ready
    populating_popup        = 0x02000000    # ida_hexrays.hxe_populating_popup
    VAR_NAME_CHANGED        = 0x04000000    # ida_hexrays.lxe_lvar_name_changed
    VAR_TYPE_CHANGED        = 0x08000000    # ida_hexrays.lxe_lvar_type_changed
    VAR_COMMENT_CHANGED     = 0x10000000    # ida_hexrays.lxe_lvar_cmt_changed
    VAR_MAPPING_CHANGED     = 0x20000000    # ida_hexrays.lxe_lvar_mapping_changed
    COMMENT_CHANGE          = 0x40000000    # ida_hexrays.hxe_cmt_changed


class HookExceptionInfo:
    def __init__(self,
                 exception: Exception,
                 event: HexraysEvent,
                 args: List,
                 kwargs: Dict):
        self.exception = exception
        self.event = event
        self.args = args
        self.kwargs = kwargs


class HexraysHook(ida_hexrays.Hexrays_Hooks):
    def __init__(self,
                 hook: Callable[[HexraysEvent, Tuple, Dict], None],
                 mask: Optional[HexraysEvent] = None,
                 except_handler: Callable[[HookExceptionInfo], None] = None,
                 *args,
                 **kwargs):
        super().__init__(*args, **kwargs)

        if mask is None:
            mask = functools.reduce(operator.ior, HexraysEvent)

        self._hook = hook
        self._mask = mask
        self._except_handler = except_handler

    def _invoke_hook(self, event, *args, **kwargs):
        try:
            if self._mask & event:
                self._hook(event, *args, **kwargs)
        except Exception as ex:
            if self._except_handler is not None:
                self._except_handler(HookExceptionInfo(
                    exception=ex,
                    event=event,
                    args=args,
                    kwargs=kwargs,
                ))
            else:
                import traceback
                print(traceback.format_exc())
        finally:
            return 0

    def open_pseudocode(self, vu: ida_hexrays.vdui_t) -> int:
        from repyda.hexrays.view import View
        return self._invoke_hook(HexraysEvent.OPEN_HEXRAYS_VIEW, View.get(vu=vu))

    def switch_pseudocode(self, vu: ida_hexrays.vdui_t) -> int:
        from repyda.hexrays.view import View
        return self._invoke_hook(HexraysEvent.SWITCH_PSEUDOCODE, View.get(vu=vu))

    def refresh_pseudocode(self, vu: ida_hexrays.vdui_t) -> int:
        from repyda.hexrays.view import View
        return self._invoke_hook(HexraysEvent.REFRESH_HEXRAYS_VIEW, View.get(vu=vu))

    def close_pseudocode(self, vu: ida_hexrays.vdui_t) -> int:
        from repyda.hexrays.view import View
        return self._invoke_hook(HexraysEvent.CLOSE_HEXRAYS_VIEW, View.get(vu=vu))

'''
    def keyboard(self, vu: ida_hexrays.vdui_t, key_code, shift_state) -> int:
        pass

    KEYBOARD                = ida_hexrays.hxe_keyboard
    RIGHT_CLICK             = ida_hexrays.hxe_right_click
    DOUBLE_CLICK            = ida_hexrays.hxe_double_click
    CURSOR_POSITION_MOVE    = ida_hexrays.hxe_curpos
    CREATE_HINT             = ida_hexrays.hxe_create_hint
    text_ready              = ida_hexrays.hxe_text_ready
    populating_popup        = ida_hexrays.hxe_populating_popup
    VAR_NAME_CHANGED        = ida_hexrays.lxe_lvar_name_changed
    VAR_TYPE_CHANGED        = ida_hexrays.lxe_lvar_type_changed
    VAR_COMMENT_CHANGED     = ida_hexrays.lxe_lvar_cmt_changed
    VAR_MAPPING_CHANGED     = ida_hexrays.lxe_lvar_mapping_changed
    COMMENT_CHANGE          = ida_hexrays.hxe_cmt_changed
'''


class HookPauseContext:
    def __init__(self,
                 identifier: str,
                 hook: Callable[[HexraysEvent, Tuple, Dict], None],
                 mask: Optional[HexraysEvent],
                 except_handler: Callable[[HookExceptionInfo], None]):
        self._identifier = identifier
        self._hook = hook
        self._mask = mask
        self._except_handler = except_handler

    def __enter__(self):
        pass

    def __exit__(self, *args, **kwargs):
        HookManager.register(identifier=self._identifier,
                             hook=self._hook,
                             mask=self._mask,
                             except_handler=self._except_handler)


class HookManager:
    _hooks: Dict[str, HexraysHook] = dict()
    _initialize_hook: ida_kernwin.UI_Hooks = None
    _is_initialized: bool = False
    _deferred_hooks = list()

    @classmethod
    def _build_id(cls, hook: Callable[[HexraysEvent, Tuple, Dict], None]) -> str:
        return f'{hook.__module__}:{hook.__qualname__}'

    @classmethod
    def register(cls,
                 hook: Callable[[HexraysEvent, Tuple, Dict], None],
                 mask: HexraysEvent = None,
                 *,
                 except_handler: Callable[[HookExceptionInfo], None] = None,
                 identifier: Optional[str] = None) -> str:
        if identifier is None:
            identifier = cls._build_id(hook)

        if identifier in cls._hooks:
            cls._hooks[identifier].unhook()

        if cls._is_initialized:
            from repyda.hexrays import HexRaysState
            if not HexRaysState.is_laoded:
                cls._hooks[identifier] = HexraysHook(hook, mask, except_handler)
                cls._hooks[identifier].hook()
            else:
                print('[Repyda]: Rejecting HexRays hook, plugin was not loaded correctly')
        elif cls._initialize_hook is None:
            class __InitializeHookManger(ida_kernwin.UI_Hooks):
                def ready_to_run(self, *arg, **kwargs):
                    cls._is_initialized = True
                    cls._run_deferred()

            cls._initialize_hook = __InitializeHookManger()
            cls._initialize_hook.hook()

            cls._deferred_hooks.append((hook, mask, except_handler, identifier))
        else:
            cls._deferred_hooks.append((hook, mask, except_handler, identifier))

        return identifier

    @classmethod
    def _run_deferred(cls):
        from repyda.hexrays import HexRaysState
        if not HexRaysState.is_laoded:
            print('[Repyda]: HexRays plugin was not loaded correctly, skipping hooks')
            return

        for hook, mask, except_handler, identifier in cls._deferred_hooks:
            cls._hooks[identifier] = HexraysHook(hook, mask, except_handler)
            cls._hooks[identifier].hook()

    @classmethod
    def _get_identifier(cls,
                        hook: Optional[Callable[[HexraysEvent, Tuple, Dict], None]] = None,
                        identifier: Optional[str] = None) -> str:
        if hook is None and identifier is None:
            raise ValueError('Must pass either hook or identifier')

        if hook is not None:
            identifier = cls._build_id(hook)

        if identifier not in cls._hooks:
            raise ValueError(f'No hook matches {identifier=}')

        return identifier

    @classmethod
    def unregister(cls,
                   *,
                   hook: Optional[Callable[[HexraysEvent, Tuple, Dict], None]] = None,
                   identifier: Optional[str] = None):
        identifier = cls._get_identifier(hook, identifier)

        cls._hooks[identifier].unhook()
        del cls._hooks[identifier]

    @classmethod
    def pause(cls,
              *,
              hook: Optional[Callable[[HexraysEvent, Tuple, Dict], None]] = None,
              identifier: Optional[str] = None) -> HookPauseContext:
        identifier = cls._get_identifier(hook, identifier)

        hook = cls._hooks[identifier]
        context = HookPauseContext(identifier, hook._hook, hook._mask, hook._except_handler)

        cls.unregister(identifier=identifier)

        return context