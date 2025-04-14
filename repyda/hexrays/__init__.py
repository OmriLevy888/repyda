from .event import HexraysEvent, HookExceptionInfo, HexraysHook, HookManager
from .hexrays_item import HexraysItem, bound_value
from .match_modifiers import Contains, Either
from .matchable import Matchable
from .expressions import *
from .statements import *
from .functions import *
from .view import UIFLags, View


class HexRaysState:
    is_laoded = False


try:
    import sys
    if 'sphinx' not in sys.modules:
        import ida_kernwin
        class __HexraysInitHook(ida_kernwin.UI_Hooks):
            def database_inited(self, *args, **kwargs):
                import ida_hexrays
                print('[Repyda]: Database initialized, initializing HexRays plugin...')
                try:
                    if ida_hexrays.init_hexrays_plugin():
                        print('[Repyda]: Loaded HexRays plugin')
                        HexRaysState.is_laoded = True
                        return

                    print('[Repyda]: Cannot initialize HexRays plugin')
                except Exception as ex:
                    print(f'[Repyda]: Exception when initializing HexRays plugin ({ex})')

                # TODO: delete symbols?

        del ida_kernwin
        __init_hooks = __HexraysInitHook()
        __init_hooks.hook()
finally:
    try:
        del sys
        del ida_kernwin
    except NameError:
        pass