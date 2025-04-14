import idc
import ida_ida


def demangle_name(name: str) -> str:
    return idc.demangle_name(name, ida_ida.inf_get_short_demnames())