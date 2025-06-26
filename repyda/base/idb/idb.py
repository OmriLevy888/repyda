from __future__ import annotations
from typing import Generator
import enum

import ida_kernwin
import idaapi
import idc
import idautils
import ida_segment
import ida_ida
import functools

from .segment import Segment, SegmentClass, SegmentPermissions
from .imported_symbol import ImportedSymbol
from .exported_symbol import ExportedSymbol


class Endianness(enum.Enum):
    BIG = enum.auto()
    LITTLE = enum.auto()


class IDB:
    @staticmethod
    def ptr_size() -> int:
        if ida_ida.inf_is_64bit():
            bits = 64
        elif ida_ida.inf_is_32bit():
            bits = 32
        else:
            bits = 16

        return bits // 8

    @staticmethod
    def get_endianness() -> Endianness:
        return Endianness.BIG if ida_ida.inf_is_be() else Endianness.LITTLE

    @staticmethod
    def min_ea() -> int:
        return idc.get_inf_attr(idc.INF_MIN_EA)

    @staticmethod
    def max_ea() -> int:
        return idc.get_inf_attr(idc.INF_MAX_EA)

    @staticmethod
    def image_base() -> int:
        return idaapi.get_imagebase()

    @staticmethod
    def current_addr() -> int:
        return ida_kernwin.get_screen_ea()

    @staticmethod
    def relea(addr: int) -> int:
        return addr - idaapi.get_imagebase()

    @staticmethod
    def absea(offset: int) -> int:
        return offset + idaapi.get_imagebase()

    @staticmethod
    def strings() -> Generator[int, int, int]:
        from repyda.base.data import Data
        for string in idautils.Strings():
            yield Data(string.ea)

    @staticmethod
    def imports() -> Generator[ImportedSymbol, None, None]:
        def callback(container, ea, name, ordinal):
            container.append((ea, name, ordinal))
            return True

        nimps = idaapi.get_import_module_qty()
        for module_idx in range(nimps):
            module_name = idaapi.get_import_module_name(module_idx)
            container = list()
            bound_callback = functools.partial(callback, container)
            idaapi.enum_import_names(module_idx, bound_callback)

            for ea, name, ordinal in container:
                yield ImportedSymbol(module_name, name, ea, ordinal)

    @staticmethod
    def exports() -> Generator[ExportedSymbol, None, None]:
        for export in idautils.Entries():
            _, ordinal, ea, name = export

            if name is None:
                name = ''

            yield ExportedSymbol(name, ea, ordinal)

    @staticmethod
    def segments() -> Generator[Segment, None, None]:
        return (Segment(ea) for ea in idautils.Segments())

    @staticmethod
    def get_segment(ea: int = None, name: str = None) -> Segment:
        if ea is None and name is None:
            raise ValueError(f"Must pass either name or ea")
        elif ea is not None and name is not None:
            raise ValueError(f"Can only pass either name or ea")
        elif ea is not None:
            return Segment(ea)
        else:
            return Segment(ida_segment.get_segm_by_name(name).start_ea)

    @staticmethod
    def add_segment(start_ea: int,
                    end_ea: int,
                    name: str,
                    segment_class: SegmentClass = SegmentClass.DATA,
                    permissions: SegmentPermissions = SegmentPermissions.READ):
        ida_segment.add_segm(0, start_ea, end_ea, name, segment_class.value)
        seg = IDB.get_segment(start_ea)
        seg.permissions = permissions

    @staticmethod
    def segment_from_data(start_ea: int,
                          name: str,
                          data: bytes,
                          segment_class: SegmentClass = SegmentClass.DATA,
                          permissions: SegmentPermissions = SegmentPermissions.READ):
        from repyda.base.data import Data
        IDB.add_segment(start_ea, start_ea + len(data), name, segment_class, permissions)
        Data.set_raw_bytes_at(start_ea, data)