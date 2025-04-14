from pathlib import Path

import repyda
import idautils
import ida_kernwin


class TestRepydaIdb(IdbTestSuite):
    IDB = Path(__file__).parent.parent / 'ntdll.dll.i64'

    def test_ptr_size(self):
        assert repyda.IDB.ptr_size() == 8

    def test_min_ea(self):
        assert repyda.IDB.min_ea() == 0x180001000

    def test_max_ea(self):
        assert repyda.IDB.max_ea() == 0x180174000

    def test_image_base(self):
        assert repyda.IDB.image_base() == 0x180000000

    def test_relea(self):
        assert repyda.IDB.relea(0x0180110018) == 0x110018

    def test_absea(self):
        assert repyda.IDB.absea(0x110018) == 0x180110018

    def test_current_addr(self):
        ida_kernwin.jumpto(0x1800d3242)
        assert repyda.IDB.current_addr() == 0x1800d3242

    def test_strings(self):
        strings = list(repyda.IDB.strings())
        assert len(strings) == len(list(idautils.Strings()))
        assert strings[0].name == 'aRtlunlockheap'
        assert strings[0].ea == 0x180113fc8

    def test_exports(self):
        exports = list(repyda.IDB.exports())
        assert len(exports) == 2350
        assert exports[1].name == 'A_SHAFinal'
        assert exports[1].ea == 0x18003d190
        assert exports[1].ordinal == 9

    def test_segments(self):
        segments = [
            {
                'name': '.text',
                'start': 0x180001000,
                'end': 0x18010f000,
                'permissions': 5,
            },
            {
                'name': 'RT',
                'start': 0x18010f000,
                'end': 0x180110000,
                'permissions': 5,
            },
            {
                'name': '.rdata',
                'start': 0x180110000,
                'end': 0x180156000,
                'permissions': 4,
            },
            {
                'name': '.data',
                'start': 0x180156000,
                'end': 0x180161000,
                'permissions': 6,
            },
            {
                'name': '.pdata',
                'start': 0x180161000,
                'end': 0x18016f000,
                'permissions': 4,
            },
            {
                'name': '.mrdata',
                'start': 0x18016f000,
                'end': 0x180173000,
                'permissions': 6,
            },
            {
                'name': '.00cfg',
                'start': 0x180173000,
                'end': 0x180174000,
                'permissions': 4,
            },
        ]

        count_found = 0
        for segment in repyda.IDB.segments():
            for expected in segments:
                if expected['name'] == segment.name and \
                    expected['start'] == segment.start_ea and \
                    expected['end'] == segment.end_ea and \
                    expected['permissions'] == segment.permissions:
                    count_found += 1
                    break

        assert count_found == len(segments)
        assert len(segments) == len(list(repyda.IDB.segments()))

    def test_add_segment(self):
        original_count_segments = len(list(repyda.IDB.segments()))
        repyda.IDB.add_segment(0x1000, 0x2000, 'foo', repyda.SegmentClass.CODE, 7)
        segments = list(repyda.IDB.segments())
        assert len(segments) == original_count_segments + 1
        assert any(True for seg in segments if \
                   seg.name == 'foo' and \
                   seg.start_ea == 0x1000 and \
                   seg.end_ea == 0x2000 and \
                   seg.permissions == 7)


@idb_test(idb=Path(__file__).parent.parent / 'notepad.exe.i64')
def test_imports():
    imports = list(repyda.IDB.imports())
    assert len(imports) == 301
    assert imports[0].module_name == 'KERNEL32'
    assert imports[0].name == 'GetProcAddress'
    assert imports[0].ea == 0x1400268b8
    assert imports[0].ordinal == 0