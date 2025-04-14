import pytest

from pathlib import Path

import repyda


class TestRepydaXref(IdbTestSuite):
    IDB = Path(__file__).parent.parent / 'ntdll.dll.i64'

    def test_xref(self):
        RtlQueryProcessLockInformation = repyda.Function(name='RtlQueryProcessLockInformation')
        references = list(RtlQueryProcessLockInformation.references)

        assert len(references) == 4

    def test_referencing(self):
        RtlQueryProcessLockInformation = repyda.Function(name='RtlQueryProcessLockInformation')
        referencing = list(RtlQueryProcessLockInformation.referencing)

        assert len(referencing) == 15

    def test_all_references(self):
        RtlQueryProcessLockInformation = repyda.Function(name='RtlQueryProcessLockInformation')
        references = list(RtlQueryProcessLockInformation.references)
        all_references = list(RtlQueryProcessLockInformation.all_references)

        assert len(references) == 4
        assert len(all_references) == 13

        for xref in references:
            for all_xref in all_references:
                if xref == all_xref:
                    break
            else:
                pytest.fail(f'{xref=} does not exist in {all_references=}')

    def test_data_xref(self):
        pass

    def test_type_xref(self):
        pass