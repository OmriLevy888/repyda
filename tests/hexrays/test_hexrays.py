from pathlib import Path

import repyda


class TestHexrays(IdbTestSuite):
    IDB = Path(__file__).parent.parent / 'ntdll.dll.i64'

    def test_parent(self):
        RtlQueryProcessLockInformation = repyda.DecompiledFunction(name='RtlQueryProcessLockInformation')
        ret = RtlQueryProcessLockInformation.match(repyda.Return(expression=repyda.Number()))
        assert ret is not None
        assert ret.parent.parent == repyda.If()
        assert isinstance(ret.parent.parent, repyda.If)